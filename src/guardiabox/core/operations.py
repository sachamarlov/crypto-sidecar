"""High-level encrypt / decrypt orchestration.

This module is the seam between the cryptographic primitives in
:mod:`guardiabox.core.crypto` and the UI adapters (CLI, TUI, sidecar). The
functions here are still pure in the sense that they accept paths and bytes
and produce files — no networking, no database, no logging of secrets.

Streaming format
----------------

For a plaintext of length ``N`` split in ``CHUNK_BYTES``-sized chunks:

* ``N == 0`` → one *final* empty chunk (16 bytes: the AES-GCM tag alone).
* ``N > 0`` → ``ceil(N / CHUNK_BYTES)`` chunks, the last of which is *final*.

Each chunk's AEAD associated data is ``header_bytes || (index, is_final)``,
binding it both to its position and to the exact header on disk. A reader that
never sees an ``is_final=1`` chunk raises :class:`CorruptedContainerError`,
which protects against chunk truncation.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import hashlib
from pathlib import Path
import secrets
import time
from typing import IO
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AES_KEY_BYTES,
    CONTAINER_VERSION,
    DECRYPTED_SUFFIX,
    DEFAULT_CHUNK_BYTES,
    ENCRYPTED_SUFFIX,
    MAX_IN_MEMORY_MESSAGE_BYTES,
    SALT_BYTES,
)
from guardiabox.core.container import (
    ContainerHeader,
    header_bytes,
    read_header,
    write_header,
)
from guardiabox.core.crypto import AesGcmCipher, chunk_aad, derive_chunk_nonce
from guardiabox.core.exceptions import (
    DecryptionError,
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    IntegrityError,
    MessageTooLargeError,
    ShareExpiredError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.core.rsa import RsaSign, RsaWrap
from guardiabox.core.share_token import (
    EMBEDDED_AAD,
    PERMISSION_READ,
    ParsedShareToken,
    ShareTokenHeader,
    build_payload_for_signing,
    read_token,
    write_token,
)
from guardiabox.fileio.atomic import atomic_writer
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.fileio.streaming import iter_chunks
from guardiabox.logging import get_logger
from guardiabox.security.password import assert_strong

__all__ = [
    "DEFAULT_KDF",
    "ContainerInspection",
    "accept_share",
    "decrypt_file",
    "decrypt_message",
    "encrypt_file",
    "encrypt_message",
    "inspect_container",
    "share_file",
]

DEFAULT_KDF: type[Pbkdf2Kdf] = Pbkdf2Kdf

# Structured logger. The project-wide ``_redact_secrets`` processor
# (cf. ``guardiabox/logging.py``) scrubs any known-sensitive key, but our
# side of the contract is to never *pass* a secret into a log event in the
# first place. Every event below carries only sizes, parameter ids, and
# outcome markers — never plaintext, passwords, keys, nonces, or paths
# beyond the filename stem.
_log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ContainerInspection:
    """Header-only view of a ``.crypt`` file, returned by :func:`inspect_container`.

    No plaintext is read or decrypted. All fields are derived from the
    header bytes and the file size, so inspection is safe to run on an
    untrusted file without knowing the password.
    """

    path: Path
    version: int
    kdf_id: int
    kdf_name: str
    kdf_params_summary: str
    salt_hex: str
    base_nonce_hex: str
    header_size: int
    ciphertext_size: int


def inspect_container(source: Path) -> ContainerInspection:
    """Read and decode a ``.crypt`` header without decrypting its content.

    Raises:
        InvalidContainerError: Magic bytes do not match.
        UnsupportedVersionError: Version byte is unknown.
        UnknownKdfError: KDF identifier is not implemented.
        CorruptedContainerError: Fixed-size fields are truncated.
        WeakKdfParametersError: KDF parameters violate the floor.
    """
    source_resolved = source.resolve(strict=True)
    with source_resolved.open("rb") as fh:
        header = read_header(fh)
        header_size = fh.tell()
        file_size = source_resolved.stat().st_size
    kdf_impl = kdf_for_id(header.kdf_id, header.kdf_params)
    if isinstance(kdf_impl, Pbkdf2Kdf):
        kdf_name = "PBKDF2-HMAC-SHA256"
        kdf_params_summary = f"iterations={kdf_impl.iterations}"
    else:
        kdf_name = "Argon2id"
        kdf_params_summary = (
            f"memory_kib={kdf_impl.memory_cost_kib}, "
            f"time_cost={kdf_impl.time_cost}, "
            f"parallelism={kdf_impl.parallelism}"
        )
    return ContainerInspection(
        path=source_resolved,
        version=header.version,
        kdf_id=header.kdf_id,
        kdf_name=kdf_name,
        kdf_params_summary=kdf_params_summary,
        salt_hex=header.salt.hex(),
        base_nonce_hex=header.base_nonce.hex(),
        header_size=header_size,
        ciphertext_size=file_size - header_size,
    )


def encrypt_file(
    source: Path,
    password: str,
    *,
    root: Path,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
    dest: Path | None = None,
    force: bool = False,
) -> Path:
    """Encrypt ``source`` to ``dest`` (or ``source.crypt`` alongside).

    Args:
        source: File to encrypt. Resolved strictly — must exist.
        password: User-supplied secret. Validated via
            :func:`guardiabox.security.password.assert_strong`. NFC-
            normalised before UTF-8 encoding so precomposed and
            decomposed codepoint sequences derive the same key.
        root: Directory tree inside which both ``source`` and ``dest``
            must resolve. The CLI passes ``Path.cwd()``; other callers
            (sidecar, TUI) must pass their configured vault root. **This
            parameter is mandatory and has no default** — per the
            spec-002 post-mortem, a self-referential default silently
            defeats :func:`resolve_within` in non-CLI callers.
        kdf: PBKDF2 (default) or Argon2id. Floors AND ceilings enforced
            in :mod:`guardiabox.core.kdf`.
        dest: Output path. Defaults to ``source + ".crypt"``. Must
            resolve inside ``root`` or :class:`PathTraversalError` is
            raised. If the resolved destination equals ``source``,
            :class:`DestinationCollidesWithSourceError` is raised
            before any write.
        force: Overwrite ``dest`` if it already exists. When ``False``
            (default), an existing destination raises
            :class:`DestinationAlreadyExistsError` before any work.

    The streaming chunk size is fixed at :data:`DEFAULT_CHUNK_BYTES`
    (64 KiB). The ``.crypt`` container does not encode the size, so
    writer and reader must agree via the module-wide constant; exposing
    it as a call-site argument used to let a caller accidentally
    produce files a different caller could not decrypt.

    Returns:
        The resolved ``.crypt`` path written.

    Note on zero-fill: the mutable ``bytearray`` holding the derived
    key is zeroed in a ``finally`` block. Python's immutable ``bytes``
    copies (the one returned by ``kdf.derive`` and the one passed to
    ``AESGCM``) cannot be zero-filled from Python — see
    ``docs/THREAT_MODEL.md`` §4.5 for the honest scope of this
    mitigation.

    Raises:
        WeakPasswordError, PathTraversalError, SymlinkEscapeError,
        FileNotFoundError, DestinationCollidesWithSourceError, OSError.
    """
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else DEFAULT_KDF()

    source_resolved = resolve_within(source, root).resolve(strict=True)
    default_dest = source_resolved.parent / (source_resolved.name + ENCRYPTED_SUFFIX)
    target = dest if dest is not None else default_dest
    safe_target = resolve_within(target, root)
    if safe_target == source_resolved:
        raise DestinationCollidesWithSourceError(
            f"encrypt refuses to overwrite its own source: {source_resolved}"
        )
    _check_dest_not_existing(safe_target, force=force)

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
        salt=secrets.token_bytes(SALT_BYTES),
        base_nonce=secrets.token_bytes(AES_GCM_NONCE_BYTES),
    )
    aad_prefix = header_bytes(header)

    key_buf = bytearray(AES_KEY_BYTES)
    try:
        derived = kdf_impl.derive(_password_bytes(password), header.salt, AES_KEY_BYTES)
        key_buf[:] = derived
        cipher = AesGcmCipher(bytes(key_buf))
        with atomic_writer(safe_target) as out:
            write_header(out, header)
            _encrypt_stream(
                chunks=iter_chunks(source_resolved, DEFAULT_CHUNK_BYTES),
                cipher=cipher,
                base_nonce=header.base_nonce,
                aad_prefix=aad_prefix,
                out=out,
            )
    finally:
        _zero_fill(key_buf)

    _log.debug(
        "vault.file.encrypted",
        kdf_id=kdf_impl.kdf_id,
        plaintext_size=source_resolved.stat().st_size,
        container_size=safe_target.stat().st_size,
    )
    return safe_target


def encrypt_message(
    message: bytes,
    password: str,
    *,
    root: Path,
    dest: Path,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
    force: bool = False,
) -> Path:
    """Encrypt ``message`` (raw bytes) to a ``.crypt`` file at ``dest``.

    Same ``root`` contract as :func:`encrypt_file`: ``dest`` must resolve
    strictly inside ``root``. The self-referential default of the first
    implementation (``dest.parent``) was flagged by the external audit
    as structurally no-op and has been removed. Chunk size is the
    module-wide :data:`DEFAULT_CHUNK_BYTES` — see :func:`encrypt_file`.

    Raises:
        MessageTooLargeError: If ``len(message) > MAX_IN_MEMORY_MESSAGE_BYTES``.
            Callers with larger payloads must use :func:`encrypt_file`.
    """
    if len(message) > MAX_IN_MEMORY_MESSAGE_BYTES:
        raise MessageTooLargeError(
            f"message of {len(message)} bytes exceeds in-memory limit "
            f"{MAX_IN_MEMORY_MESSAGE_BYTES}; use encrypt_file for larger payloads"
        )
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else DEFAULT_KDF()

    safe_target = resolve_within(dest, root)
    _check_dest_not_existing(safe_target, force=force)

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
        salt=secrets.token_bytes(SALT_BYTES),
        base_nonce=secrets.token_bytes(AES_GCM_NONCE_BYTES),
    )
    aad_prefix = header_bytes(header)

    key_buf = bytearray(AES_KEY_BYTES)
    try:
        derived = kdf_impl.derive(password.encode("utf-8"), header.salt, AES_KEY_BYTES)
        key_buf[:] = derived
        cipher = AesGcmCipher(bytes(key_buf))
        with atomic_writer(safe_target) as out:
            write_header(out, header)
            _encrypt_stream(
                chunks=_split_message(message, DEFAULT_CHUNK_BYTES),
                cipher=cipher,
                base_nonce=header.base_nonce,
                aad_prefix=aad_prefix,
                out=out,
            )
    finally:
        _zero_fill(key_buf)

    _log.debug(
        "vault.message.encrypted",
        kdf_id=kdf_impl.kdf_id,
        plaintext_size=len(message),
        container_size=safe_target.stat().st_size,
    )
    return safe_target


def decrypt_file(
    source: Path,
    password: str,
    *,
    root: Path,
    dest: Path | None = None,
    force: bool = False,
) -> Path:
    """Decrypt ``source`` (a ``.crypt`` file) to ``dest``.

    Default destination rules:
    * If ``source`` ends with ``.crypt`` (the normal case), the suffix is
      replaced with ``.decrypt``: ``report.pdf.crypt`` → ``report.pdf.decrypt``.
    * If ``source`` does **not** end with ``.crypt`` (e.g. a renamed or
      user-supplied non-standard name), ``.decrypt`` is appended:
      ``renamed_container`` → ``renamed_container.decrypt``. This never
      overwrites a file that lacks the ``.crypt`` suffix, which is
      important because the function refuses to operate on ``source`` if
      ``dest`` would otherwise collide with it.

    Pass ``dest`` explicitly to override these defaults.
    """
    source_resolved = resolve_within(source, root).resolve(strict=True)
    default_dest = _default_decrypt_dest(source_resolved)
    target = dest if dest is not None else default_dest
    safe_target = resolve_within(target, root)
    if safe_target == source_resolved:
        raise DestinationCollidesWithSourceError(
            f"decrypt refuses to overwrite its own source: {source_resolved}"
        )
    _check_dest_not_existing(safe_target, force=force)

    key_buf = bytearray(AES_KEY_BYTES)
    with source_resolved.open("rb") as raw_in:
        header = read_header(raw_in)
        aad_prefix = header_bytes(header)
        kdf_impl = kdf_for_id(header.kdf_id, header.kdf_params)
        try:
            derived = kdf_impl.derive(_password_bytes(password), header.salt, AES_KEY_BYTES)
            key_buf[:] = derived
            cipher = AesGcmCipher(bytes(key_buf))
            with atomic_writer(safe_target) as out:
                # Post-KDF failures (wrong password, tampered ciphertext,
                # truncated stream) all surface as :class:`DecryptionError`
                # via :func:`_decrypt_stream_plaintext`. No structlog
                # warning is emitted here because the stderr channel is
                # observable by an attacker — event presence itself would
                # become a timing oracle. Persistent audit logging lands
                # with spec 000-multi-user and writes to a separate sink.
                _decrypt_stream(
                    raw_in=raw_in,
                    cipher=cipher,
                    base_nonce=header.base_nonce,
                    aad_prefix=aad_prefix,
                    chunk_bytes=DEFAULT_CHUNK_BYTES,
                    out=out,
                )
        finally:
            _zero_fill(key_buf)

    _log.debug(
        "vault.file.decrypted",
        kdf_id=kdf_impl.kdf_id,
        container_size=source_resolved.stat().st_size,
        plaintext_size=safe_target.stat().st_size,
    )
    return safe_target


def decrypt_message(
    source: Path,
    password: str,
) -> bytes:
    """Decrypt ``source`` and return the plaintext bytes in memory.

    Used by the CLI's ``decrypt --message`` path which prints the plaintext to
    stdout rather than writing to disk.

    Raises:
        MessageTooLargeError: If the ``.crypt`` file is larger than
            :data:`MAX_IN_MEMORY_MESSAGE_BYTES`; callers must go through
            :func:`decrypt_file` in that case to stream to disk.
    """
    source_resolved = source.resolve(strict=True)
    # The plaintext is bounded by the ciphertext size (minus header +
    # per-chunk tags). If the file on disk is already above the
    # in-memory limit, refuse before reading any secret material.
    ct_size = source_resolved.stat().st_size
    if ct_size > MAX_IN_MEMORY_MESSAGE_BYTES:
        raise MessageTooLargeError(
            f"ciphertext of {ct_size} bytes exceeds in-memory limit "
            f"{MAX_IN_MEMORY_MESSAGE_BYTES}; use decrypt_file for larger payloads"
        )
    buffer = bytearray()
    key_buf = bytearray(AES_KEY_BYTES)
    with source_resolved.open("rb") as raw_in:
        header = read_header(raw_in)
        aad_prefix = header_bytes(header)
        kdf_impl = kdf_for_id(header.kdf_id, header.kdf_params)
        try:
            derived = kdf_impl.derive(_password_bytes(password), header.salt, AES_KEY_BYTES)
            key_buf[:] = derived
            cipher = AesGcmCipher(bytes(key_buf))
            # No structlog warning on failure: see the matching comment in
            # ``decrypt_file`` — event presence on stderr is a timing
            # oracle we do not want to expose.
            for pt in _decrypt_stream_plaintext(
                raw_in=raw_in,
                cipher=cipher,
                base_nonce=header.base_nonce,
                aad_prefix=aad_prefix,
                chunk_bytes=DEFAULT_CHUNK_BYTES,
            ):
                buffer.extend(pt)
        finally:
            _zero_fill(key_buf)
    _log.debug(
        "vault.message.decrypted",
        kdf_id=kdf_impl.kdf_id,
        container_size=source_resolved.stat().st_size,
        plaintext_size=len(buffer),
    )
    return bytes(buffer)


# ---------------------------------------------------------------------------
# Internal streaming helpers
# ---------------------------------------------------------------------------


def _encrypt_stream(
    *,
    chunks: Iterator[bytes],
    cipher: AesGcmCipher,
    base_nonce: bytes,
    aad_prefix: bytes,
    out: IO[bytes],
) -> None:
    """Encrypt a lookahead-driven iterator of plaintext chunks.

    A lookahead buffer of one chunk lets us flag the last one as ``is_final``
    without having to know the total size in advance. Empty plaintexts emit a
    single empty final chunk so the decoder always sees an authenticated
    terminator.
    """
    index = 0
    iterator = iter(chunks)
    try:
        current = next(iterator)
    except StopIteration:
        current = b""

    for next_chunk in iterator:
        _emit_chunk(
            out=out,
            cipher=cipher,
            base_nonce=base_nonce,
            aad_prefix=aad_prefix,
            index=index,
            plaintext=current,
            is_final=False,
        )
        current = next_chunk
        index += 1

    _emit_chunk(
        out=out,
        cipher=cipher,
        base_nonce=base_nonce,
        aad_prefix=aad_prefix,
        index=index,
        plaintext=current,
        is_final=True,
    )


def _emit_chunk(
    *,
    out: IO[bytes],
    cipher: AesGcmCipher,
    base_nonce: bytes,
    aad_prefix: bytes,
    index: int,
    plaintext: bytes,
    is_final: bool,
) -> None:
    nonce = derive_chunk_nonce(base_nonce, index)
    aad = chunk_aad(aad_prefix, index, is_final=is_final)
    out.write(cipher.encrypt(nonce, plaintext, aad))


def _decrypt_stream(
    *,
    raw_in: IO[bytes],
    cipher: AesGcmCipher,
    base_nonce: bytes,
    aad_prefix: bytes,
    chunk_bytes: int,
    out: IO[bytes],
) -> None:
    out.writelines(
        _decrypt_stream_plaintext(
            raw_in=raw_in,
            cipher=cipher,
            base_nonce=base_nonce,
            aad_prefix=aad_prefix,
            chunk_bytes=chunk_bytes,
        )
    )


def _decrypt_stream_plaintext(
    *,
    raw_in: IO[bytes],
    cipher: AesGcmCipher,
    base_nonce: bytes,
    aad_prefix: bytes,
    chunk_bytes: int,
) -> Iterator[bytes]:
    full_ct_size = chunk_bytes + AES_GCM_TAG_BYTES
    # 32-bit chunk counter — derive_chunk_nonce guards writers. The
    # reader must also refuse files that claim more than 2**32 chunks
    # (crafted or malformed ``.crypt`` past the format's ceiling).
    max_chunk_index = (1 << 32) - 1
    index = 0
    current = raw_in.read(full_ct_size)
    if not current:
        # Post-header failures raise ``DecryptionError`` (not
        # ``CorruptedContainerError``) so the CLI routes them through the
        # anti-oracle branch (exit 2 + constant message) rather than the
        # data-error branch (exit 65). An attacker who can influence the
        # trailing bytes of a ``.crypt`` (stream truncation) must not be
        # able to distinguish that failure from a wrong password.
        raise DecryptionError("ciphertext stream missing final chunk")

    while True:
        if len(current) < full_ct_size:
            # Short read → this is the last chunk regardless of what comes next.
            if len(current) < AES_GCM_TAG_BYTES:
                raise DecryptionError("truncated final chunk")
            yield _decrypt_one(
                cipher=cipher,
                base_nonce=base_nonce,
                aad_prefix=aad_prefix,
                index=index,
                ciphertext=current,
                is_final=True,
            )
            return

        next_chunk = raw_in.read(full_ct_size)
        if not next_chunk:
            # current is a full-size final chunk.
            yield _decrypt_one(
                cipher=cipher,
                base_nonce=base_nonce,
                aad_prefix=aad_prefix,
                index=index,
                ciphertext=current,
                is_final=True,
            )
            return

        yield _decrypt_one(
            cipher=cipher,
            base_nonce=base_nonce,
            aad_prefix=aad_prefix,
            index=index,
            ciphertext=current,
            is_final=False,
        )
        current = next_chunk
        index += 1
        if index > max_chunk_index:
            # A ``.crypt`` legitimately produced by this codebase caps at
            # ``max_chunk_index`` chunks (~256 TiB at 64 KiB chunks). A
            # crafted file claiming more is refused before the AEAD
            # surface is further stressed.
            raise DecryptionError("ciphertext stream exceeds 32-bit chunk counter")


def _decrypt_one(
    *,
    cipher: AesGcmCipher,
    base_nonce: bytes,
    aad_prefix: bytes,
    index: int,
    ciphertext: bytes,
    is_final: bool,
) -> bytes:
    nonce = derive_chunk_nonce(base_nonce, index)
    aad = chunk_aad(aad_prefix, index, is_final=is_final)
    return cipher.decrypt(nonce, ciphertext, aad)


def _split_message(message: bytes, chunk_bytes: int) -> Iterator[bytes]:
    for start in range(0, len(message), chunk_bytes):
        yield message[start : start + chunk_bytes]


def _default_decrypt_dest(source: Path) -> Path:
    if source.suffix == ENCRYPTED_SUFFIX:
        return source.with_suffix(DECRYPTED_SUFFIX)
    return source.with_name(source.name + DECRYPTED_SUFFIX)


def _zero_fill(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _check_dest_not_existing(target: Path, *, force: bool) -> None:
    """Refuse to overwrite an existing regular file unless ``force`` is set.

    ``os.replace`` silently overwrites on every platform; this guard
    surfaces the collision so users can opt in via ``--force`` or pick a
    different output path. Directories are left to the ``atomic_writer``
    which will fail with its own error -- we target regular files only.
    """
    if force:
        return
    if target.exists() and target.is_file():
        raise DestinationAlreadyExistsError(
            f"destination already exists: {target}. Pass force=True (CLI --force) to overwrite."
        )


def _password_bytes(password: str) -> bytes:
    """NFC-normalise a password before UTF-8 encoding.

    Two visually-identical passwords can round-trip through different
    Unicode codepoint sequences (``é`` as a single U+00E9 vs ``e`` +
    U+0301 combining acute accent). Without normalisation they derive
    distinct keys. We pick **NFC** (canonical composition) because it is
    the default on most systems (macOS still uses NFD but normalises to
    NFC on text output paths) and matches what a user's keyboard input
    usually produces.
    """
    import unicodedata

    return unicodedata.normalize("NFC", password).encode("utf-8")


# ---------------------------------------------------------------------------
# RSA share orchestration (T-003.04 + T-003.05)
# ---------------------------------------------------------------------------
#
# These two functions implement the spec 003 hybrid cryptosystem. The
# pattern is:
#
#   * sender takes a .crypt + their password, decrypts the source plaintext
#     into memory (capped by MAX_IN_MEMORY_MESSAGE_BYTES), generates a fresh
#     32-byte DEK, re-encrypts the plaintext with raw AES-GCM (no KDF -- the
#     DEK *is* the symmetric key, single-use), wraps the DEK under the
#     recipient's RSA-OAEP public key, signs the whole payload with their
#     RSA-PSS private key, and writes the .gbox-share token.
#
#   * recipient parses the token, verifies the signature *first* (anti-
#     oracle ordering), checks expiry, unwraps the DEK with their private
#     key, decrypts the embedded ciphertext, and writes the plaintext.
#
# Trade-off: the in-memory cap means files larger than 10 MiB cannot be
# shared today via this path. Streaming sharing is tracked as a follow-up
# (no academic-grade requirement for it).


def share_file(
    *,
    source: Path,
    sender_password: str,
    sender_user_id: UUID,
    sender_private_key: rsa.RSAPrivateKey,
    recipient_user_id: UUID,
    recipient_public_key: rsa.RSAPublicKey,
    output: Path,
    expires_at: int = 0,
    permission_flags: int = PERMISSION_READ,
    force: bool = False,
) -> Path:
    """Produce a ``.gbox-share`` token from a ``.crypt`` source.

    Args:
        source: A ``.crypt`` file the sender owns. Decrypted in memory
            with ``sender_password``; the resulting plaintext is then
            re-encrypted under a fresh DEK that is wrapped for the
            recipient.
        sender_password: Password for ``source`` (NFC-normalised inside).
        sender_user_id: Sender's UUID (for the audit chain on accept side).
        sender_private_key: Sender's RSA private key (used to sign the
            token).
        recipient_user_id: Recipient's UUID.
        recipient_public_key: Recipient's RSA public key (wraps the DEK).
        output: Where to write the ``.gbox-share`` token. Atomically
            written; refused if it already exists unless ``force=True``.
        expires_at: Unix epoch seconds; ``0`` = never. Bound by the v1
            uint64 field.
        permission_flags: Bitfield (read / re-share). Defaults to
            ``PERMISSION_READ``.
        force: Overwrite an existing destination.

    Returns:
        The resolved output path.

    Raises:
        DecryptionError: If ``sender_password`` does not unlock ``source``.
        MessageTooLargeError: If the source ``.crypt`` would decrypt to
            more than :data:`MAX_IN_MEMORY_MESSAGE_BYTES`.
        DestinationCollidesWithSourceError / DestinationAlreadyExistsError:
            Standard guards (cf. encrypt_file / decrypt_file).
        ValueError: For RSA-OAEP payload size or struct invariants.
    """
    source_resolved = source.resolve(strict=True)
    output_resolved = output if output.is_absolute() else (Path.cwd() / output)
    output_resolved = output_resolved.resolve()

    if output_resolved == source_resolved:
        raise DestinationCollidesWithSourceError(
            f"share output cannot equal the source: {source_resolved}"
        )
    _check_dest_not_existing(output_resolved, force=force)

    # Step 1: decrypt the source .crypt to plaintext (in memory; capped).
    plaintext_bytes = decrypt_message(source_resolved, sender_password)

    # Step 2-4: fresh DEK + raw AES-GCM encrypt + content hash. The DEK
    # lives in a bytearray so we can zero-fill it before returning.
    dek_buf = bytearray(secrets.token_bytes(AES_KEY_BYTES))
    embedded_nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    try:
        embedded_ct = AESGCM(bytes(dek_buf)).encrypt(embedded_nonce, plaintext_bytes, EMBEDDED_AAD)
        embedded = embedded_nonce + embedded_ct
        content_sha256 = hashlib.sha256(embedded).digest()

        # Step 5: wrap the DEK with the recipient's RSA-OAEP public key.
        wrapped_dek = RsaWrap.wrap(bytes(dek_buf), recipient_public_key)
    finally:
        _zero_fill(dek_buf)

    # Step 6: assemble header + sign payload + write atomically.
    header = ShareTokenHeader(
        sender_user_id=sender_user_id,
        recipient_user_id=recipient_user_id,
        content_sha256=content_sha256,
        wrapped_dek=wrapped_dek,
        expires_at=expires_at,
        permission_flags=permission_flags,
    )
    payload_to_sign = build_payload_for_signing(header, embedded)
    signature = RsaSign.sign(payload_to_sign, sender_private_key)
    blob = write_token(header=header, embedded_ciphertext=embedded, signature=signature)

    with atomic_writer(output_resolved) as out:
        out.write(blob)

    _log.info(
        "vault.share.created",
        sender_user_id=str(sender_user_id),
        recipient_user_id=str(recipient_user_id),
        embedded_size=len(embedded),
        expires_at=expires_at,
    )
    return output_resolved


def accept_share(
    *,
    source: Path,
    recipient_private_key: rsa.RSAPrivateKey,
    sender_public_key: rsa.RSAPublicKey,
    expected_recipient_user_id: UUID,
    output: Path,
    now_epoch: int | None = None,
    force: bool = False,
) -> Path:
    """Verify, unwrap, decrypt and write the plaintext from a share token.

    Operation ordering enforces the anti-oracle discipline (ADR-0015):

    1. Parse the on-disk bytes (no signature trust yet).
    2. Verify the signature with ``sender_public_key`` -- a tampered
       token surfaces as :class:`IntegrityError` here, before any unwrap
       or decrypt happens.
    3. Check ``expected_recipient_user_id`` matches the token's
       ``recipient_user_id`` -- raises :class:`IntegrityError` (uniform
       failure mode, no "wrong recipient" oracle).
    4. Check expiry -- :class:`ShareExpiredError` only after the token's
       authenticity is established.
    5. Verify ``content_sha256`` against the actual embedded bytes.
    6. Unwrap the DEK with ``recipient_private_key``.
    7. Decrypt the embedded ciphertext.
    8. Write the plaintext atomically.

    Args:
        source: Path to a ``.gbox-share`` file.
        recipient_private_key: Recipient's RSA private key (unwraps DEK).
        sender_public_key: Sender's RSA public key (verifies signature).
        expected_recipient_user_id: The recipient's UUID; the token's
            field must match exactly.
        output: Where to write the decrypted plaintext.
        now_epoch: Override clock for tests. Defaults to ``int(time.time())``.
        force: Overwrite an existing destination.

    Returns:
        The resolved output path.

    Raises:
        IntegrityError: Signature failure, recipient mismatch, content
            hash mismatch, or DEK unwrap / AEAD decrypt failure (all
            collapse to the same exception class -- anti-oracle).
        ShareExpiredError: Token's ``expires_at`` is in the past.
        DestinationAlreadyExistsError: Output exists and ``force=False``.
    """
    source_resolved = source.resolve(strict=True)
    output_resolved = output if output.is_absolute() else (Path.cwd() / output)
    output_resolved = output_resolved.resolve()
    _check_dest_not_existing(output_resolved, force=force)

    # Bound the read: the share is currently capped by the embedded
    # ciphertext size (cf. share_file). 16 KiB header overhead plus the
    # embedded ciphertext stays under MAX_IN_MEMORY_MESSAGE_BYTES + 16
    # KiB, well below any reasonable RAM budget.
    blob = source_resolved.read_bytes()

    # Step 1: parse (no trust).
    parsed: ParsedShareToken = read_token(blob)

    # Step 2: verify signature FIRST. After this point, every header
    # field is authentic.
    RsaSign.verify(parsed.signature, parsed.payload_bytes, sender_public_key)

    # Step 3: recipient match. We do a constant-time-ish comparison via
    # UUID.bytes equality (UUID.__eq__ short-circuits but the leak is on
    # public, low-entropy data, not secret).
    if parsed.header.recipient_user_id != expected_recipient_user_id:
        raise IntegrityError("share token addressed to a different recipient")

    # Step 4: expiry.
    now = now_epoch if now_epoch is not None else int(time.time())
    if parsed.header.expires_at != 0 and now > parsed.header.expires_at:
        raise ShareExpiredError(
            f"share token expired (expires_at={parsed.header.expires_at}, now={now})"
        )

    # Step 5: content hash check (defence in depth -- the signature
    # already covers these bytes, but verifying gives a clear-cut
    # IntegrityError if a programming bug ever decoupled hash from
    # ciphertext on the sender side).
    actual_sha256 = hashlib.sha256(parsed.embedded_ciphertext).digest()
    if actual_sha256 != parsed.header.content_sha256:
        raise IntegrityError("embedded ciphertext hash mismatch")

    # Step 6: unwrap DEK. Failure here means signature passed but the
    # token was crafted with the wrong recipient's pubkey -- still
    # IntegrityError for uniformity.
    dek_buf = bytearray(RsaWrap.unwrap(parsed.header.wrapped_dek, recipient_private_key))
    if len(dek_buf) != AES_KEY_BYTES:
        _zero_fill(dek_buf)
        raise IntegrityError(
            f"unwrapped DEK has unexpected length {len(dek_buf)} (expected {AES_KEY_BYTES})"
        )

    # Step 7: decrypt embedded ciphertext.
    if len(parsed.embedded_ciphertext) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
        _zero_fill(dek_buf)
        raise IntegrityError("embedded ciphertext shorter than nonce + tag")
    embedded_nonce = parsed.embedded_ciphertext[:AES_GCM_NONCE_BYTES]
    embedded_ct = parsed.embedded_ciphertext[AES_GCM_NONCE_BYTES:]
    try:
        plaintext = AESGCM(bytes(dek_buf)).decrypt(embedded_nonce, embedded_ct, EMBEDDED_AAD)
    except InvalidTag as exc:
        raise IntegrityError("embedded AES-GCM authentication failed") from exc
    finally:
        _zero_fill(dek_buf)

    # Step 8: write plaintext atomically.
    with atomic_writer(output_resolved) as out:
        out.write(plaintext)

    _log.info(
        "vault.share.accepted",
        sender_user_id=str(parsed.header.sender_user_id),
        recipient_user_id=str(parsed.header.recipient_user_id),
        plaintext_size=len(plaintext),
    )
    return output_resolved

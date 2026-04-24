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
from pathlib import Path
import secrets
from typing import IO

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AES_KEY_BYTES,
    CONTAINER_VERSION,
    DECRYPTED_SUFFIX,
    DEFAULT_CHUNK_BYTES,
    ENCRYPTED_SUFFIX,
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
    DestinationCollidesWithSourceError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.fileio.atomic import atomic_writer
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.fileio.streaming import iter_chunks
from guardiabox.logging import get_logger
from guardiabox.security.password import assert_strong

__all__ = [
    "DEFAULT_KDF",
    "ContainerInspection",
    "decrypt_file",
    "decrypt_message",
    "encrypt_file",
    "encrypt_message",
    "inspect_container",
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
) -> Path:
    """Encrypt ``message`` (raw bytes) to a ``.crypt`` file at ``dest``.

    Same ``root`` contract as :func:`encrypt_file`: ``dest`` must resolve
    strictly inside ``root``. The self-referential default of the first
    implementation (``dest.parent``) was flagged by the external audit
    as structurally no-op and has been removed. Chunk size is the
    module-wide :data:`DEFAULT_CHUNK_BYTES` — see :func:`encrypt_file`.
    """
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else DEFAULT_KDF()

    safe_target = resolve_within(dest, root)

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
    """
    source_resolved = source.resolve(strict=True)
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

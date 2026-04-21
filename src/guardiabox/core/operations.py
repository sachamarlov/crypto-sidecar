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
from guardiabox.core.exceptions import CorruptedContainerError, DecryptionError
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
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
    dest: Path | None = None,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> Path:
    """Encrypt ``source`` to ``dest`` (or ``source.crypt`` alongside).

    The password is validated against
    :func:`guardiabox.security.password.assert_strong` before any disk write,
    and any path escape is caught by :func:`resolve_within`. The derived key
    is zero-filled in memory after use.
    """
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else DEFAULT_KDF()

    source_resolved = source.resolve(strict=True)
    default_dest = source_resolved.parent / (source_resolved.name + ENCRYPTED_SUFFIX)
    target = dest if dest is not None else default_dest
    safe_target = resolve_within(target, source_resolved.parent)

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
        cipher = AesGcmCipher()
        with atomic_writer(safe_target) as out:
            write_header(out, header)
            _encrypt_stream(
                chunks=iter_chunks(source_resolved, chunk_bytes),
                cipher=cipher,
                key=bytes(key_buf),
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
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
    dest: Path,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> Path:
    """Encrypt ``message`` (raw bytes) to a ``.crypt`` file at ``dest``."""
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else DEFAULT_KDF()

    safe_target = resolve_within(dest, dest.resolve(strict=False).parent)

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
        cipher = AesGcmCipher()
        with atomic_writer(safe_target) as out:
            write_header(out, header)
            _encrypt_stream(
                chunks=_split_message(message, chunk_bytes),
                cipher=cipher,
                key=bytes(key_buf),
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
    dest: Path | None = None,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
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
    source_resolved = source.resolve(strict=True)
    default_dest = _default_decrypt_dest(source_resolved)
    target = dest if dest is not None else default_dest
    safe_target = resolve_within(target, source_resolved.parent)

    key_buf = bytearray(AES_KEY_BYTES)
    with source_resolved.open("rb") as raw_in:
        header = read_header(raw_in)
        aad_prefix = header_bytes(header)
        kdf_impl = kdf_for_id(header.kdf_id, header.kdf_params)
        try:
            derived = kdf_impl.derive(password.encode("utf-8"), header.salt, AES_KEY_BYTES)
            key_buf[:] = derived
            cipher = AesGcmCipher()
            with atomic_writer(safe_target) as out:
                try:
                    _decrypt_stream(
                        raw_in=raw_in,
                        cipher=cipher,
                        key=bytes(key_buf),
                        base_nonce=header.base_nonce,
                        aad_prefix=aad_prefix,
                        chunk_bytes=chunk_bytes,
                        out=out,
                    )
                except (DecryptionError, CorruptedContainerError) as exc:
                    _log.warning(
                        "vault.file.decrypt_failed",
                        kdf_id=kdf_impl.kdf_id,
                        reason=type(exc).__name__,
                    )
                    raise
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
    *,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
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
            derived = kdf_impl.derive(password.encode("utf-8"), header.salt, AES_KEY_BYTES)
            key_buf[:] = derived
            cipher = AesGcmCipher()
            try:
                for pt in _decrypt_stream_plaintext(
                    raw_in=raw_in,
                    cipher=cipher,
                    key=bytes(key_buf),
                    base_nonce=header.base_nonce,
                    aad_prefix=aad_prefix,
                    chunk_bytes=chunk_bytes,
                ):
                    buffer.extend(pt)
            except (DecryptionError, CorruptedContainerError) as exc:
                _log.warning(
                    "vault.message.decrypt_failed",
                    kdf_id=kdf_impl.kdf_id,
                    reason=type(exc).__name__,
                )
                raise
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
    key: bytes,
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
            key=key,
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
        key=key,
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
    key: bytes,
    base_nonce: bytes,
    aad_prefix: bytes,
    index: int,
    plaintext: bytes,
    is_final: bool,
) -> None:
    nonce = derive_chunk_nonce(base_nonce, index)
    aad = chunk_aad(aad_prefix, index, is_final=is_final)
    out.write(cipher.encrypt(key, nonce, plaintext, aad))


def _decrypt_stream(
    *,
    raw_in: IO[bytes],
    cipher: AesGcmCipher,
    key: bytes,
    base_nonce: bytes,
    aad_prefix: bytes,
    chunk_bytes: int,
    out: IO[bytes],
) -> None:
    out.writelines(
        _decrypt_stream_plaintext(
            raw_in=raw_in,
            cipher=cipher,
            key=key,
            base_nonce=base_nonce,
            aad_prefix=aad_prefix,
            chunk_bytes=chunk_bytes,
        )
    )


def _decrypt_stream_plaintext(
    *,
    raw_in: IO[bytes],
    cipher: AesGcmCipher,
    key: bytes,
    base_nonce: bytes,
    aad_prefix: bytes,
    chunk_bytes: int,
) -> Iterator[bytes]:
    full_ct_size = chunk_bytes + AES_GCM_TAG_BYTES
    index = 0
    current = raw_in.read(full_ct_size)
    if not current:
        raise CorruptedContainerError("ciphertext stream is empty — missing final chunk")

    while True:
        if len(current) < full_ct_size:
            # Short read → this is the last chunk regardless of what comes next.
            if len(current) < AES_GCM_TAG_BYTES:
                raise CorruptedContainerError("truncated final chunk (smaller than AES-GCM tag)")
            yield _decrypt_one(
                cipher=cipher,
                key=key,
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
                key=key,
                base_nonce=base_nonce,
                aad_prefix=aad_prefix,
                index=index,
                ciphertext=current,
                is_final=True,
            )
            return

        yield _decrypt_one(
            cipher=cipher,
            key=key,
            base_nonce=base_nonce,
            aad_prefix=aad_prefix,
            index=index,
            ciphertext=current,
            is_final=False,
        )
        current = next_chunk
        index += 1


def _decrypt_one(
    *,
    cipher: AesGcmCipher,
    key: bytes,
    base_nonce: bytes,
    aad_prefix: bytes,
    index: int,
    ciphertext: bytes,
    is_final: bool,
) -> bytes:
    nonce = derive_chunk_nonce(base_nonce, index)
    aad = chunk_aad(aad_prefix, index, is_final=is_final)
    return cipher.decrypt(key, nonce, ciphertext, aad)


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

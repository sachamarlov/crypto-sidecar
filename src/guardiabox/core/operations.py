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
from guardiabox.core.exceptions import CorruptedContainerError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.fileio.atomic import atomic_writer
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.fileio.streaming import iter_chunks
from guardiabox.security.password import assert_strong

__all__ = [
    "DEFAULT_KDF",
    "decrypt_file",
    "decrypt_message",
    "encrypt_file",
    "encrypt_message",
]

DEFAULT_KDF: type[Pbkdf2Kdf] = Pbkdf2Kdf


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

    return safe_target


def decrypt_file(
    source: Path,
    password: str,
    *,
    dest: Path | None = None,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> Path:
    """Decrypt ``source`` (a ``.crypt`` file) to ``dest``.

    ``dest`` defaults to ``source`` with ``.crypt`` replaced by ``.decrypt``.
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
                _decrypt_stream(
                    raw_in=raw_in,
                    cipher=cipher,
                    key=bytes(key_buf),
                    base_nonce=header.base_nonce,
                    aad_prefix=aad_prefix,
                    chunk_bytes=chunk_bytes,
                    out=out,
                )
        finally:
            _zero_fill(key_buf)

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
            for pt in _decrypt_stream_plaintext(
                raw_in=raw_in,
                cipher=cipher,
                key=bytes(key_buf),
                base_nonce=header.base_nonce,
                aad_prefix=aad_prefix,
                chunk_bytes=chunk_bytes,
            ):
                buffer.extend(pt)
        finally:
            _zero_fill(key_buf)
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

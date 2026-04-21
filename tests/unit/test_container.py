"""Round-trip and negative tests for the ``.crypt`` container header."""

from __future__ import annotations

import io
import struct

import pytest

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    CONTAINER_MAGIC,
    CONTAINER_VERSION,
    KDF_ID_ARGON2ID,
    KDF_ID_PBKDF2_SHA256,
    KDF_PARAMS_MAX_BYTES,
    SALT_BYTES,
)
from guardiabox.core.container import (
    ContainerHeader,
    header_bytes,
    read_header,
    write_header,
)
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    UnknownKdfError,
    UnsupportedVersionError,
)


def _valid_header(kdf_id: int = KDF_ID_PBKDF2_SHA256) -> ContainerHeader:
    return ContainerHeader(
        version=CONTAINER_VERSION,
        kdf_id=kdf_id,
        kdf_params=b"\x00\x09\x27\xc0",  # 600 000 big-endian
        salt=b"s" * SALT_BYTES,
        base_nonce=b"n" * AES_GCM_NONCE_BYTES,
    )


def test_roundtrip_pbkdf2() -> None:
    header = _valid_header()
    buf = io.BytesIO()
    write_header(buf, header)
    buf.seek(0)
    decoded = read_header(buf)
    assert decoded == header


def test_roundtrip_argon2id() -> None:
    header = ContainerHeader(
        version=CONTAINER_VERSION,
        kdf_id=KDF_ID_ARGON2ID,
        kdf_params=struct.pack("!III", 65536, 3, 1),
        salt=b"\x11" * SALT_BYTES,
        base_nonce=b"\x22" * AES_GCM_NONCE_BYTES,
    )
    buf = io.BytesIO()
    write_header(buf, header)
    buf.seek(0)
    decoded = read_header(buf)
    assert decoded == header


def test_header_bytes_matches_write_output() -> None:
    header = _valid_header()
    buf = io.BytesIO()
    write_header(buf, header)
    assert header_bytes(header) == buf.getvalue()


def test_header_starts_with_magic_and_version() -> None:
    header = _valid_header()
    raw = header_bytes(header)
    assert raw.startswith(CONTAINER_MAGIC)
    assert raw[4] == CONTAINER_VERSION


def test_bad_magic_raises() -> None:
    buf = io.BytesIO(b"XXXX" + b"\x01" * 8 + b"s" * SALT_BYTES + b"n" * 12)
    with pytest.raises(InvalidContainerError):
        read_header(buf)


def test_unsupported_version_raises() -> None:
    raw = (
        CONTAINER_MAGIC
        + struct.pack("!BBH", 99, KDF_ID_PBKDF2_SHA256, 4)
        + b"\x00\x09\x27\xc0"
        + b"s" * SALT_BYTES
        + b"n" * AES_GCM_NONCE_BYTES
    )
    with pytest.raises(UnsupportedVersionError):
        read_header(io.BytesIO(raw))


def test_unknown_kdf_id_raises() -> None:
    raw = (
        CONTAINER_MAGIC
        + struct.pack("!BBH", CONTAINER_VERSION, 0x7F, 0)
        + b"s" * SALT_BYTES
        + b"n" * AES_GCM_NONCE_BYTES
    )
    with pytest.raises(UnknownKdfError):
        read_header(io.BytesIO(raw))


def test_declared_params_length_exceeds_cap_raises() -> None:
    raw = CONTAINER_MAGIC + struct.pack("!BBH", CONTAINER_VERSION, KDF_ID_PBKDF2_SHA256, 0xFFFF)
    with pytest.raises(CorruptedContainerError):
        read_header(io.BytesIO(raw))


def test_truncated_salt_raises() -> None:
    raw = (
        CONTAINER_MAGIC
        + struct.pack("!BBH", CONTAINER_VERSION, KDF_ID_PBKDF2_SHA256, 4)
        + b"\x00\x09\x27\xc0"
        + b"\x00" * (SALT_BYTES - 1)
    )
    with pytest.raises(CorruptedContainerError):
        read_header(io.BytesIO(raw))


def test_truncated_magic_raises() -> None:
    with pytest.raises(CorruptedContainerError):
        read_header(io.BytesIO(b"GB"))


def test_invalid_salt_length_in_constructor() -> None:
    with pytest.raises(CorruptedContainerError):
        ContainerHeader(
            version=CONTAINER_VERSION,
            kdf_id=KDF_ID_PBKDF2_SHA256,
            kdf_params=b"\x00\x09\x27\xc0",
            salt=b"short",
            base_nonce=b"n" * AES_GCM_NONCE_BYTES,
        )


def test_invalid_base_nonce_length_in_constructor() -> None:
    with pytest.raises(CorruptedContainerError):
        ContainerHeader(
            version=CONTAINER_VERSION,
            kdf_id=KDF_ID_PBKDF2_SHA256,
            kdf_params=b"\x00\x09\x27\xc0",
            salt=b"s" * SALT_BYTES,
            base_nonce=b"short",
        )


def test_oversized_params_in_constructor() -> None:
    with pytest.raises(CorruptedContainerError):
        ContainerHeader(
            version=CONTAINER_VERSION,
            kdf_id=KDF_ID_PBKDF2_SHA256,
            kdf_params=b"\x00" * (KDF_PARAMS_MAX_BYTES + 1),
            salt=b"s" * SALT_BYTES,
            base_nonce=b"n" * AES_GCM_NONCE_BYTES,
        )

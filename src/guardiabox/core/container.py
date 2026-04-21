"""``.crypt`` container format (read / write).

On-disk layout (version 1, big-endian fixed-size fields except where noted):

.. code-block:: text

    offset  size       field
    ------  ---------  ------------------------------------------
    0       4          magic = b"GBOX"
    4       1          version = 0x01
    5       1          kdf_id (0x01=PBKDF2, 0x02=Argon2id)
    6       2          kdf_params_length (uint16 big-endian)
    8       N          kdf_params (variable, KDF-specific)
    8+N     16         salt
    24+N    12         base_nonce (per-chunk nonces are derived)
    36+N    *          ciphertext chunk stream (see below)

Each ciphertext chunk is authenticated individually with AES-GCM. The AEAD
``associated_data`` of every chunk binds it to the full header bytes, the
chunk index, and a final-flag, which protects against chunk reordering,
truncation, and header substitution. See :mod:`guardiabox.core.crypto`.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import IO

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    CONTAINER_MAGIC,
    CONTAINER_VERSION,
    KDF_ID_ARGON2ID,
    KDF_ID_PBKDF2_SHA256,
    KDF_PARAMS_MAX_BYTES,
    SALT_BYTES,
)
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    UnknownKdfError,
    UnsupportedVersionError,
)

__all__ = [
    "ContainerHeader",
    "header_bytes",
    "read_header",
    "write_header",
]

_MAGIC_LEN: int = len(CONTAINER_MAGIC)
_FIXED_PREFIX_STRUCT = struct.Struct("!BBH")  # version(1) | kdf_id(1) | kdf_params_len(2)
_SUPPORTED_KDF_IDS: frozenset[int] = frozenset({KDF_ID_PBKDF2_SHA256, KDF_ID_ARGON2ID})


@dataclass(frozen=True, slots=True)
class ContainerHeader:
    """Parsed view of a ``.crypt`` header (everything before the ciphertext)."""

    version: int
    kdf_id: int
    kdf_params: bytes
    salt: bytes
    base_nonce: bytes

    def __post_init__(self) -> None:
        if self.version != CONTAINER_VERSION:
            raise UnsupportedVersionError(
                f"unsupported container version {self.version}; "
                f"this build handles {CONTAINER_VERSION}"
            )
        if self.kdf_id not in _SUPPORTED_KDF_IDS:
            raise UnknownKdfError(f"unknown kdf_id=0x{self.kdf_id:02x}")
        if len(self.kdf_params) > KDF_PARAMS_MAX_BYTES:
            raise CorruptedContainerError(
                f"kdf_params length {len(self.kdf_params)} exceeds cap {KDF_PARAMS_MAX_BYTES}"
            )
        if len(self.salt) != SALT_BYTES:
            raise CorruptedContainerError(f"salt must be {SALT_BYTES} bytes, got {len(self.salt)}")
        if len(self.base_nonce) != AES_GCM_NONCE_BYTES:
            raise CorruptedContainerError(
                f"base_nonce must be {AES_GCM_NONCE_BYTES} bytes, got {len(self.base_nonce)}"
            )


def header_bytes(header: ContainerHeader) -> bytes:
    """Serialise ``header`` to the exact byte sequence written on disk."""
    prefix = _FIXED_PREFIX_STRUCT.pack(header.version, header.kdf_id, len(header.kdf_params))
    return b"".join((CONTAINER_MAGIC, prefix, header.kdf_params, header.salt, header.base_nonce))


def write_header(stream: IO[bytes], header: ContainerHeader) -> None:
    """Write ``header`` at the current position of ``stream``."""
    stream.write(header_bytes(header))


def read_header(stream: IO[bytes]) -> ContainerHeader:
    """Parse and return the header at the current position of ``stream``.

    Raises:
        InvalidContainerError: Magic bytes do not match.
        UnsupportedVersionError: Version byte is unknown.
        UnknownKdfError: KDF identifier is not implemented.
        CorruptedContainerError: Fixed-size fields are truncated or inconsistent.
    """
    magic = _read_exact(stream, _MAGIC_LEN, "magic")
    if magic != CONTAINER_MAGIC:
        raise InvalidContainerError(f"bad magic bytes {magic!r}")

    prefix = _read_exact(stream, _FIXED_PREFIX_STRUCT.size, "fixed prefix")
    version, kdf_id, kdf_params_len = _FIXED_PREFIX_STRUCT.unpack(prefix)

    if kdf_params_len > KDF_PARAMS_MAX_BYTES:
        raise CorruptedContainerError(
            f"declared kdf_params length {kdf_params_len} exceeds cap {KDF_PARAMS_MAX_BYTES}"
        )

    kdf_params = _read_exact(stream, kdf_params_len, "kdf_params")
    salt = _read_exact(stream, SALT_BYTES, "salt")
    base_nonce = _read_exact(stream, AES_GCM_NONCE_BYTES, "base_nonce")

    return ContainerHeader(
        version=version,
        kdf_id=kdf_id,
        kdf_params=kdf_params,
        salt=salt,
        base_nonce=base_nonce,
    )


def _read_exact(stream: IO[bytes], size: int, field_name: str) -> bytes:
    if size == 0:
        return b""
    data = stream.read(size)
    if len(data) != size:
        raise CorruptedContainerError(
            f"unexpected EOF while reading {field_name}: expected {size} bytes, got {len(data)}"
        )
    return data

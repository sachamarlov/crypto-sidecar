"""``.crypt`` container format (read / write).

On-disk layout (version 1, big-endian fixed-size fields except where noted):

.. code-block:: text

    offset  size       field
    ------  ---------  ------------------------------------------
    0       4          magic = b"GBOX"
    4       1          version = 0x01
    5       1          kdf_id (0x01=PBKDF2, 0x02=Argon2id)
    6       2          kdf_params_length (uint16)
    8       N          kdf_params (variable, KDF-specific)
    8+N     16         salt
    24+N    12         base_nonce (per-chunk nonces are derived)
    36+N    *          ciphertext chunks + per-chunk tags
    EOF-16  16         final integrity tag (over the chunk-stream)

The *base_nonce* + chunk counter scheme is necessary to avoid GCM nonce reuse
when streaming files larger than ~64 GiB. See ``docs/CRYPTO_DECISIONS.md``.

Implementation deliberately deferred — see
``docs/specs/001-encrypt-file/plan.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO


@dataclass(frozen=True, slots=True)
class ContainerHeader:
    """Parsed view of a ``.crypt`` header (everything before the ciphertext)."""

    version: int
    kdf_id: int
    kdf_params: bytes
    salt: bytes
    base_nonce: bytes


def write_header(stream: BinaryIO, header: ContainerHeader) -> None:
    """Write a header at the current position of ``stream``."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")


def read_header(stream: BinaryIO) -> ContainerHeader:
    """Parse and return the header from the current position of ``stream``."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

"""AES-GCM authenticated encryption primitive.

Thin wrapper around :class:`cryptography.hazmat.primitives.ciphers.aead.AESGCM`
implementing :class:`guardiabox.core.protocols.AeadCipher`.

Alongside the primitive, this module exposes two helpers used by the streaming
encryption pipeline:

* :func:`derive_chunk_nonce` — combine the per-file base nonce with the chunk
  counter to produce a unique 12-byte nonce per chunk. The 64 random bits of
  the base nonce keep collisions between distinct files negligible.
* :func:`chunk_aad` — build the associated-data blob bound to every chunk:
  full serialised header bytes + chunk index + final-flag. This prevents
  chunk reordering, truncation, and header substitution.

AESGCM context reuse (Fix-1.P)
------------------------------

``AesGcmCipher`` is **key-bound** by construction: instantiating it with a key
builds the underlying :class:`AESGCM` context once, and the same context is
reused for every chunk of the file. Prior to Fix-1.P the wrapper was
stateless and rebuilt the AESGCM context on every chunk, paying the AES key
schedule thousands of times per file for no gain. See NFR-1 (``docs/SPEC.md``).

The wrapper intentionally does **not** expose the key after construction;
callers zero-fill their own bytearray buffer and drop the cipher reference
when they are done with the file. The AESGCM C context still holds a copy
internally — ``docs/THREAT_MODEL.md`` §4.5 documents the honest scope.
"""

from __future__ import annotations

import struct
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AES_KEY_BYTES,
)
from guardiabox.core.exceptions import DecryptionError

__all__ = [
    "AesGcmCipher",
    "chunk_aad",
    "derive_chunk_nonce",
]

_CHUNK_NONCE_PREFIX_BYTES: int = 8
_CHUNK_NONCE_COUNTER_STRUCT = struct.Struct("!I")  # chunk_index (4 bytes big-endian)
_CHUNK_AAD_SUFFIX_STRUCT = struct.Struct("!IB")  # chunk_index | is_final
_MAX_CHUNK_INDEX: int = (1 << 32) - 1  # uint32 max


def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Return the 12-byte nonce used to encrypt chunk ``chunk_index``.

    The nonce is ``base_nonce[:8] || struct.pack('!I', chunk_index)``. The
    leading 8 bytes are the random per-file salt; the trailing 4 bytes are the
    chunk counter. Collisions on the nonce across files are bounded by the
    64-bit prefix, and within a single file the counter guarantees uniqueness.
    """
    if len(base_nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError(f"base_nonce must be {AES_GCM_NONCE_BYTES} bytes, got {len(base_nonce)}")
    if chunk_index < 0 or chunk_index > _MAX_CHUNK_INDEX:
        raise ValueError(f"chunk_index {chunk_index} out of range [0, {_MAX_CHUNK_INDEX}]")
    return base_nonce[:_CHUNK_NONCE_PREFIX_BYTES] + _CHUNK_NONCE_COUNTER_STRUCT.pack(chunk_index)


def chunk_aad(header_bytes: bytes, chunk_index: int, *, is_final: bool) -> bytes:
    """Return the associated-data blob bound to one ciphertext chunk.

    ``header_bytes`` is the full serialised container header (see
    :func:`guardiabox.core.container.header_bytes`). Including it in every
    chunk's AAD prevents an attacker from pairing the ciphertext stream with a
    different header. The trailing ``(index, is_final)`` field prevents
    reordering and truncation.
    """
    if chunk_index < 0 or chunk_index > _MAX_CHUNK_INDEX:
        raise ValueError(f"chunk_index {chunk_index} out of range [0, {_MAX_CHUNK_INDEX}]")
    return header_bytes + _CHUNK_AAD_SUFFIX_STRUCT.pack(chunk_index, 1 if is_final else 0)


class AesGcmCipher:
    """AES-256-GCM bound to a single key for its lifetime.

    Instantiate once per file / per secret; reuse for every chunk. The
    underlying :class:`AESGCM` context (and its AES key schedule) is
    allocated in :meth:`__init__` and shared across all ``encrypt`` /
    ``decrypt`` calls on the instance.
    """

    __slots__ = ("_impl",)

    nonce_bytes: ClassVar[int] = AES_GCM_NONCE_BYTES
    tag_bytes: ClassVar[int] = AES_GCM_TAG_BYTES

    def __init__(self, key: bytes) -> None:
        _validate_key(key)
        self._impl: AESGCM = AESGCM(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt ``plaintext`` and return ``ciphertext || tag``."""
        _validate_nonce(nonce)
        return self._impl.encrypt(nonce, plaintext, aad)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Return the plaintext if the tag verifies, else raise.

        :exc:`cryptography.exceptions.InvalidTag` is re-raised as
        :class:`~guardiabox.core.exceptions.DecryptionError` so callers never
        have to import ``cryptography.exceptions`` to discriminate failures.
        """
        _validate_nonce(nonce)
        if len(ciphertext_with_tag) < AES_GCM_TAG_BYTES:
            raise DecryptionError("ciphertext shorter than the AES-GCM tag")
        try:
            return self._impl.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag as exc:
            raise DecryptionError("AES-GCM authentication failed") from exc


def _validate_key(key: bytes) -> None:
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"key must be {AES_KEY_BYTES} bytes, got {len(key)}")


def _validate_nonce(nonce: bytes) -> None:
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError(f"nonce must be {AES_GCM_NONCE_BYTES} bytes, got {len(nonce)}")

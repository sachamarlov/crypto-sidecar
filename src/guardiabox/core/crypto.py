"""AES-GCM authenticated encryption primitive.

Thin wrapper around :class:`cryptography.hazmat.primitives.ciphers.aead.AESGCM`
implementing :class:`guardiabox.core.protocols.AeadCipher`.

Alongside the primitive, this module exposes helpers used by two distinct
callers:

Streaming pipeline (spec 001 / 002)
-----------------------------------

* :func:`derive_chunk_nonce` — combine the per-file base nonce with the chunk
  counter to produce a unique 12-byte nonce per chunk.
* :func:`chunk_aad` — build the associated-data blob bound to every chunk:
  full serialised header bytes + chunk index + final-flag. Prevents chunk
  reordering, truncation, and header substitution.

Column-level encryption (spec 000-multi-user, ADR-0011)
-------------------------------------------------------

* :func:`encrypt_column` / :func:`decrypt_column` — AES-GCM over a single
  column value with AAD bound to the column name and row id so ciphertext
  cannot be lifted from column A into column B or from row X into row Y.
* :func:`deterministic_index_hmac` — HMAC-SHA256 over the column name + plaintext,
  keyed on the vault key. Lets the repository layer do equality lookups on
  encrypted columns without decrypting every row.

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

import hmac
import secrets
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
    "decrypt_column",
    "derive_chunk_nonce",
    "deterministic_index_hmac",
    "encrypt_column",
]

# Byte separator used in the associated-data blob for column encryption.
# Bytes-safe, single char, unlikely to appear naturally in column names.
_COLUMN_AAD_SEPARATOR = b"\x1f"  # ASCII Unit Separator

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


# ---------------------------------------------------------------------------
# Column-level encryption (ADR-0011 fallback on Win/Mac without SQLCipher)
# ---------------------------------------------------------------------------


def _column_aad(column: str, row_id: bytes) -> bytes:
    """Build the AAD blob binding a ciphertext to a specific (column, row).

    Using ``column || 0x1f || row_id`` prevents an attacker with database
    write access from moving a ciphertext from row X's ``filename`` into
    row Y's ``filename``, or from ``filename`` into ``original_path``.
    Both moves would produce a different AAD and fail the GCM tag check.
    """
    if not column:
        raise ValueError("column name must be non-empty")
    return column.encode("utf-8") + _COLUMN_AAD_SEPARATOR + row_id


def encrypt_column(
    plaintext: bytes,
    vault_key: bytes,
    *,
    column: str,
    row_id: bytes,
) -> bytes:
    """Encrypt a single column value, returning ``nonce || ciphertext_with_tag``.

    Args:
        plaintext: The raw bytes to store in the column (e.g. UTF-8 filename).
        vault_key: 32-byte AES-256 key derived from the vault administrator
            password (see ADR-0011). Same key across every column of every
            row for the vault.
        column: Column name (e.g. ``"filename"``). Part of the AAD so
            ciphertext cannot be lifted to a different column.
        row_id: Stable row identifier (any bytes, typically the row's
            primary-key as UTF-8 or the 16-byte UUID). Part of the AAD so
            ciphertext cannot be lifted to a different row.

    Returns:
        ``nonce (12 bytes) || ciphertext || tag (16 bytes)`` — self-contained
        blob safe to store in a single ``BLOB`` column.

    Raises:
        ValueError: If ``vault_key`` is not 32 bytes or ``column`` is empty.
    """
    _validate_key(vault_key)
    nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    aad = _column_aad(column, row_id)
    ct = AESGCM(vault_key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_column(
    blob: bytes,
    vault_key: bytes,
    *,
    column: str,
    row_id: bytes,
) -> bytes:
    """Reverse :func:`encrypt_column`.

    Raises:
        DecryptionError: If the tag does not verify (wrong key, tampered
            blob, wrong column, wrong row_id — all indistinguishable).
        ValueError: If ``blob`` is shorter than nonce + tag or the key is
            the wrong size.
    """
    _validate_key(vault_key)
    if len(blob) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
        raise DecryptionError("encrypted column blob shorter than nonce + tag")
    nonce = blob[:AES_GCM_NONCE_BYTES]
    ct = blob[AES_GCM_NONCE_BYTES:]
    aad = _column_aad(column, row_id)
    try:
        return AESGCM(vault_key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("column AES-GCM authentication failed") from exc


def deterministic_index_hmac(
    vault_key: bytes,
    *,
    column: str,
    plaintext: bytes,
) -> bytes:
    """Return a stable 32-byte tag usable as an equality index on encrypted columns.

    The tag is ``HMAC-SHA256(key=vault_key, msg=column || 0x1f || plaintext)``.
    Two calls with the same arguments produce the same tag, so ``SELECT ...
    WHERE filename_index = ?`` works without decrypting every row.

    Binding the column name into the HMAC input prevents correlation: the
    string ``alice`` in ``username`` and in ``audit_log.target`` must
    produce distinct tags so an attacker with read access cannot tell
    they are the same value.

    Args:
        vault_key: 32-byte AES-256 vault key (same as encrypt_column).
        column: Column name; same separator rules as :func:`_column_aad`.
        plaintext: Value to index; should be the exact bytes the column
            would store encrypted.

    Returns:
        32-byte HMAC tag.

    Raises:
        ValueError: If ``vault_key`` is not 32 bytes or ``column`` is empty.
    """
    _validate_key(vault_key)
    if not column:
        raise ValueError("column name must be non-empty")
    msg = column.encode("utf-8") + _COLUMN_AAD_SEPARATOR + plaintext
    return hmac.new(vault_key, msg, "sha256").digest()

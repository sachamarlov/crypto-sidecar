"""Tests for AES-GCM wrapper and chunk-nonce / AAD helpers.

Since Fix-1.P the :class:`AesGcmCipher` wrapper is key-bound: the AESGCM
context is allocated once per instance and reused for every chunk. Tests
therefore instantiate a fresh cipher per scenario (``AesGcmCipher(key)``)
rather than passing the key to every call.
"""

from __future__ import annotations

import secrets
import struct

import pytest

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AES_KEY_BYTES,
)
from guardiabox.core.crypto import (
    AesGcmCipher,
    chunk_aad,
    derive_chunk_nonce,
)
from guardiabox.core.exceptions import DecryptionError


@pytest.fixture(name="key")
def _key() -> bytes:
    return secrets.token_bytes(AES_KEY_BYTES)


@pytest.fixture(name="nonce")
def _nonce() -> bytes:
    return secrets.token_bytes(AES_GCM_NONCE_BYTES)


@pytest.fixture(name="cipher")
def _cipher(key: bytes) -> AesGcmCipher:
    return AesGcmCipher(key)


# ---------------------------------------------------------------------------
# AesGcmCipher
# ---------------------------------------------------------------------------


def test_roundtrip_small(cipher: AesGcmCipher, nonce: bytes) -> None:
    plaintext = b"the magic words are squeamish ossifrage"
    ct = cipher.encrypt(nonce, plaintext)
    assert len(ct) == len(plaintext) + AES_GCM_TAG_BYTES
    assert cipher.decrypt(nonce, ct) == plaintext


def test_roundtrip_empty(cipher: AesGcmCipher, nonce: bytes) -> None:
    ct = cipher.encrypt(nonce, b"")
    assert len(ct) == AES_GCM_TAG_BYTES
    assert cipher.decrypt(nonce, ct) == b""


def test_aad_is_authenticated(cipher: AesGcmCipher, nonce: bytes) -> None:
    plaintext = b"payload"
    aad = b"context"
    ct = cipher.encrypt(nonce, plaintext, aad)
    with pytest.raises(DecryptionError):
        cipher.decrypt(nonce, ct, b"different-context")
    assert cipher.decrypt(nonce, ct, aad) == plaintext


def test_wrong_key_raises(cipher: AesGcmCipher, nonce: bytes) -> None:
    ct = cipher.encrypt(nonce, b"payload")
    other_cipher = AesGcmCipher(secrets.token_bytes(AES_KEY_BYTES))
    with pytest.raises(DecryptionError):
        other_cipher.decrypt(nonce, ct)


def test_wrong_nonce_raises(cipher: AesGcmCipher, nonce: bytes) -> None:
    ct = cipher.encrypt(nonce, b"payload")
    other_nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    with pytest.raises(DecryptionError):
        cipher.decrypt(other_nonce, ct)


def test_truncated_ciphertext_raises(cipher: AesGcmCipher, nonce: bytes) -> None:
    ct = cipher.encrypt(nonce, b"payload")
    with pytest.raises(DecryptionError):
        cipher.decrypt(nonce, ct[: AES_GCM_TAG_BYTES // 2])


def test_tampered_byte_raises(cipher: AesGcmCipher, nonce: bytes) -> None:
    ct = bytearray(cipher.encrypt(nonce, b"payload"))
    ct[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        cipher.decrypt(nonce, bytes(ct))


def test_invalid_key_size_raises() -> None:
    with pytest.raises(ValueError, match="key must be"):
        AesGcmCipher(b"\x00" * 10)


def test_invalid_nonce_size_raises(cipher: AesGcmCipher) -> None:
    with pytest.raises(ValueError, match="nonce must be"):
        cipher.encrypt(b"\x00" * 5, b"x")


def test_key_not_exposed_as_public_attribute(cipher: AesGcmCipher) -> None:
    """Key material stays behind the wrapper -- no public `.key` accessor."""
    assert not hasattr(cipher, "key")


# ---------------------------------------------------------------------------
# derive_chunk_nonce
# ---------------------------------------------------------------------------


def test_derive_chunk_nonce_layout() -> None:
    base = b"\xaa" * AES_GCM_NONCE_BYTES
    nonce_0 = derive_chunk_nonce(base, 0)
    nonce_1 = derive_chunk_nonce(base, 1)
    assert nonce_0[:8] == base[:8]
    assert nonce_0[8:] == struct.pack("!I", 0)
    assert nonce_1[8:] == struct.pack("!I", 1)
    assert nonce_0 != nonce_1


def test_derive_chunk_nonce_rejects_wrong_base_length() -> None:
    with pytest.raises(ValueError, match="base_nonce must be"):
        derive_chunk_nonce(b"short", 0)


def test_derive_chunk_nonce_rejects_negative_index() -> None:
    base = b"\xaa" * AES_GCM_NONCE_BYTES
    with pytest.raises(ValueError, match="chunk_index"):
        derive_chunk_nonce(base, -1)


def test_derive_chunk_nonce_rejects_overflow_index() -> None:
    base = b"\xaa" * AES_GCM_NONCE_BYTES
    with pytest.raises(ValueError, match="chunk_index"):
        derive_chunk_nonce(base, 1 << 32)


# ---------------------------------------------------------------------------
# chunk_aad
# ---------------------------------------------------------------------------


def test_chunk_aad_determinism() -> None:
    prefix = b"header-bytes"
    assert chunk_aad(prefix, 7, is_final=False) == chunk_aad(prefix, 7, is_final=False)


def test_chunk_aad_changes_with_final_flag() -> None:
    prefix = b"header-bytes"
    assert chunk_aad(prefix, 3, is_final=False) != chunk_aad(prefix, 3, is_final=True)


def test_chunk_aad_changes_with_index() -> None:
    prefix = b"header-bytes"
    assert chunk_aad(prefix, 1, is_final=False) != chunk_aad(prefix, 2, is_final=False)


def test_chunk_aad_rejects_negative_index() -> None:
    with pytest.raises(ValueError, match="chunk_index"):
        chunk_aad(b"h", -1, is_final=False)


def test_chunk_aad_rejects_overflow_index() -> None:
    with pytest.raises(ValueError, match="chunk_index"):
        chunk_aad(b"h", 1 << 32, is_final=False)

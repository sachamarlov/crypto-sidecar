"""Tests for AES-GCM wrapper and chunk-nonce / AAD helpers."""

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


@pytest.fixture(name="cipher")
def _cipher() -> AesGcmCipher:
    return AesGcmCipher()


@pytest.fixture(name="key")
def _key() -> bytes:
    return secrets.token_bytes(AES_KEY_BYTES)


@pytest.fixture(name="nonce")
def _nonce() -> bytes:
    return secrets.token_bytes(AES_GCM_NONCE_BYTES)


# ---------------------------------------------------------------------------
# AesGcmCipher
# ---------------------------------------------------------------------------


def test_roundtrip_small(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    plaintext = b"the magic words are squeamish ossifrage"
    ct = cipher.encrypt(key, nonce, plaintext)
    assert len(ct) == len(plaintext) + AES_GCM_TAG_BYTES
    assert cipher.decrypt(key, nonce, ct) == plaintext


def test_roundtrip_empty(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    ct = cipher.encrypt(key, nonce, b"")
    assert len(ct) == AES_GCM_TAG_BYTES
    assert cipher.decrypt(key, nonce, ct) == b""


def test_aad_is_authenticated(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    plaintext = b"payload"
    aad = b"context"
    ct = cipher.encrypt(key, nonce, plaintext, aad)
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, ct, b"different-context")
    assert cipher.decrypt(key, nonce, ct, aad) == plaintext


def test_wrong_key_raises(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    ct = cipher.encrypt(key, nonce, b"payload")
    other_key = secrets.token_bytes(AES_KEY_BYTES)
    with pytest.raises(DecryptionError):
        cipher.decrypt(other_key, nonce, ct)


def test_wrong_nonce_raises(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    ct = cipher.encrypt(key, nonce, b"payload")
    other_nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, other_nonce, ct)


def test_truncated_ciphertext_raises(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    ct = cipher.encrypt(key, nonce, b"payload")
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, ct[: AES_GCM_TAG_BYTES // 2])


def test_tampered_byte_raises(cipher: AesGcmCipher, key: bytes, nonce: bytes) -> None:
    ct = bytearray(cipher.encrypt(key, nonce, b"payload"))
    ct[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, bytes(ct))


def test_invalid_key_size_raises(cipher: AesGcmCipher, nonce: bytes) -> None:
    with pytest.raises(ValueError, match="key must be"):
        cipher.encrypt(b"\x00" * 10, nonce, b"x")


def test_invalid_nonce_size_raises(cipher: AesGcmCipher, key: bytes) -> None:
    with pytest.raises(ValueError, match="nonce must be"):
        cipher.encrypt(key, b"\x00" * 5, b"x")


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

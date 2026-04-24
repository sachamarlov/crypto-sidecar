"""Tests for column-level encryption helpers (ADR-0011 fallback).

These helpers power the Windows / macOS persistence path where SQLCipher
is unavailable. The correctness contracts they enforce:

* Round-trip: ``decrypt_column(encrypt_column(x)) == x``.
* AAD binding: ciphertext encrypted under ``column=A, row=1`` fails to
  decrypt under any other ``(column, row)`` tuple.
* Deterministic index: the HMAC tag is stable across calls with the
  same inputs but changes with the key, the column name, or the value.
"""

from __future__ import annotations

import secrets

from hypothesis import given, settings, strategies as st
import pytest

from guardiabox.core.constants import AES_KEY_BYTES
from guardiabox.core.crypto import (
    decrypt_column,
    deterministic_index_hmac,
    encrypt_column,
)
from guardiabox.core.exceptions import DecryptionError


@pytest.fixture(name="vault_key")
def _vault_key() -> bytes:
    return secrets.token_bytes(AES_KEY_BYTES)


# ---------------------------------------------------------------------------
# encrypt_column / decrypt_column
# ---------------------------------------------------------------------------


def test_roundtrip_small(vault_key: bytes) -> None:
    blob = encrypt_column(b"invoice-2026.pdf", vault_key, column="filename", row_id=b"1")
    assert decrypt_column(blob, vault_key, column="filename", row_id=b"1") == b"invoice-2026.pdf"


def test_roundtrip_empty_plaintext(vault_key: bytes) -> None:
    blob = encrypt_column(b"", vault_key, column="filename", row_id=b"7")
    assert decrypt_column(blob, vault_key, column="filename", row_id=b"7") == b""


def test_roundtrip_long_plaintext(vault_key: bytes) -> None:
    payload = b"X" * 10_000
    blob = encrypt_column(payload, vault_key, column="metadata", row_id=b"42")
    assert decrypt_column(blob, vault_key, column="metadata", row_id=b"42") == payload


def test_two_encryptions_differ_even_with_same_inputs(vault_key: bytes) -> None:
    """Fresh nonce per call → two ciphertexts for the same plaintext."""
    a = encrypt_column(b"secret", vault_key, column="filename", row_id=b"1")
    b = encrypt_column(b"secret", vault_key, column="filename", row_id=b"1")
    assert a != b
    # But both decrypt to the same plaintext.
    assert decrypt_column(a, vault_key, column="filename", row_id=b"1") == b"secret"
    assert decrypt_column(b, vault_key, column="filename", row_id=b"1") == b"secret"


def test_wrong_column_rejects(vault_key: bytes) -> None:
    blob = encrypt_column(b"alice", vault_key, column="username", row_id=b"1")
    with pytest.raises(DecryptionError):
        decrypt_column(blob, vault_key, column="email", row_id=b"1")


def test_wrong_row_id_rejects(vault_key: bytes) -> None:
    blob = encrypt_column(b"alice", vault_key, column="username", row_id=b"1")
    with pytest.raises(DecryptionError):
        decrypt_column(blob, vault_key, column="username", row_id=b"2")


def test_wrong_key_rejects(vault_key: bytes) -> None:
    other_key = secrets.token_bytes(AES_KEY_BYTES)
    blob = encrypt_column(b"alice", vault_key, column="username", row_id=b"1")
    with pytest.raises(DecryptionError):
        decrypt_column(blob, other_key, column="username", row_id=b"1")


def test_tampered_blob_rejects(vault_key: bytes) -> None:
    blob = bytearray(encrypt_column(b"secret", vault_key, column="f", row_id=b"r"))
    blob[-1] ^= 0x01  # flip a tag byte
    with pytest.raises(DecryptionError):
        decrypt_column(bytes(blob), vault_key, column="f", row_id=b"r")


def test_short_blob_rejects(vault_key: bytes) -> None:
    with pytest.raises(DecryptionError):
        decrypt_column(b"\x00" * 4, vault_key, column="f", row_id=b"r")


def test_empty_column_name_refused(vault_key: bytes) -> None:
    with pytest.raises(ValueError, match="column"):
        encrypt_column(b"x", vault_key, column="", row_id=b"1")
    with pytest.raises(ValueError, match="column"):
        decrypt_column(b"\x00" * 28, vault_key, column="", row_id=b"1")


def test_invalid_key_size_refused() -> None:
    with pytest.raises(ValueError, match="key"):
        encrypt_column(b"x", b"\x00" * 10, column="f", row_id=b"r")
    with pytest.raises(ValueError, match="key"):
        decrypt_column(b"\x00" * 28, b"\x00" * 10, column="f", row_id=b"r")


# ---------------------------------------------------------------------------
# deterministic_index_hmac
# ---------------------------------------------------------------------------


def test_index_is_deterministic(vault_key: bytes) -> None:
    a = deterministic_index_hmac(vault_key, column="filename", plaintext=b"alice.pdf")
    b = deterministic_index_hmac(vault_key, column="filename", plaintext=b"alice.pdf")
    assert a == b
    assert len(a) == 32  # HMAC-SHA256 output


def test_index_differs_per_column(vault_key: bytes) -> None:
    """Same plaintext in two distinct columns must yield distinct indices."""
    a = deterministic_index_hmac(vault_key, column="username", plaintext=b"alice")
    b = deterministic_index_hmac(vault_key, column="audit_target", plaintext=b"alice")
    assert a != b


def test_index_differs_per_key() -> None:
    """Same plaintext + column but different keys → different indices.

    A user reading one vault's DB must not be able to correlate entries
    with another vault's DB.
    """
    k1 = secrets.token_bytes(AES_KEY_BYTES)
    k2 = secrets.token_bytes(AES_KEY_BYTES)
    a = deterministic_index_hmac(k1, column="filename", plaintext=b"x.pdf")
    b = deterministic_index_hmac(k2, column="filename", plaintext=b"x.pdf")
    assert a != b


def test_index_differs_per_plaintext(vault_key: bytes) -> None:
    a = deterministic_index_hmac(vault_key, column="filename", plaintext=b"a.pdf")
    b = deterministic_index_hmac(vault_key, column="filename", plaintext=b"b.pdf")
    assert a != b


def test_index_rejects_empty_column(vault_key: bytes) -> None:
    with pytest.raises(ValueError, match="column"):
        deterministic_index_hmac(vault_key, column="", plaintext=b"x")


def test_index_rejects_wrong_key_size() -> None:
    with pytest.raises(ValueError, match="key"):
        deterministic_index_hmac(b"\x00" * 10, column="f", plaintext=b"x")


# ---------------------------------------------------------------------------
# Property-based round-trip
# ---------------------------------------------------------------------------


@pytest.mark.property
@given(
    plaintext=st.binary(min_size=0, max_size=2048),
    column=st.text(
        alphabet=st.characters(blacklist_categories=["Cs"], blacklist_characters="\x00"),
        min_size=1,
        max_size=64,
    ),
    row_id=st.binary(min_size=1, max_size=64),
)
@settings(max_examples=100, deadline=None)
def test_roundtrip_property(plaintext: bytes, column: str, row_id: bytes) -> None:
    """Any reasonable (plaintext, column, row_id) triple must round-trip."""
    vault_key = secrets.token_bytes(AES_KEY_BYTES)
    blob = encrypt_column(plaintext, vault_key, column=column, row_id=row_id)
    assert decrypt_column(blob, vault_key, column=column, row_id=row_id) == plaintext

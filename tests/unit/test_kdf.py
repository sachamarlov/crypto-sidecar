"""Tests for PBKDF2 and Argon2id wrappers.

Strategy:

* **Wire correctness** — our wrapper must produce the same output as the
  underlying primitive called directly with the same parameters. That rules out
  wrapping bugs without duplicating pyca/cryptography's or argon2-cffi's own
  KAT suites.
* **Floor enforcement** — any parameter below ``docs/CRYPTO_DECISIONS.md``'s
  minimum raises at construction time and again at ``decode_params``.
* **Header params round-trip** — encoding then decoding yields an
  equivalent instance.
"""

from __future__ import annotations

import struct

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pytest

from guardiabox.core.constants import (
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    KDF_ID_ARGON2ID,
    KDF_ID_PBKDF2_SHA256,
    PBKDF2_MIN_ITERATIONS,
)
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    UnknownKdfError,
    WeakKdfParametersError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id

# ---------------------------------------------------------------------------
# PBKDF2
# ---------------------------------------------------------------------------


def test_pbkdf2_wire_matches_primitive() -> None:
    password = b"Correct_Horse_Battery_Staple_42!"
    salt = b"A" * 16
    ours = Pbkdf2Kdf().derive(password, salt, 32)
    reference = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_MIN_ITERATIONS,
    ).derive(password)
    assert ours == reference
    assert len(ours) == 32


def test_pbkdf2_below_floor_refused() -> None:
    with pytest.raises(WeakKdfParametersError):
        Pbkdf2Kdf(iterations=PBKDF2_MIN_ITERATIONS - 1)


def test_pbkdf2_salt_below_floor_refused() -> None:
    with pytest.raises(WeakKdfParametersError):
        Pbkdf2Kdf().derive(b"password", b"short", 32)


def test_pbkdf2_zero_length_refused() -> None:
    with pytest.raises(ValueError, match="positive"):
        Pbkdf2Kdf().derive(b"password", b"A" * 16, 0)


def test_pbkdf2_encode_decode_roundtrip() -> None:
    kdf = Pbkdf2Kdf(iterations=750_000)
    blob = kdf.encode_params()
    assert len(blob) == 4  # uint32 big-endian
    assert struct.unpack("!I", blob)[0] == 750_000
    decoded = Pbkdf2Kdf.decode_params(blob)
    assert decoded == kdf


def test_pbkdf2_decode_wrong_length_raises() -> None:
    with pytest.raises(CorruptedContainerError):
        Pbkdf2Kdf.decode_params(b"\x00\x00")


def test_pbkdf2_decode_below_floor_raises() -> None:
    blob = struct.pack("!I", 1)
    with pytest.raises(WeakKdfParametersError):
        Pbkdf2Kdf.decode_params(blob)


def test_pbkdf2_kdf_id_byte() -> None:
    assert Pbkdf2Kdf.kdf_id == KDF_ID_PBKDF2_SHA256
    assert 0 < Pbkdf2Kdf.kdf_id <= 0xFF


# ---------------------------------------------------------------------------
# Argon2id
# ---------------------------------------------------------------------------


def test_argon2id_wire_matches_primitive() -> None:
    password = b"a" * 32
    salt = b"B" * 16
    kdf = Argon2idKdf()
    ours = kdf.derive(password, salt, 32)
    reference = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=kdf.time_cost,
        memory_cost=kdf.memory_cost_kib,
        parallelism=kdf.parallelism,
        hash_len=32,
        type=Type.ID,
    )
    assert ours == reference


def test_argon2id_floor_enforcement() -> None:
    with pytest.raises(WeakKdfParametersError):
        Argon2idKdf(memory_cost_kib=ARGON2_MIN_MEMORY_KIB - 1)
    with pytest.raises(WeakKdfParametersError):
        Argon2idKdf(time_cost=ARGON2_MIN_TIME_COST - 1)
    with pytest.raises(WeakKdfParametersError):
        Argon2idKdf(parallelism=ARGON2_MIN_PARALLELISM - 1)


def test_argon2id_encode_decode_roundtrip() -> None:
    kdf = Argon2idKdf(memory_cost_kib=131_072, time_cost=4, parallelism=2)
    blob = kdf.encode_params()
    assert len(blob) == 12  # three uint32 big-endian
    decoded = Argon2idKdf.decode_params(blob)
    assert decoded == kdf


def test_argon2id_decode_wrong_length_raises() -> None:
    with pytest.raises(CorruptedContainerError):
        Argon2idKdf.decode_params(b"\x00\x00\x00\x00")


def test_argon2id_decode_below_floor_raises() -> None:
    blob = struct.pack("!III", 1024, 1, 1)
    with pytest.raises(WeakKdfParametersError):
        Argon2idKdf.decode_params(blob)


def test_argon2id_kdf_id_byte() -> None:
    assert Argon2idKdf.kdf_id == KDF_ID_ARGON2ID
    assert 0 < Argon2idKdf.kdf_id <= 0xFF


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_kdf_for_id_returns_pbkdf2() -> None:
    kdf = Pbkdf2Kdf()
    back = kdf_for_id(KDF_ID_PBKDF2_SHA256, kdf.encode_params())
    assert isinstance(back, Pbkdf2Kdf)
    assert back == kdf


def test_kdf_for_id_returns_argon2id() -> None:
    kdf = Argon2idKdf()
    back = kdf_for_id(KDF_ID_ARGON2ID, kdf.encode_params())
    assert isinstance(back, Argon2idKdf)
    assert back == kdf


def test_kdf_for_id_unknown_raises() -> None:
    with pytest.raises(UnknownKdfError):
        kdf_for_id(0xEE, b"")

"""Unit tests for :mod:`guardiabox.core.rsa` (T-003.01 + T-003.02)."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import pytest

from guardiabox.core.exceptions import IntegrityError
from guardiabox.core.rsa import (
    RsaSign,
    RsaWrap,
    load_private_key_der,
    load_public_key_pem,
)

# ---------------------------------------------------------------------------
# Session-scoped key fixtures — RSA keygen is expensive (~ 100 ms for 2048 bit,
# ~ 1 s for 4096 bit). Generating once per session keeps the suite fast.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key_a() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_key_b() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_key_4096() -> rsa.RSAPrivateKey:
    """The size used in production (matches keystore default)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


# ---------------------------------------------------------------------------
# RsaWrap — round-trip + negative paths
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrip_returns_original_dek(rsa_key_a: rsa.RSAPrivateKey) -> None:
    dek = b"\xaa" * 32  # representative AES-256 DEK
    wrapped = RsaWrap.wrap(dek, rsa_key_a.public_key())
    assert RsaWrap.unwrap(wrapped, rsa_key_a) == dek


def test_wrap_is_non_deterministic(rsa_key_a: rsa.RSAPrivateKey) -> None:
    """OAEP draws fresh randomness — two wraps of the same DEK must differ."""
    dek = b"\x01" * 32
    pub = rsa_key_a.public_key()
    assert RsaWrap.wrap(dek, pub) != RsaWrap.wrap(dek, pub)


def test_wrap_output_length_matches_modulus(rsa_key_a: rsa.RSAPrivateKey) -> None:
    """The wrap is exactly ``modulus_bytes`` long (2048 bits = 256 bytes)."""
    wrapped = RsaWrap.wrap(b"\x00" * 32, rsa_key_a.public_key())
    assert len(wrapped) == 256  # 2048 / 8


def test_unwrap_with_wrong_private_key_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
    rsa_key_b: rsa.RSAPrivateKey,
) -> None:
    wrapped = RsaWrap.wrap(b"secret payload", rsa_key_a.public_key())
    with pytest.raises(IntegrityError):
        RsaWrap.unwrap(wrapped, rsa_key_b)


def test_unwrap_with_byte_flipped_ciphertext_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
) -> None:
    wrapped = bytearray(RsaWrap.wrap(b"\x33" * 32, rsa_key_a.public_key()))
    wrapped[42] ^= 0x01  # flip a single bit somewhere in the middle
    with pytest.raises(IntegrityError):
        RsaWrap.unwrap(bytes(wrapped), rsa_key_a)


def test_unwrap_with_truncated_ciphertext_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
) -> None:
    wrapped = RsaWrap.wrap(b"\x33" * 32, rsa_key_a.public_key())
    with pytest.raises(IntegrityError):
        RsaWrap.unwrap(wrapped[:-1], rsa_key_a)


def test_wrap_payload_too_large_raises_value_error(rsa_key_a: rsa.RSAPrivateKey) -> None:
    """OAEP-SHA256 + 2048-bit key allows at most 256 - 2*32 - 2 = 190 bytes."""
    too_large = b"x" * 191
    with pytest.raises(ValueError, match=r"(?i)encryption|too large|message"):
        RsaWrap.wrap(too_large, rsa_key_a.public_key())


def test_wrap_unwrap_with_4096_bit_key_roundtrip(rsa_key_4096: rsa.RSAPrivateKey) -> None:
    """4096-bit is the production key size (keystore default)."""
    dek = b"\x5a" * 32
    wrapped = RsaWrap.wrap(dek, rsa_key_4096.public_key())
    assert len(wrapped) == 512  # 4096 / 8
    assert RsaWrap.unwrap(wrapped, rsa_key_4096) == dek


def test_wrap_empty_payload_roundtrip(rsa_key_a: rsa.RSAPrivateKey) -> None:
    """OAEP allows empty payloads — useful for negative tests later."""
    wrapped = RsaWrap.wrap(b"", rsa_key_a.public_key())
    assert RsaWrap.unwrap(wrapped, rsa_key_a) == b""


# ---------------------------------------------------------------------------
# RsaSign — round-trip + negative paths
# ---------------------------------------------------------------------------


def test_sign_verify_roundtrip(rsa_key_a: rsa.RSAPrivateKey) -> None:
    payload = b"share token payload bytes"
    signature = RsaSign.sign(payload, rsa_key_a)
    RsaSign.verify(signature, payload, rsa_key_a.public_key())


def test_sign_is_non_deterministic(rsa_key_a: rsa.RSAPrivateKey) -> None:
    """PSS uses a random salt — two signatures of the same payload must differ."""
    payload = b"deterministic-input"
    sig1 = RsaSign.sign(payload, rsa_key_a)
    sig2 = RsaSign.sign(payload, rsa_key_a)
    assert sig1 != sig2


def test_signature_length_matches_modulus(rsa_key_a: rsa.RSAPrivateKey) -> None:
    sig = RsaSign.sign(b"x", rsa_key_a)
    assert len(sig) == 256  # 2048 / 8


def test_verify_with_wrong_public_key_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
    rsa_key_b: rsa.RSAPrivateKey,
) -> None:
    payload = b"authentic payload"
    sig = RsaSign.sign(payload, rsa_key_a)
    with pytest.raises(IntegrityError):
        RsaSign.verify(sig, payload, rsa_key_b.public_key())


def test_verify_with_tampered_payload_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
) -> None:
    payload = b"authentic payload"
    sig = RsaSign.sign(payload, rsa_key_a)
    tampered = payload[:-1] + bytes([payload[-1] ^ 0x01])
    with pytest.raises(IntegrityError):
        RsaSign.verify(sig, tampered, rsa_key_a.public_key())


def test_verify_with_tampered_signature_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
) -> None:
    payload = b"authentic payload"
    sig = bytearray(RsaSign.sign(payload, rsa_key_a))
    sig[10] ^= 0x01
    with pytest.raises(IntegrityError):
        RsaSign.verify(bytes(sig), payload, rsa_key_a.public_key())


def test_verify_with_truncated_signature_raises_integrity_error(
    rsa_key_a: rsa.RSAPrivateKey,
) -> None:
    payload = b"authentic payload"
    sig = RsaSign.sign(payload, rsa_key_a)
    with pytest.raises(IntegrityError):
        RsaSign.verify(sig[:-1], payload, rsa_key_a.public_key())


def test_sign_verify_with_4096_bit_key_roundtrip(rsa_key_4096: rsa.RSAPrivateKey) -> None:
    payload = b"production key signature path"
    sig = RsaSign.sign(payload, rsa_key_4096)
    assert len(sig) == 512
    RsaSign.verify(sig, payload, rsa_key_4096.public_key())


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def test_load_public_key_pem_roundtrip(rsa_key_a: rsa.RSAPrivateKey) -> None:
    pem = rsa_key_a.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded = load_public_key_pem(pem)
    assert isinstance(loaded, rsa.RSAPublicKey)
    # The loaded key must wrap into something the original private key unwraps.
    wrapped = RsaWrap.wrap(b"\x77" * 32, loaded)
    assert RsaWrap.unwrap(wrapped, rsa_key_a) == b"\x77" * 32


def test_load_public_key_pem_rejects_non_rsa_key() -> None:
    """An EC public key in PEM form must be refused."""
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(TypeError, match="expected RSA public key"):
        load_public_key_pem(pem)


def test_load_public_key_pem_rejects_garbage() -> None:
    with pytest.raises(ValueError, match=r".+"):  # pyca raises ValueError on parse fail
        load_public_key_pem(b"not a key at all")


def test_load_private_key_der_roundtrip(rsa_key_a: rsa.RSAPrivateKey) -> None:
    der = rsa_key_a.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    loaded = load_private_key_der(der)
    assert isinstance(loaded, rsa.RSAPrivateKey)
    # The reloaded key must unwrap something wrapped under the original public.
    wrapped = RsaWrap.wrap(b"\x55" * 32, rsa_key_a.public_key())
    assert RsaWrap.unwrap(wrapped, loaded) == b"\x55" * 32


def test_load_private_key_der_rejects_non_rsa_key() -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der = ec_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(TypeError, match="expected RSA private key"):
        load_private_key_der(der)

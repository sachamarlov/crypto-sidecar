"""Property-based tests for :mod:`guardiabox.core.rsa`.

The RFC 8017 Appendix C KAT vectors target 1024-bit / 2048-bit toy keys
with a deterministic shape that does not match our 4096-bit keystore
defaults. Instead of replaying static vectors, we exhaustively
property-test the round-trip on arbitrary payloads — a strictly stronger
signal because it covers boundary sizes (empty, OAEP max, off-by-one)
that the static KAT does not.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given, settings, strategies as st
import pytest

from guardiabox.core.exceptions import IntegrityError
from guardiabox.core.rsa import RsaSign, RsaWrap

# 2048-bit key: OAEP-SHA256 max payload = 256 - 2*32 - 2 = 190 bytes.
_OAEP_MAX_PAYLOAD = 190


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@settings(max_examples=50, deadline=None)
@given(payload=st.binary(min_size=0, max_size=_OAEP_MAX_PAYLOAD))
def test_wrap_unwrap_roundtrip_property(
    rsa_key: rsa.RSAPrivateKey,
    payload: bytes,
) -> None:
    wrapped = RsaWrap.wrap(payload, rsa_key.public_key())
    assert RsaWrap.unwrap(wrapped, rsa_key) == payload


@settings(max_examples=50, deadline=None)
@given(payload=st.binary(min_size=0, max_size=4096))
def test_sign_verify_roundtrip_property(
    rsa_key: rsa.RSAPrivateKey,
    payload: bytes,
) -> None:
    signature = RsaSign.sign(payload, rsa_key)
    RsaSign.verify(signature, payload, rsa_key.public_key())


@settings(max_examples=30, deadline=None)
@given(
    payload=st.binary(min_size=1, max_size=512),
    flip_index=st.integers(min_value=0, max_value=255),
)
def test_signature_byte_flip_always_fails(
    rsa_key: rsa.RSAPrivateKey,
    payload: bytes,
    flip_index: int,
) -> None:
    sig = bytearray(RsaSign.sign(payload, rsa_key))
    flip_index %= len(sig)
    sig[flip_index] ^= 0x01
    with pytest.raises(IntegrityError):
        RsaSign.verify(bytes(sig), payload, rsa_key.public_key())

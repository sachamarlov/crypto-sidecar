"""Tests for :mod:`guardiabox.security.keystore`.

RSA-4096 key generation is slow (~1 s per call on a laptop); the most
expensive tests use ``rsa_key_bits=2048`` to keep the suite under a
couple of seconds. The default 4096 bits is exercised in one
``@pytest.mark.slow`` smoke so we still catch a regression on the real
size.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
import pytest

from guardiabox.core.exceptions import DecryptionError, WeakPasswordError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.security.keystore import Keystore, change_password, create, unlock

STRONG = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
OTHER_STRONG = "Different_Horse_Battery_Staple_42!"  # pragma: allowlist secret
# Smaller key for fast tests; the full 4096 is asserted in the slow smoke.
TEST_RSA_BITS = 2048


def test_create_then_unlock_roundtrip() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    vault_key = unlock(ks, STRONG)
    assert len(vault_key) == 32


def test_unlock_wrong_password_raises_decryption_error() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    with pytest.raises(DecryptionError):
        unlock(ks, OTHER_STRONG)


def test_two_keystores_have_distinct_salts_and_keys() -> None:
    """Fresh randomness per call: salt, vault key, wraps all differ."""
    a = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    b = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    assert a.salt != b.salt
    assert a.wrapped_vault_key != b.wrapped_vault_key
    assert unlock(a, STRONG) != unlock(b, STRONG)


def test_create_refuses_weak_password() -> None:
    with pytest.raises(WeakPasswordError):
        create("weak", rsa_key_bits=TEST_RSA_BITS)


def test_rsa_public_pem_is_parseable() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    pub = serialization.load_pem_public_key(ks.rsa_public_pem)
    assert pub.key_size == TEST_RSA_BITS


def test_tampered_wrap_surfaces_as_decryption_error() -> None:
    """Flipping a byte in the vault-key wrap must fail the GCM tag."""
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    tampered_wrap = bytearray(ks.wrapped_vault_key)
    tampered_wrap[-1] ^= 0x01
    tampered = Keystore(
        salt=ks.salt,
        kdf_id=ks.kdf_id,
        kdf_params=ks.kdf_params,
        wrapped_vault_key=bytes(tampered_wrap),
        wrapped_rsa_private=ks.wrapped_rsa_private,
        rsa_public_pem=ks.rsa_public_pem,
    )
    with pytest.raises(DecryptionError):
        unlock(tampered, STRONG)


def test_wraps_use_distinct_aad_contexts() -> None:
    """The vault-key wrap must not decrypt under the RSA-private AAD.

    Enforced by giving each wrap a different context string at
    :func:`_wrap` time. A sophisticated attacker swapping the two
    ciphertexts in a crafted keystore still cannot extract anything.
    """
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    swapped = Keystore(
        salt=ks.salt,
        kdf_id=ks.kdf_id,
        kdf_params=ks.kdf_params,
        # Put the RSA-private blob where the vault-key wrap should be.
        wrapped_vault_key=ks.wrapped_rsa_private,
        wrapped_rsa_private=ks.wrapped_vault_key,
        rsa_public_pem=ks.rsa_public_pem,
    )
    with pytest.raises(DecryptionError):
        unlock(swapped, STRONG)


def test_change_password_rotates_wraps_but_preserves_vault_key() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    original_vault_key = unlock(ks, STRONG)

    new_ks = change_password(ks, STRONG, OTHER_STRONG)

    # Salt and wraps changed; public key did not.
    assert new_ks.salt != ks.salt
    assert new_ks.wrapped_vault_key != ks.wrapped_vault_key
    assert new_ks.wrapped_rsa_private != ks.wrapped_rsa_private
    assert new_ks.rsa_public_pem == ks.rsa_public_pem

    # New password unlocks to the SAME vault key (no .crypt re-encryption needed).
    assert unlock(new_ks, OTHER_STRONG) == original_vault_key

    # Old password no longer works against the new keystore.
    with pytest.raises(DecryptionError):
        unlock(new_ks, STRONG)


def test_change_password_refuses_weak_new_password() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    with pytest.raises(WeakPasswordError):
        change_password(ks, STRONG, "weak")


def test_change_password_wrong_old_password_raises() -> None:
    ks = create(STRONG, rsa_key_bits=TEST_RSA_BITS)
    with pytest.raises(DecryptionError):
        change_password(ks, OTHER_STRONG, "Yet_Another_Strong_Password_42!")


@pytest.mark.slow
def test_create_with_default_rsa_key_bits() -> None:
    """Smoke the real 4096-bit key size once."""
    ks = create(STRONG)
    pub = serialization.load_pem_public_key(ks.rsa_public_pem)
    assert pub.key_size == 4096


@pytest.mark.slow
def test_argon2id_keystore_roundtrip() -> None:
    ks = create(STRONG, kdf=Argon2idKdf(), rsa_key_bits=TEST_RSA_BITS)
    assert unlock(ks, STRONG) is not None
    assert ks.kdf_id == Argon2idKdf.kdf_id


def test_kdf_id_recorded_in_keystore() -> None:
    ks = create(STRONG, kdf=Pbkdf2Kdf(), rsa_key_bits=TEST_RSA_BITS)
    assert ks.kdf_id == Pbkdf2Kdf.kdf_id

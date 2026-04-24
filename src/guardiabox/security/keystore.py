"""Per-user key storage.

A keystore is the persisted shape of one user's secret material:

* ``salt`` + ``kdf_id`` + ``kdf_params`` — public KDF inputs that let
  us re-derive the master key from the user's password.
* ``wrapped_vault_key`` — AES-256 vault key, AES-GCM-wrapped under
  the master key. The vault key is what the repository layer uses to
  encrypt/decrypt metadata columns (``filename``, ``audit_log.target``,
  ...).
* ``wrapped_rsa_private`` — 4096-bit RSA-OAEP private key serialised
  in DER, AES-GCM-wrapped under the master key. Used by spec 003
  (rsa-share) to unwrap the per-share DEK.
* ``rsa_public_pem`` — matching RSA public key in PEM form; public by
  design so other users can wrap DEKs for this user.

Three operations:

1. :func:`create` — fresh keystore from a strong password.
2. :func:`unlock` — derive the master key from the password, unwrap
   the vault key; raises :class:`DecryptionError` on wrong password
   (GCM tag mismatch).
3. :func:`change_password` — re-wrap the vault key and RSA private
   under a fresh salt + master-key derivation. No .crypt file is
   re-encrypted; only the user's keystore rotates.

Design note: wrapped material is stored as ``nonce (12) || ciphertext
|| tag (16)``. The AAD for each wrap is the constant bytestring
``b"vault_key"`` or ``b"rsa_private"`` so a swapped ciphertext between
the two fields fails authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardiabox.core.constants import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    AES_KEY_BYTES,
    SALT_BYTES,
)
from guardiabox.core.exceptions import DecryptionError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.security.password import assert_strong

__all__ = [
    "DEFAULT_RSA_KEY_BITS",
    "Keystore",
    "change_password",
    "create",
    "unlock",
]

#: RSA key size used by :func:`create`. 4096 bits matches
#: ``docs/CRYPTO_DECISIONS.md`` section 3 and ADR-0004.
DEFAULT_RSA_KEY_BITS: Final[int] = 4096

#: AAD context tag for the vault key wrap.
_VAULT_KEY_AAD: Final[bytes] = b"guardiabox/keystore/vault_key/v1"

#: AAD context tag for the RSA private key wrap.
_RSA_PRIVATE_AAD: Final[bytes] = b"guardiabox/keystore/rsa_private/v1"


@dataclass(frozen=True, slots=True)
class Keystore:
    """In-memory view of a persisted keystore row."""

    salt: bytes
    kdf_id: int
    kdf_params: bytes
    wrapped_vault_key: bytes
    wrapped_rsa_private: bytes
    rsa_public_pem: bytes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create(
    password: str,
    *,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
    rsa_key_bits: int = DEFAULT_RSA_KEY_BITS,
) -> Keystore:
    """Build a brand-new keystore from ``password``.

    Args:
        password: The user's master password. Validated against
            :func:`guardiabox.security.password.assert_strong` (>= 12
            chars, zxcvbn score >= 3, <= 1024 chars).
        kdf: KDF implementation. Defaults to :class:`Pbkdf2Kdf` at the
            OWASP 2026 floor (600 000 iterations). Argon2id is opt-in.
        rsa_key_bits: RSA key size in bits. Default 4096.

    Returns:
        A :class:`Keystore` with fresh salt, KDF params, RSA keypair,
        vault key, and matching wraps.
    """
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else Pbkdf2Kdf()

    salt = secrets.token_bytes(SALT_BYTES)
    master_key = _derive_master_key(password, salt, kdf_impl)

    vault_key = secrets.token_bytes(AES_KEY_BYTES)
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=rsa_key_bits)
    rsa_private_der = rsa_private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rsa_public_pem = rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    try:
        wrapped_vault_key = _wrap(master_key, vault_key, aad=_VAULT_KEY_AAD)
        wrapped_rsa_private = _wrap(master_key, rsa_private_der, aad=_RSA_PRIVATE_AAD)
    finally:
        _zero(master_key)

    return Keystore(
        salt=salt,
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
        wrapped_vault_key=wrapped_vault_key,
        wrapped_rsa_private=wrapped_rsa_private,
        rsa_public_pem=rsa_public_pem,
    )


def unlock(keystore: Keystore, password: str) -> bytes:
    """Re-derive the master key from ``password`` and return the vault key.

    Raises:
        DecryptionError: If the password is wrong (GCM tag mismatch on
            the vault-key wrap). Indistinguishable from a tampered
            keystore to match the anti-oracle contract.
    """
    kdf_impl = kdf_for_id(keystore.kdf_id, keystore.kdf_params)
    master_key = _derive_master_key(password, keystore.salt, kdf_impl)
    try:
        return _unwrap(master_key, keystore.wrapped_vault_key, aad=_VAULT_KEY_AAD)
    finally:
        _zero(master_key)


def change_password(
    keystore: Keystore,
    old_password: str,
    new_password: str,
    *,
    new_kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
) -> Keystore:
    """Rotate the password without re-encrypting any ``.crypt`` file.

    The vault key and the RSA private are unwrapped under the old
    master key and re-wrapped under a fresh master key derived from
    ``new_password`` + a new random salt. The public key stays the
    same; downstream files keep decrypting.

    Args:
        keystore: Current keystore row.
        old_password: Must unlock ``keystore`` (else :class:`DecryptionError`).
        new_password: New password; validated against the strength policy.
        new_kdf: Optional override for the fresh KDF (same default as
            :func:`create`).

    Returns:
        A new :class:`Keystore` — caller is responsible for persisting
        it, typically in the same DB row as the previous one.
    """
    assert_strong(new_password)

    # Unlock via the old credentials.
    old_kdf = kdf_for_id(keystore.kdf_id, keystore.kdf_params)
    old_master_key = _derive_master_key(old_password, keystore.salt, old_kdf)
    try:
        vault_key = _unwrap(old_master_key, keystore.wrapped_vault_key, aad=_VAULT_KEY_AAD)
        rsa_private_der = _unwrap(
            old_master_key, keystore.wrapped_rsa_private, aad=_RSA_PRIVATE_AAD
        )
    finally:
        _zero(old_master_key)

    # Fresh salt + KDF for the new wrap.
    new_salt = secrets.token_bytes(SALT_BYTES)
    new_kdf_impl: Pbkdf2Kdf | Argon2idKdf = new_kdf if new_kdf is not None else Pbkdf2Kdf()
    new_master_key = _derive_master_key(new_password, new_salt, new_kdf_impl)
    try:
        wrapped_vault_key = _wrap(new_master_key, vault_key, aad=_VAULT_KEY_AAD)
        wrapped_rsa_private = _wrap(new_master_key, rsa_private_der, aad=_RSA_PRIVATE_AAD)
    finally:
        _zero(new_master_key)

    return Keystore(
        salt=new_salt,
        kdf_id=new_kdf_impl.kdf_id,
        kdf_params=new_kdf_impl.encode_params(),
        wrapped_vault_key=wrapped_vault_key,
        wrapped_rsa_private=wrapped_rsa_private,
        rsa_public_pem=keystore.rsa_public_pem,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _derive_master_key(
    password: str,
    salt: bytes,
    kdf: Pbkdf2Kdf | Argon2idKdf,
) -> bytearray:
    """NFC-normalised UTF-8 password, then KDF-derive, return a mutable buffer."""
    import unicodedata

    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    derived = kdf.derive(password_bytes, salt, AES_KEY_BYTES)
    # bytearray so _zero can actually wipe the buffer (bytes is immutable).
    # The ``bytes`` copy returned by kdf.derive stays alive until GC; the
    # honest scope of this mitigation is documented in THREAT_MODEL.md
    # section 4.5.
    return bytearray(derived)


def _wrap(key_buf: bytearray, plaintext: bytes, *, aad: bytes) -> bytes:
    """Return ``nonce || ciphertext || tag``, AAD-bound to ``aad``."""
    if len(key_buf) != AES_KEY_BYTES:
        raise ValueError(f"master key must be {AES_KEY_BYTES} bytes, got {len(key_buf)}")
    nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    ct = AESGCM(bytes(key_buf)).encrypt(nonce, plaintext, aad)
    return nonce + ct


def _unwrap(key_buf: bytearray, blob: bytes, *, aad: bytes) -> bytes:
    if len(key_buf) != AES_KEY_BYTES:
        raise ValueError(f"master key must be {AES_KEY_BYTES} bytes, got {len(key_buf)}")
    if len(blob) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
        raise DecryptionError("wrapped blob shorter than nonce + tag")
    nonce = blob[:AES_GCM_NONCE_BYTES]
    ct = blob[AES_GCM_NONCE_BYTES:]
    try:
        return AESGCM(bytes(key_buf)).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError("keystore AES-GCM authentication failed") from exc


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0

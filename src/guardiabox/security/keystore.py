"""Per-user key storage.

Each user's keystore holds:

* The salt used to derive their *master key* from their password.
* The user's RSA-OAEP key-pair (private key wrapped under the master key).
* The user's *vault key* (random AES-256, wrapped under the master key) — used
  to encrypt per-file metadata in the SQLCipher database.

The on-disk representation lives in :mod:`guardiabox.persistence`, which
imports :class:`Keystore` here. UI code interacts only via this module.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Keystore:
    """In-memory view of a user's keystore."""

    salt: bytes
    wrapped_vault_key: bytes
    wrapped_rsa_private_key: bytes
    rsa_public_key_pem: bytes


def create(password: str) -> Keystore:
    """Generate a brand-new keystore for ``password``."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")


def unlock(keystore: Keystore, password: str) -> bytes:
    """Return the *vault key* if ``password`` correctly unlocks the keystore."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

"""Structural protocols for pluggable algorithms.

Defining algorithms as :class:`typing.Protocol` decouples
:mod:`guardiabox.core` from any concrete implementation, satisfies the
Dependency Inversion principle, and lets us register new KDFs / ciphers /
asymmetric primitives without touching the call sites.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class KeyDerivation(Protocol):
    """Derive a symmetric key from a password and a salt."""

    kdf_id: int
    """Unique identifier persisted in the container header."""

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        """Return ``length`` bytes derived from ``password`` and ``salt``."""

    def encode_params(self) -> bytes:
        """Serialise algorithm parameters for storage in the container."""

    @classmethod
    def decode_params(cls, blob: bytes) -> KeyDerivation:
        """Reconstruct a :class:`KeyDerivation` from its serialised parameters."""


@runtime_checkable
class AeadCipher(Protocol):
    """Authenticated-encryption-with-associated-data primitive."""

    nonce_bytes: int
    tag_bytes: int

    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Return ciphertext concatenated with the authentication tag."""

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Return the plaintext if the tag verifies, else raise."""

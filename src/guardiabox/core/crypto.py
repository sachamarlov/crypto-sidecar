"""AES-GCM authenticated encryption primitive.

Thin wrapper around :class:`cryptography.hazmat.primitives.ciphers.aead.AESGCM`
implementing :class:`guardiabox.core.protocols.AeadCipher`.

Implementation deliberately deferred — see
``docs/specs/001-encrypt-file/plan.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class AesGcmCipher:
    """AES-256-GCM with 12-byte nonces (NIST SP 800-38D recommended)."""

    nonce_bytes: ClassVar[int] = 12
    tag_bytes: ClassVar[int] = 16

    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

r"""Structural protocols for pluggable algorithms.

Defining algorithms as :class:`typing.Protocol` decouples
:mod:`guardiabox.core` from any concrete implementation, satisfies the
Dependency Inversion principle, and lets us register new KDFs / ciphers /
asymmetric primitives without touching the call sites.

Note: factory operations (``decode_params``) are **not** part of the protocols.
They live as :class:`classmethod`\s on each concrete implementation so that the
return type can be :class:`typing.Self`, which is impossible to express
through a Protocol's structural subtyping without ``Self`` covariance issues.
"""

from __future__ import annotations

from typing import ClassVar, Protocol


class KeyDerivation(Protocol):
    """Derive a symmetric key from a password and a salt."""

    kdf_id: ClassVar[int]
    """Unique identifier persisted in the container header."""

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        """Return ``length`` bytes derived from ``password`` and ``salt``."""
        ...

    def encode_params(self) -> bytes:
        """Serialise algorithm parameters for storage in the container."""
        ...


class AeadCipher(Protocol):
    """Authenticated-encryption-with-associated-data primitive.

    Implementations are **key-bound**: the concrete class takes the key
    at construction time (typically ``__init__(self, key: bytes)``) and
    reuses the underlying cipher context for every call. The key is not
    part of the public protocol surface — callers zero-fill their own
    buffer and drop the cipher reference when done.
    """

    nonce_bytes: ClassVar[int]
    tag_bytes: ClassVar[int]

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Return ciphertext concatenated with the authentication tag."""
        ...

    def decrypt(
        self,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Return the plaintext if the tag verifies, else raise."""
        ...

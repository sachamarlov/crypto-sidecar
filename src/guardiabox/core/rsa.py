"""RSA-OAEP wrap and RSA-PSS sign primitives for spec 003 (rsa-share).

This module exposes the asymmetric building blocks that the share-token
flow relies on:

* :class:`RsaWrap` — RSA-OAEP-SHA256 wrap / unwrap of a small payload
  (32-byte data-encryption key in the share-token use case). The wrap is
  the raw RSA-OAEP ciphertext, ``key_size_bytes`` long, suitable for
  framing inside the ``.gbox-share`` v1 layout (T-003.03).
* :class:`RsaSign` — RSA-PSS-SHA256 detached signatures over an arbitrary
  payload. Used to authenticate every byte of a share token before any
  unwrap or decrypt happens (anti-oracle: failure mode is uniform
  :class:`IntegrityError`).
* :func:`load_public_key_pem` / :func:`load_private_key_der` —
  serialisation helpers matching the on-disk layout produced by
  :mod:`guardiabox.security.keystore`.

Both classes are intentionally stateless: callers pass the key explicitly
on every call. The keystore (Phase C) already manages key material with
zero-fill discipline; layering another stateful wrapper here would
duplicate that responsibility.

Exception policy
----------------
Every failure mode (wrong recipient key on unwrap, tampered ciphertext,
tampered signature) collapses to :class:`IntegrityError`. The hazmat
exceptions :class:`cryptography.exceptions.InvalidSignature` and the
``ValueError`` raised by ``RSAPrivateKey.decrypt`` on padding mismatch
are caught and rewrapped, so callers never have to import
``cryptography.exceptions`` and the share-accept flow can route both
failure paths through a single domain-level branch (cf. ADR-0015 anti-
oracle discipline applied here too: signature failure and padding
mismatch are indistinguishable to the caller).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from guardiabox.core.exceptions import IntegrityError

__all__ = [
    "RsaSign",
    "RsaWrap",
    "load_private_key_der",
    "load_public_key_pem",
]


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def load_public_key_pem(pem: bytes) -> rsa.RSAPublicKey:
    """Deserialise a PEM-encoded SubjectPublicKeyInfo RSA public key.

    The keystore (Phase C) persists every user's public key in this exact
    encoding (see :func:`guardiabox.security.keystore.create`).

    Args:
        pem: The PEM-encoded blob, as produced by
            ``RSAPublicKey.public_bytes(PEM, SubjectPublicKeyInfo)``.

    Returns:
        The deserialised :class:`rsa.RSAPublicKey`.

    Raises:
        ValueError: If the blob is malformed or carries a non-RSA key
            (e.g. an EC public key).
    """
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError(f"expected RSA public key, got {type(key).__name__}")
    return key


def load_private_key_der(der: bytes) -> rsa.RSAPrivateKey:
    """Deserialise a DER-encoded PKCS#8 RSA private key.

    The keystore stores the unwrapped private key in this encoding —
    the ``rsa_private_der`` blob obtained after
    :func:`guardiabox.security.keystore.unlock` derives the master key
    and AES-GCM-unwraps the keystore row.

    Args:
        der: The PKCS#8 DER blob.

    Returns:
        The deserialised :class:`rsa.RSAPrivateKey`.

    Raises:
        ValueError: If the blob is malformed, password-protected (we do
            not pass a password), or carries a non-RSA key.
    """
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError(f"expected RSA private key, got {type(key).__name__}")
    return key


# ---------------------------------------------------------------------------
# RSA-OAEP wrap / unwrap (T-003.01)
# ---------------------------------------------------------------------------


def _oaep_padding() -> padding.OAEP:
    """Single source of truth for the OAEP parameters used project-wide.

    SHA-256 for both the hash inside OAEP and the MGF1 mask generation,
    no label. Aligns with ADR-0004 and OWASP 2026 guidance for hybrid
    cryptosystems.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RsaWrap:
    """RSA-OAEP-SHA256 wrap / unwrap of a small payload.

    The wrap output is the raw RSA-OAEP ciphertext (``modulus_bytes``
    long, e.g. 512 bytes for a 4096-bit key, 256 for a 2048-bit key).
    The wrap is **non-deterministic**: OAEP draws its seed from the OS
    CSPRNG, so wrapping the same DEK twice produces two distinct
    ciphertexts. Tests therefore validate behaviour via round-trip and
    tampering rather than against a static KAT vector.

    The class is stateless on purpose: callers always pass the RSA key
    explicitly. The keystore module owns key lifecycle (zero-fill on
    drop); this primitive does not.
    """

    @staticmethod
    def wrap(payload: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt ``payload`` under ``public_key``.

        Args:
            payload: The plaintext to wrap. For the share-token flow
                this is a 32-byte AES-256 DEK (cf. T-003.04). The
                maximum length is bounded by the RSA key size:
                ``modulus_bytes - 2 * hash_bytes - 2`` per RFC 8017
                §7.1.1 (e.g. 190 bytes for a 2048-bit key + SHA-256).

            public_key: The recipient's RSA public key, typically loaded
                via :func:`load_public_key_pem`.

        Returns:
            The raw RSA-OAEP ciphertext (``modulus_bytes`` long).

        Raises:
            ValueError: If ``payload`` exceeds the OAEP-imposed maximum
                size for the given key (re-raised from pyca).
        """
        return public_key.encrypt(payload, _oaep_padding())

    @staticmethod
    def unwrap(wrapped: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt ``wrapped`` under ``private_key``.

        Args:
            wrapped: A ciphertext previously produced by :meth:`wrap`
                under the matching public key, or a tampered blob.

            private_key: The recipient's RSA private key, typically
                obtained from
                :func:`guardiabox.security.keystore.unlock_rsa_private`
                (after the user authenticates).

        Returns:
            The original plaintext payload.

        Raises:
            IntegrityError: If the wrap was produced under a different
                public key, or the ciphertext was tampered with, or the
                length does not match ``modulus_bytes``. The three cases
                are intentionally indistinguishable so a malicious
                ciphertext cannot be used as an oracle.
        """
        try:
            return private_key.decrypt(wrapped, _oaep_padding())
        except ValueError as exc:
            # pyca raises ValueError on padding mismatch (wrong key,
            # tampered ciphertext) and on length mismatch. Both are
            # treated as integrity failures by the share-accept flow.
            raise IntegrityError("RSA-OAEP unwrap failed") from exc


# ---------------------------------------------------------------------------
# RSA-PSS sign / verify (T-003.02)
# ---------------------------------------------------------------------------


def _pss_padding() -> padding.PSS:
    """Single source of truth for the PSS parameters.

    MGF1-SHA256 with the maximum salt length permitted by the key
    (RFC 8017 §9.1.1 + §A.2.3). Maximum salt length improves security
    over fixed lengths because the resulting signatures are
    indistinguishable from random under EUF-CMA without the deterministic
    failure modes of small-salt PSS variants.
    """
    return padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


class RsaSign:
    """RSA-PSS-SHA256 detached signatures.

    Like :class:`RsaWrap`, the API is stateless. Signatures are
    non-deterministic (random salt drawn per call), which is the
    standard PSS behaviour and matches the security analysis in RFC
    8017 §B.2.

    Verification failures are uniform: any altered byte in the payload
    or the signature surfaces as :class:`IntegrityError`. The share-
    accept flow runs verification *first*, before any unwrap or decrypt,
    so a tampered token is rejected in constant-ish time without
    revealing where the tampering occurred.
    """

    @staticmethod
    def sign(payload: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Return a detached signature over ``payload``.

        Args:
            payload: The exact bytes to sign. The caller is responsible
                for canonicalisation: PSS does not normalise input.

            private_key: The signer's RSA private key.

        Returns:
            The signature blob, ``modulus_bytes`` long.
        """
        return private_key.sign(payload, _pss_padding(), hashes.SHA256())

    @staticmethod
    def verify(
        signature: bytes,
        payload: bytes,
        public_key: rsa.RSAPublicKey,
    ) -> None:
        """Verify ``signature`` over ``payload`` under ``public_key``.

        Args:
            signature: The blob returned by a previous :meth:`sign`.
            payload: The message bytes the signature is supposed to
                authenticate.
            public_key: The signer's RSA public key.

        Raises:
            IntegrityError: If the signature does not verify (wrong key,
                altered payload, altered signature, or wrong length).
                The cases are intentionally indistinguishable.
        """
        try:
            public_key.verify(signature, payload, _pss_padding(), hashes.SHA256())
        except InvalidSignature as exc:
            raise IntegrityError("RSA-PSS verification failed") from exc

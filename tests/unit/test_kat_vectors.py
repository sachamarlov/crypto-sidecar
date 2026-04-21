"""Known-Answer Tests from authoritative public sources.

Two layers of KAT coverage sit here:

1. **Primitive-level KATs.** We feed published input vectors directly into
   the underlying library primitives (``cryptography.hazmat``'s ``AESGCM``
   and ``PBKDF2HMAC``, ``argon2.low_level.hash_secret_raw``) and verify the
   output byte-for-byte against the values in the reference document. This
   layer guards against a regression in the library itself — it is redundant
   with the upstream test suite but makes the test explicit in our repo,
   which is what the 001 plan asked for.

2. **Wrapper-level gold vectors.** We run our own ``Pbkdf2Kdf`` /
   ``Argon2idKdf`` wrappers at the production floor parameters (600 000
   PBKDF2 iterations ; Argon2id m=64 MiB, t=3, p=1) against hex values
   precomputed offline with this very codebase. If a refactor silently
   changes the derived key for a fixed input, these tests scream.

Sources are cited inline in each test's docstring.
"""

from __future__ import annotations

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pytest

from guardiabox.core.crypto import AesGcmCipher
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf

# ---------------------------------------------------------------------------
# AES-256-GCM — NIST SP 800-38D Appendix B
# (originally published in McGrew & Viega "The GCM Mode of Operation",
#  <https://siswg.net/docs/gcm_spec.pdf>, §A.1 test cases 13-15)
# ---------------------------------------------------------------------------


def test_aes_gcm_kat_case_13_zero_plaintext() -> None:
    """NIST / McGrew-Viega Test Case 13 — zero key, zero IV, empty plaintext.

    Expected authentication tag: ``530f8afbc74536b9a963b4f1c4cb738b``.
    """
    key = bytes(32)
    nonce = bytes(12)
    aad: bytes | None = None

    # Wrapper must produce the same ciphertext+tag as the primitive does.
    ct_wrapper = AesGcmCipher().encrypt(key, nonce, b"", aad)
    ct_primitive = AESGCM(key).encrypt(nonce, b"", aad)
    assert ct_wrapper == ct_primitive

    # The tag matches the published KAT (ciphertext is empty for empty P).
    expected_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")
    assert ct_wrapper == expected_tag


def test_aes_gcm_kat_case_14_zero_block_plaintext() -> None:
    """Test Case 14 — zero key, zero IV, one block of zero plaintext.

    Expected ciphertext||tag:
    ``cea7403d4d606b6e074ec5d3baf39d18`` ``d0d1c8a799996bf0265b98b5d48ab919``.
    """
    key = bytes(32)
    nonce = bytes(12)
    plaintext = bytes(16)

    ct = AesGcmCipher().encrypt(key, nonce, plaintext)
    expected = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
    assert ct == expected
    # And we can decrypt back.
    assert AesGcmCipher().decrypt(key, nonce, ct) == plaintext


def test_aes_gcm_kat_case_15_with_iv_and_plaintext() -> None:
    """Test Case 15 — non-trivial key, IV, and plaintext (no AAD)."""
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255"
    )
    expected = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad"
        "b094dac5d93471bdec1a502270e3cc6c"
    )
    assert AesGcmCipher().encrypt(key, nonce, plaintext) == expected


# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SHA1 — RFC 6070
# <https://www.rfc-editor.org/rfc/rfc6070>
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("password", "salt", "iterations", "dk_len", "expected_hex"),
    [
        # RFC 6070 Test Vector 1.
        (b"password", b"salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        # RFC 6070 Test Vector 2.
        (b"password", b"salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        # RFC 6070 Test Vector 3.
        (b"password", b"salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
    ],
)
def test_pbkdf2_hmac_sha1_kat_rfc_6070(
    password: bytes, salt: bytes, iterations: int, dk_len: int, expected_hex: str
) -> None:
    """RFC 6070 PBKDF2-HMAC-SHA-1 test vectors.

    Exercised against the primitive directly since our :class:`Pbkdf2Kdf`
    wraps SHA-256 only and enforces a 600 000 iteration floor. The point of
    this test is to pin pyca/cryptography's PBKDF2 implementation.
    """
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA1(),  # noqa: S303 — RFC 6070 uses SHA-1 by spec
        length=dk_len,
        salt=salt,
        iterations=iterations,
    ).derive(password)
    assert derived.hex() == expected_hex


# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SHA256 — draft-josefsson-pbkdf2-test-vectors-06
# <https://tools.ietf.org/id/draft-josefsson-pbkdf2-test-vectors-06.html>
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("password", "salt", "iterations", "dk_len", "expected_hex"),
    [
        # Test Vector 1.
        (
            b"password",
            b"salt",
            1,
            32,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        ),
        # Test Vector 2.
        (
            b"password",
            b"salt",
            2,
            32,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        ),
        # Test Vector 3.
        (
            b"password",
            b"salt",
            4096,
            32,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        ),
    ],
)
def test_pbkdf2_hmac_sha256_kat_draft_josefsson(
    password: bytes, salt: bytes, iterations: int, dk_len: int, expected_hex: str
) -> None:
    """draft-josefsson-pbkdf2-test-vectors PBKDF2-HMAC-SHA-256 vectors.

    Exercised against the primitive directly: these iteration counts are far
    below our 600 000 floor, so the wrapper would refuse them.
    """
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=dk_len,
        salt=salt,
        iterations=iterations,
    ).derive(password)
    assert derived.hex() == expected_hex


# ---------------------------------------------------------------------------
# Argon2id — RFC 9106 v1.3 via argon2-cffi
# Reproducible with:
#   python -c "from argon2.low_level import hash_secret_raw, Type; \
#              print(hash_secret_raw(b'password', b'somesalt', 2, 65536, 1, 32, Type.ID).hex())"
# Inputs (password, salt, parallelism, hash_len) are taken from the
# phc-winner-argon2 test.c corpus; the tag below is the RFC 9106 v1.3 output
# of the argon2-cffi primitive at these parameters.
# ---------------------------------------------------------------------------


def test_argon2id_kat_primitive_default_params() -> None:
    """Pin argon2-cffi's Argon2id output for canonical parameters.

    ``t=2, m=65 536, p=1`` falls below our wrapper's ``t≥3`` floor, so we
    drive the primitive directly. The hex below was generated from this
    repo's pinned ``argon2-cffi`` version — if argon2-cffi ships a new
    implementation or our pin slides across an RFC 9106 revision, the test
    fails and forces a conscious review.
    """
    tag = hash_secret_raw(
        secret=b"password",
        salt=b"somesalt",
        time_cost=2,
        memory_cost=65_536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    assert tag.hex() == (
        "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
    )  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Wrapper gold vectors — lock the default-floor output of our classes
# ---------------------------------------------------------------------------

# These values were produced once locally by running the wrappers under the
# exact code in this repository and pasted here. Any subsequent drift means
# either a library upgrade changed semantics or we introduced a regression.


def test_pbkdf2_kdf_gold_vector_default_floor() -> None:
    """Lock the output of ``Pbkdf2Kdf()`` at the 600 000 iteration floor."""
    salt = b"NaCl" + b"\x00" * 12  # 16 bytes
    derived = Pbkdf2Kdf().derive(b"password", salt, 32)
    assert derived.hex() == (
        "83543409950223c4d5542cbdeaeaad8b4514dc3e61a2c97a8d75c6030e0f230f"
    )  # pragma: allowlist secret


def test_argon2id_kdf_gold_vector_default_floor() -> None:
    """Lock the output of ``Argon2idKdf()`` at m=64 MiB, t=3, p=1."""
    salt = b"somesalt" * 2  # 16 bytes
    derived = Argon2idKdf().derive(b"password", salt, 32)
    assert derived.hex() == (
        "7664ad4ba1a3c999fcdd0991ffc2270f78302d2383233db5e7befc85d1bb1819"
    )  # pragma: allowlist secret

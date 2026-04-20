"""Property-based crypto roundtrip skeleton.

The real test exercises every implementation of
:class:`guardiabox.core.protocols.AeadCipher` and
:class:`guardiabox.core.protocols.KeyDerivation` and asserts:

    decrypt(encrypt(plaintext, password), password) == plaintext

for arbitrary plaintexts (length 0, 1, 1 chunk-1, 1 chunk, 1 chunk+1, large)
and arbitrary policy-conformant passwords.

Currently skipped because the implementations are deferred to
``docs/specs/001-encrypt-file/plan.md``.
"""

from __future__ import annotations

import pytest


@pytest.mark.property
@pytest.mark.skip(reason="Awaiting implementation in spec 001-encrypt-file.")
def test_aes_gcm_pbkdf2_roundtrip() -> None:
    """Round-trip across PBKDF2-derived keys."""


@pytest.mark.property
@pytest.mark.skip(reason="Awaiting implementation in spec 001-encrypt-file.")
def test_aes_gcm_argon2id_roundtrip() -> None:
    """Round-trip across Argon2id-derived keys."""

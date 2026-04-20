"""Secure deletion of plaintext files.

Two strategies are exposed:

* **Multi-pass overwrite** (``DoD 5220.22-M``-style 3-pass) — meaningful only
  for spinning disks. Documented as best-effort on SSDs given wear-levelling.
* **Cryptographic erase** — the canonical answer for SSDs per NIST SP 800-88r2:
  destroy the encryption key rather than try to overwrite the ciphertext blocks.

Implementation deliberately deferred — see
``docs/specs/004-secure-delete/plan.md``.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path


class SecureDeleteMethod(StrEnum):
    """Strategy used by :func:`secure_delete`."""

    OVERWRITE_DOD_3PASS = "overwrite-dod-3pass"
    CRYPTO_ERASE = "crypto-erase"


def secure_delete(
    path: Path,
    method: SecureDeleteMethod = SecureDeleteMethod.CRYPTO_ERASE,
) -> None:
    """Securely delete the file at ``path`` using ``method``."""
    raise NotImplementedError("See docs/specs/004-secure-delete/plan.md")

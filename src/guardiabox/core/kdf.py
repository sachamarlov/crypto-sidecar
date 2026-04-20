"""Key Derivation Functions.

Two implementations satisfy :class:`guardiabox.core.protocols.KeyDerivation`:

* :class:`Pbkdf2Kdf` — PBKDF2-HMAC-SHA256, default per the academic brief and
  FIPS-140 compliant.
* :class:`Argon2idKdf` — Argon2id, recommended by OWASP 2026 for new systems.

Implementation deliberately deferred — see
``docs/specs/001-encrypt-file/plan.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Self


@dataclass(frozen=True, slots=True)
class Pbkdf2Kdf:
    """PBKDF2-HMAC-SHA256 with configurable iteration count.

    Defaults match OWASP 2026 (≥ 600 000 iterations for FIPS-140 compliance).
    """

    iterations: int = 600_000

    kdf_id: ClassVar[int] = 0x01

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

    def encode_params(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def decode_params(cls, blob: bytes) -> Self:  # noqa: ARG003 — stub
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class Argon2idKdf:
    """Argon2id with parameters per OWASP 2026 (m=64 MiB, t=3, p=1)."""

    memory_cost_kib: int = 65_536
    time_cost: int = 3
    parallelism: int = 1

    kdf_id: ClassVar[int] = 0x02

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

    def encode_params(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def decode_params(cls, blob: bytes) -> Self:  # noqa: ARG003 — stub
        raise NotImplementedError

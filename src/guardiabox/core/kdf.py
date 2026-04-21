"""Key Derivation Functions.

Two implementations satisfy :class:`guardiabox.core.protocols.KeyDerivation`:

* :class:`Pbkdf2Kdf` — PBKDF2-HMAC-SHA256, default per the academic brief and
  FIPS-140 compliant.
* :class:`Argon2idKdf` — Argon2id, recommended by OWASP 2026 for new systems.

Parameter floors from ``docs/CRYPTO_DECISIONS.md`` are enforced both when a KDF
is constructed and when decoding parameters read from a ``.crypt`` header, so a
container crafted with weaker parameters is rejected before a key is derived.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import ClassVar, Self

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from guardiabox.core.constants import (
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    KDF_ID_ARGON2ID,
    KDF_ID_PBKDF2_SHA256,
    PBKDF2_MIN_ITERATIONS,
    SALT_BYTES,
)
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    WeakKdfParametersError,
)

__all__ = [
    "Argon2idKdf",
    "Pbkdf2Kdf",
    "kdf_for_id",
]

_PBKDF2_PARAMS_STRUCT = struct.Struct("!I")  # iterations (4 bytes)
_ARGON2_PARAMS_STRUCT = struct.Struct("!III")  # memory_kib | time_cost | parallelism


def _validate_length(length: int) -> None:
    if length <= 0:
        raise ValueError(f"derived key length must be positive, got {length}")


def _validate_salt(salt: bytes) -> None:
    if len(salt) < SALT_BYTES:
        raise WeakKdfParametersError(f"salt must be at least {SALT_BYTES} bytes, got {len(salt)}")


@dataclass(frozen=True, slots=True)
class Pbkdf2Kdf:
    """PBKDF2-HMAC-SHA256 with configurable iteration count.

    The default matches OWASP 2026 Password Storage CS for FIPS-140 compliance.
    Fewer iterations are refused at construction time.
    """

    iterations: int = PBKDF2_MIN_ITERATIONS

    kdf_id: ClassVar[int] = KDF_ID_PBKDF2_SHA256

    def __post_init__(self) -> None:
        if self.iterations < PBKDF2_MIN_ITERATIONS:
            raise WeakKdfParametersError(
                f"PBKDF2 iterations {self.iterations} below floor {PBKDF2_MIN_ITERATIONS}"
            )

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        """Derive ``length`` bytes from ``password`` and ``salt``."""
        _validate_length(length)
        _validate_salt(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password)

    def encode_params(self) -> bytes:
        """Pack iteration count as 4 bytes big-endian."""
        return _PBKDF2_PARAMS_STRUCT.pack(self.iterations)

    @classmethod
    def decode_params(cls, blob: bytes) -> Self:
        """Parse and validate parameters read from a ``.crypt`` header."""
        if len(blob) != _PBKDF2_PARAMS_STRUCT.size:
            raise CorruptedContainerError(
                f"PBKDF2 params must be {_PBKDF2_PARAMS_STRUCT.size} bytes, got {len(blob)}"
            )
        (iterations,) = _PBKDF2_PARAMS_STRUCT.unpack(blob)
        return cls(iterations=iterations)


@dataclass(frozen=True, slots=True)
class Argon2idKdf:
    """Argon2id with parameters per OWASP 2026 (m=64 MiB, t=3, p=1)."""

    memory_cost_kib: int = ARGON2_MIN_MEMORY_KIB
    time_cost: int = ARGON2_MIN_TIME_COST
    parallelism: int = ARGON2_MIN_PARALLELISM

    kdf_id: ClassVar[int] = KDF_ID_ARGON2ID

    def __post_init__(self) -> None:
        violations: list[str] = []
        if self.memory_cost_kib < ARGON2_MIN_MEMORY_KIB:
            violations.append(f"memory_cost_kib {self.memory_cost_kib} < {ARGON2_MIN_MEMORY_KIB}")
        if self.time_cost < ARGON2_MIN_TIME_COST:
            violations.append(f"time_cost {self.time_cost} < {ARGON2_MIN_TIME_COST}")
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            violations.append(f"parallelism {self.parallelism} < {ARGON2_MIN_PARALLELISM}")
        if violations:
            raise WeakKdfParametersError(
                "Argon2id parameters below OWASP 2026 floor: " + "; ".join(violations)
            )

    def derive(self, password: bytes, salt: bytes, length: int) -> bytes:
        """Derive ``length`` bytes from ``password`` and ``salt``."""
        _validate_length(length)
        _validate_salt(salt)
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost_kib,
            parallelism=self.parallelism,
            hash_len=length,
            type=Type.ID,
        )

    def encode_params(self) -> bytes:
        """Pack (memory, time, parallelism) as three 4-byte big-endian ints."""
        return _ARGON2_PARAMS_STRUCT.pack(self.memory_cost_kib, self.time_cost, self.parallelism)

    @classmethod
    def decode_params(cls, blob: bytes) -> Self:
        """Parse and validate parameters read from a ``.crypt`` header."""
        if len(blob) != _ARGON2_PARAMS_STRUCT.size:
            raise CorruptedContainerError(
                f"Argon2id params must be {_ARGON2_PARAMS_STRUCT.size} bytes, got {len(blob)}"
            )
        memory_kib, time_cost, parallelism = _ARGON2_PARAMS_STRUCT.unpack(blob)
        return cls(
            memory_cost_kib=memory_kib,
            time_cost=time_cost,
            parallelism=parallelism,
        )


def kdf_for_id(kdf_id: int, params: bytes) -> Pbkdf2Kdf | Argon2idKdf:
    """Return the concrete KDF instance matching ``kdf_id`` with ``params``.

    Raises:
        UnknownKdfError: If ``kdf_id`` is not implemented.
        WeakKdfParametersError: If the decoded parameters violate the floor.
        CorruptedContainerError: If ``params`` cannot be parsed.
    """
    if kdf_id == KDF_ID_PBKDF2_SHA256:
        return Pbkdf2Kdf.decode_params(params)
    if kdf_id == KDF_ID_ARGON2ID:
        return Argon2idKdf.decode_params(params)
    # Lazy import to avoid a cycle — UnknownKdfError is part of the same
    # exception surface as the container errors but raising directly here
    # keeps the flow explicit.
    from guardiabox.core.exceptions import UnknownKdfError

    raise UnknownKdfError(f"unknown kdf_id=0x{kdf_id:02x}")

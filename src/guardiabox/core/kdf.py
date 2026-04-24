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

from collections.abc import Mapping
from dataclasses import dataclass
import struct
from types import MappingProxyType
from typing import ClassVar, Self

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from guardiabox.core.constants import (
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    KDF_ID_ARGON2ID,
    KDF_ID_PBKDF2_SHA256,
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    SALT_BYTES,
)
from guardiabox.core.exceptions import (
    CorruptedContainerError,
    WeakKdfParametersError,
)

__all__ = [
    "KDF_REGISTRY",
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
        if self.iterations > PBKDF2_MAX_ITERATIONS:
            # Upper cap protects against a crafted ``.crypt`` that would
            # otherwise lock the decoder for hours. The legitimate
            # operating range is well inside this ceiling (see CRYPTO_DECISIONS §2).
            raise WeakKdfParametersError(
                f"PBKDF2 iterations {self.iterations} above ceiling {PBKDF2_MAX_ITERATIONS}"
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
        if self.memory_cost_kib > ARGON2_MAX_MEMORY_KIB:
            violations.append(
                f"memory_cost_kib {self.memory_cost_kib} > {ARGON2_MAX_MEMORY_KIB} (ceiling)"
            )
        if self.time_cost < ARGON2_MIN_TIME_COST:
            violations.append(f"time_cost {self.time_cost} < {ARGON2_MIN_TIME_COST}")
        if self.time_cost > ARGON2_MAX_TIME_COST:
            violations.append(f"time_cost {self.time_cost} > {ARGON2_MAX_TIME_COST} (ceiling)")
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            violations.append(f"parallelism {self.parallelism} < {ARGON2_MIN_PARALLELISM}")
        if self.parallelism > ARGON2_MAX_PARALLELISM:
            violations.append(
                f"parallelism {self.parallelism} > {ARGON2_MAX_PARALLELISM} (ceiling)"
            )
        if violations:
            raise WeakKdfParametersError(
                "Argon2id parameters outside OWASP 2026 range: " + "; ".join(violations)
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


#: Public registry mapping ``kdf_id`` bytes to the concrete KDF class.
#: A new KDF is added by adding ``kdf_id -> class`` to the backing
#: dict below and implementing ``encode_params`` / ``decode_params``.
#: The container layout itself needs no change (cf. ADR-0013).
#:
#: ``KDF_REGISTRY`` is a read-only :class:`MappingProxyType` view, so
#: a rogue module cannot monkey-patch a fake KDF into the dispatch at
#: runtime (defence in depth — see Fix-1.O).
_KDF_REGISTRY_IMPL: dict[int, type[Pbkdf2Kdf] | type[Argon2idKdf]] = {
    KDF_ID_PBKDF2_SHA256: Pbkdf2Kdf,
    KDF_ID_ARGON2ID: Argon2idKdf,
}
KDF_REGISTRY: Mapping[int, type[Pbkdf2Kdf] | type[Argon2idKdf]] = MappingProxyType(
    _KDF_REGISTRY_IMPL,
)


def kdf_for_id(kdf_id: int, params: bytes) -> Pbkdf2Kdf | Argon2idKdf:
    """Return the concrete KDF instance matching ``kdf_id`` with ``params``.

    Raises:
        UnknownKdfError: If ``kdf_id`` is not implemented.
        WeakKdfParametersError: If the decoded parameters violate the floor.
        CorruptedContainerError: If ``params`` cannot be parsed.
    """
    kdf_cls = KDF_REGISTRY.get(kdf_id)
    if kdf_cls is None:
        from guardiabox.core.exceptions import UnknownKdfError

        raise UnknownKdfError(f"unknown kdf_id=0x{kdf_id:02x}")
    return kdf_cls.decode_params(params)

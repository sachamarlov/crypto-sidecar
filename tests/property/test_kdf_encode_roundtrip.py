"""Property-based round-trip of KDF param serialisation.

``encode_params`` and ``decode_params`` sit at the boundary of the
``.crypt`` container. Any drift between them silently breaks every
existing file. This suite proves round-trip equality across the full
legal parameter range for both KDFs.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st
import pytest

from guardiabox.core.constants import (
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf


@pytest.mark.property
@given(iterations=st.integers(min_value=PBKDF2_MIN_ITERATIONS, max_value=PBKDF2_MAX_ITERATIONS))
@settings(max_examples=100, deadline=None)
def test_pbkdf2_encode_decode_is_identity(iterations: int) -> None:
    """For every legal iteration count, encode -> decode yields an equal instance."""
    original = Pbkdf2Kdf(iterations=iterations)
    decoded = Pbkdf2Kdf.decode_params(original.encode_params())
    assert decoded == original
    assert decoded.iterations == iterations


@pytest.mark.property
@given(
    memory_kib=st.integers(min_value=ARGON2_MIN_MEMORY_KIB, max_value=ARGON2_MAX_MEMORY_KIB),
    time_cost=st.integers(min_value=ARGON2_MIN_TIME_COST, max_value=ARGON2_MAX_TIME_COST),
    parallelism=st.integers(min_value=ARGON2_MIN_PARALLELISM, max_value=ARGON2_MAX_PARALLELISM),
)
@settings(max_examples=100, deadline=None)
def test_argon2id_encode_decode_is_identity(
    memory_kib: int, time_cost: int, parallelism: int
) -> None:
    original = Argon2idKdf(
        memory_cost_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
    )
    decoded = Argon2idKdf.decode_params(original.encode_params())
    assert decoded == original
    assert decoded.memory_cost_kib == memory_kib
    assert decoded.time_cost == time_cost
    assert decoded.parallelism == parallelism


@pytest.mark.property
@given(
    iterations=st.integers(min_value=PBKDF2_MIN_ITERATIONS, max_value=PBKDF2_MAX_ITERATIONS),
)
def test_pbkdf2_encoded_params_are_four_bytes(iterations: int) -> None:
    """PBKDF2 params serialise to exactly 4 bytes big-endian."""
    blob = Pbkdf2Kdf(iterations=iterations).encode_params()
    assert len(blob) == 4

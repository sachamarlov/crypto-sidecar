"""Property-based roundtrip: ``decrypt(encrypt(x, p)) == x``.

Parameters are trimmed to keep the suite fast (PBKDF2 at 600 000 iterations
dominates runtime). We exercise plaintext sizes around chunk boundaries, which
are the most interesting edge cases for the streaming format.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from guardiabox.core.constants import DEFAULT_CHUNK_BYTES
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import (
    decrypt_message,
    encrypt_message,
)

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret

_INTERESTING_SIZES: list[int] = [
    0,
    1,
    DEFAULT_CHUNK_BYTES - 1,
    DEFAULT_CHUNK_BYTES,
    DEFAULT_CHUNK_BYTES + 1,
    DEFAULT_CHUNK_BYTES * 2 + 5,
]


@pytest.mark.property
@pytest.mark.parametrize("size", _INTERESTING_SIZES)
@given(payload=st.binary(min_size=0, max_size=DEFAULT_CHUNK_BYTES * 3 + 10))
@settings(
    max_examples=4,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_pbkdf2_message_roundtrip(
    tmp_path_factory: pytest.TempPathFactory, size: int, payload: bytes
) -> None:
    """Parametric over anchor sizes, fuzzed over arbitrary bytes within bound."""
    tmp: Path = tmp_path_factory.mktemp("prop")
    sliced = payload[:size]
    dest = tmp / "msg.crypt"
    encrypt_message(sliced, STRONG_PASSWORD, root=tmp, dest=dest, kdf=Pbkdf2Kdf())
    assert decrypt_message(dest, STRONG_PASSWORD) == sliced


@pytest.mark.property
@pytest.mark.slow
def test_argon2id_message_roundtrip(tmp_path: Path) -> None:
    """A single Argon2id roundtrip per suite — the KDF is expensive."""
    payload = b"\xde\xad\xbe\xef" * 1024
    dest = tmp_path / "msg.crypt"
    encrypt_message(payload, STRONG_PASSWORD, root=tmp_path, dest=dest, kdf=Argon2idKdf())
    assert decrypt_message(dest, STRONG_PASSWORD) == payload

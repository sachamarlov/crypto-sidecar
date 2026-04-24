"""Edge-case tests for :func:`guardiabox.core.operations.inspect_container`.

The happy path is covered by the CLI integration tests; this file exercises
the header-only branches (Pbkdf2 vs Argon2id summary, short ciphertext,
corrupted header) that the CLI suite does not reach directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import (
    ContainerInspection,
    encrypt_file,
    encrypt_message,
    inspect_container,
)

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


def _make_pbkdf2_container(tmp_path: Path, payload: bytes = b"payload") -> Path:
    source = tmp_path / "in.bin"
    source.write_bytes(payload)
    return encrypt_file(source, STRONG_PASSWORD, root=tmp_path, kdf=Pbkdf2Kdf())


def _make_argon2_container(tmp_path: Path) -> Path:
    dest = tmp_path / "msg.crypt"
    encrypt_message(b"argon", STRONG_PASSWORD, root=tmp_path, dest=dest, kdf=Argon2idKdf())
    return dest


def test_inspect_reports_pbkdf2_summary(tmp_path: Path) -> None:
    crypt = _make_pbkdf2_container(tmp_path)
    info = inspect_container(crypt)
    assert isinstance(info, ContainerInspection)
    assert info.kdf_name == "PBKDF2-HMAC-SHA256"
    assert "iterations=" in info.kdf_params_summary
    assert info.version == 1
    assert info.header_size == 40  # 4+1+1+2+4+16+12 = 40 bytes for PBKDF2
    assert info.ciphertext_size > 0


@pytest.mark.slow
def test_inspect_reports_argon2_summary(tmp_path: Path) -> None:
    crypt = _make_argon2_container(tmp_path)
    info = inspect_container(crypt)
    assert info.kdf_name == "Argon2id"
    assert "memory_kib=" in info.kdf_params_summary
    assert "time_cost=" in info.kdf_params_summary
    assert "parallelism=" in info.kdf_params_summary
    # Argon2id header is 48 bytes (12 bytes of params instead of 4).
    assert info.header_size == 48


def test_inspect_short_file_raises(tmp_path: Path) -> None:
    """A file shorter than the fixed prefix must surface a data error."""
    fake = tmp_path / "truncated.crypt"
    fake.write_bytes(b"GB")  # shorter than magic
    with pytest.raises(CorruptedContainerError):
        inspect_container(fake)


def test_inspect_bad_magic_raises(tmp_path: Path) -> None:
    fake = tmp_path / "not-gbox.crypt"
    fake.write_bytes(b"XXXX" + b"\x01" * 64)
    with pytest.raises(InvalidContainerError):
        inspect_container(fake)


def test_inspect_hex_fields_are_encoded(tmp_path: Path) -> None:
    crypt = _make_pbkdf2_container(tmp_path)
    info = inspect_container(crypt)
    # salt = 16 bytes -> 32 hex chars ; base_nonce = 12 bytes -> 24 hex chars.
    assert len(info.salt_hex) == 32
    assert len(info.base_nonce_hex) == 24
    # Hex is lowercase, printable.
    assert all(c in "0123456789abcdef" for c in info.salt_hex)

"""Tests for :mod:`guardiabox.security.vault_admin`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.exceptions import WeakPasswordError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.security.vault_admin import (
    ADMIN_CONFIG_FILENAME,
    VaultAdminConfig,
    VaultAdminConfigAlreadyExistsError,
    VaultAdminConfigMissingError,
    create_admin_config,
    derive_admin_key,
    read_admin_config,
    write_admin_config,
)

STRONG = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
OTHER = "Different_Horse_Battery_Staple_42!"  # pragma: allowlist secret


def test_create_admin_config_has_expected_shape() -> None:
    config = create_admin_config(STRONG)
    assert len(config.salt) == 16
    assert config.kdf_id == Pbkdf2Kdf.kdf_id
    assert len(config.kdf_params) == 4  # PBKDF2 iterations as uint32 BE


def test_create_admin_config_refuses_weak_password() -> None:
    with pytest.raises(WeakPasswordError):
        create_admin_config("weak")


def test_two_create_calls_produce_distinct_salts() -> None:
    a = create_admin_config(STRONG)
    b = create_admin_config(STRONG)
    assert a.salt != b.salt


def test_to_from_json_roundtrip() -> None:
    config = create_admin_config(STRONG)
    decoded = VaultAdminConfig.from_json(config.to_json())
    assert decoded == config


def test_from_json_rejects_unknown_schema_version() -> None:
    blob = '{"schema_version": 99, "salt": "' + "00" * 16 + '", "kdf_id": 1, "kdf_params": ""}'
    with pytest.raises(ValueError, match="schema_version"):
        VaultAdminConfig.from_json(blob)


def test_from_json_rejects_wrong_salt_length() -> None:
    bad = (
        '{"schema_version": 2, "salt": "00", "kdf_id": 1, "kdf_params": "00", '
        '"verification_blob": "00"}'
    )
    with pytest.raises(ValueError, match="salt"):
        VaultAdminConfig.from_json(bad)


def test_from_json_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        VaultAdminConfig.from_json("[]")


@pytest.mark.slow
def test_derive_admin_key_is_32_bytes() -> None:
    config = create_admin_config(STRONG)
    key = derive_admin_key(config, STRONG)
    assert len(key) == 32


@pytest.mark.slow
def test_derive_admin_key_deterministic_for_same_password() -> None:
    config = create_admin_config(STRONG)
    a = derive_admin_key(config, STRONG)
    b = derive_admin_key(config, STRONG)
    assert a == b


@pytest.mark.slow
def test_derive_admin_key_differs_per_password() -> None:
    config = create_admin_config(STRONG)
    a = derive_admin_key(config, STRONG)
    b = derive_admin_key(config, OTHER)
    assert a != b


@pytest.mark.slow
def test_derive_admin_key_differs_per_salt() -> None:
    a_config = create_admin_config(STRONG)
    b_config = create_admin_config(STRONG)
    a = derive_admin_key(a_config, STRONG)
    b = derive_admin_key(b_config, STRONG)
    assert a != b


@pytest.mark.slow
def test_derive_admin_key_nfc_equivalent_passwords() -> None:
    """NFC vs NFD forms of the same password derive the same key."""
    # U+00E9 vs U+0065 + U+0301
    nfc_password = "Café_Horse_Battery_Staple_42!"  # pragma: allowlist secret
    nfd_password = "Café_Horse_Battery_Staple_42!"  # pragma: allowlist secret
    config = create_admin_config(nfc_password)
    a = derive_admin_key(config, nfc_password)
    b = derive_admin_key(config, nfd_password)
    assert a == b


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    config = create_admin_config(STRONG)
    path = tmp_path / ADMIN_CONFIG_FILENAME
    write_admin_config(path, config)
    assert path.is_file()
    loaded = read_admin_config(path)
    assert loaded == config


def test_write_refuses_existing_file(tmp_path: Path) -> None:
    config = create_admin_config(STRONG)
    path = tmp_path / ADMIN_CONFIG_FILENAME
    write_admin_config(path, config)
    with pytest.raises(VaultAdminConfigAlreadyExistsError):
        write_admin_config(path, config)


def test_read_missing_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "does-not-exist.json"
    with pytest.raises(VaultAdminConfigMissingError):
        read_admin_config(path)


def test_write_creates_parent_dir(tmp_path: Path) -> None:
    """The function must mkdir -p the parent so first-run init works."""
    config = create_admin_config(STRONG)
    path = tmp_path / "nested" / "dir" / ADMIN_CONFIG_FILENAME
    write_admin_config(path, config)
    assert path.is_file()


@pytest.mark.slow
def test_argon2id_admin_config() -> None:
    """Argon2id is opt-in; ensure the derive path works end-to-end."""
    config = create_admin_config(STRONG, kdf=Argon2idKdf())
    assert config.kdf_id == Argon2idKdf.kdf_id
    key = derive_admin_key(config, STRONG)
    assert len(key) == 32

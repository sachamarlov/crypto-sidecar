"""Tests for :mod:`guardiabox.config`."""

from __future__ import annotations

from pydantic import ValidationError
import pytest

from guardiabox.config import (
    CryptoSettings,
    Settings,
    SidecarSettings,
    get_settings,
)


def test_default_crypto_settings_match_owasp_floors() -> None:
    """Default CryptoSettings must not fall below OWASP 2026 / NIST floors."""
    crypto = CryptoSettings()
    assert crypto.pbkdf2_iterations >= 600_000
    assert crypto.argon2id_memory_cost_kib >= 19_456
    assert crypto.argon2id_time_cost >= 2
    assert crypto.argon2id_parallelism >= 1
    assert crypto.rsa_key_bits in {3072, 4096}
    assert crypto.aes_nonce_bytes == 12
    assert crypto.salt_bytes in {16, 32}


def test_pbkdf2_iterations_refused_below_floor() -> None:
    with pytest.raises(ValidationError):
        CryptoSettings(pbkdf2_iterations=100)


def test_argon2id_memory_refused_below_floor() -> None:
    with pytest.raises(ValidationError):
        CryptoSettings(argon2id_memory_cost_kib=100)


def test_sidecar_binds_127_0_0_1_only() -> None:
    sidecar = SidecarSettings()
    assert sidecar.host == "127.0.0.1"
    # 0 = OS-chosen free port; 0 to 65535 are accepted.
    assert 0 <= sidecar.port <= 65_535


def test_top_level_defaults_are_coherent() -> None:
    """Default Settings load without explicit args and expose the sub-models.

    ``data_dir`` is deliberately not asserted against a fixed value because
    the test environment (conftest / CI) can override it via
    ``GUARDIABOX_DATA_DIR`` -- matching the behaviour users rely on.
    """
    settings = Settings()
    assert settings.auto_lock_minutes == 15
    assert settings.data_dir.is_absolute()
    assert isinstance(settings.crypto, CryptoSettings)
    assert isinstance(settings.sidecar, SidecarSettings)


def test_get_settings_returns_fresh_instance_each_call() -> None:
    """The helper deliberately does not cache, so tests can parametrise."""
    a = get_settings()
    b = get_settings()
    assert a is not b
    assert a == b  # equal fields


def test_env_override_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """GUARDIABOX_AUTO_LOCK_MINUTES overrides the default."""
    monkeypatch.setenv("GUARDIABOX_AUTO_LOCK_MINUTES", "42")
    settings = Settings()
    assert settings.auto_lock_minutes == 42


def test_forbids_extra_constructor_kwargs() -> None:
    """``extra="forbid"`` refuses unknown kwargs passed directly to the model.

    (Unknown ``GUARDIABOX_`` env vars that do not match a field name are
    ignored by pydantic-settings -- the guard fires for constructor
    kwargs only.)
    """
    with pytest.raises(ValidationError):
        Settings(unknown_setting="boom")  # type: ignore[call-arg]

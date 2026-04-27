"""Integration tests for Phase E -- spec 000-cli residuals.

Covers:
* T-000cli.08 -- config list / get / set sub-Typer
* T-000cli.12 -- --quiet / --verbose global flags
* T-000cli.13 -- --format json|table on user list / user show / doctor
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.persistence.bootstrap import init_vault
from guardiabox.ui.cli.commands import user as user_cmd
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

ADMIN_PW = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
ALICE_PW = "Alice_Strong_Password_2026!"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# T-000cli.08 -- config sub-Typer
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_config_list_lists_known_keys() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "list"])
    assert result.exit_code == ExitCode.OK, result.stderr
    # The flat dict must contain at least these top-level + nested keys.
    assert "data_dir" in result.stdout
    assert "auto_lock_minutes" in result.stdout
    assert "crypto.pbkdf2_iterations" in result.stdout


@pytest.mark.integration
def test_config_get_returns_known_value() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "get", "crypto.pbkdf2_iterations"])
    assert result.exit_code == ExitCode.OK, result.stderr
    assert result.stdout.strip() == "600000"


@pytest.mark.integration
def test_config_get_unknown_key_exits_path_or_file() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "get", "non.existent.key"])
    assert result.exit_code == ExitCode.PATH_OR_FILE


@pytest.mark.integration
def test_config_set_is_deferred_post_mvp() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "set", "data_dir", "anywhere"])
    assert result.exit_code == ExitCode.USAGE
    assert "post-MVP" in result.stderr or "MVP" in result.stderr or "GUARDIABOX_" in result.stderr


@pytest.mark.integration
def test_config_help_advertises_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["config", "--help"])
    assert result.exit_code == ExitCode.OK
    flat = " ".join(result.stdout.split())
    assert "list" in flat
    assert "get" in flat


# ---------------------------------------------------------------------------
# T-000cli.12 -- --quiet / --verbose global flags
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_quiet_and_verbose_are_mutually_exclusive() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--quiet", "--verbose", "config", "list"])
    assert result.exit_code == ExitCode.USAGE
    assert "exclusifs" in result.stderr or "mutually" in result.stderr


@pytest.mark.integration
def test_version_flag_still_works() -> None:
    """--version is a sibling root flag of --quiet / --verbose; must still work."""
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == ExitCode.OK
    assert "guardiabox" in result.stdout.lower()


@pytest.mark.integration
def test_quiet_flag_does_not_break_a_read_command() -> None:
    """--quiet should not regress functional output of a working command."""
    runner = CliRunner()
    result = runner.invoke(app, ["--quiet", "config", "get", "auto_lock_minutes"])
    assert result.exit_code == ExitCode.OK


@pytest.mark.integration
def test_verbose_flag_does_not_break_a_read_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--verbose", "config", "get", "auto_lock_minutes"])
    assert result.exit_code == ExitCode.OK


# ---------------------------------------------------------------------------
# T-000cli.13 -- --format json|table on user list / user show / doctor
# ---------------------------------------------------------------------------


@pytest.fixture(name="vault_with_alice")
def _vault_with_alice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Init vault, register Alice via the in-process flow."""
    queue: list[str] = []

    def fake_read_password(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.user.read_password",
        "guardiabox.ui.cli.commands.init.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake_read_password, raising=True)

    data_dir = tmp_path / "vault"
    asyncio.run(init_vault(data_dir, ADMIN_PW))

    queue.extend((ALICE_PW, ADMIN_PW))
    asyncio.run(
        user_cmd._create_flow(  # noqa: SLF001
            data_dir=data_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )
    return data_dir


@pytest.fixture(name="patched_pw")
def _patched_pw(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    queue: list[str] = []

    def fake(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake, raising=True)

    def configure(*answers: str) -> None:
        queue.clear()
        queue.extend(answers)

    return configure


@pytest.mark.integration
@pytest.mark.slow
def test_user_list_format_json_returns_parseable_json(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
) -> None:
    patched_pw(ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "user",
            "list",
            "--format",
            "json",
            "--data-dir",
            str(vault_with_alice),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["username"] == "alice"
    assert "id" in parsed[0]
    assert "created_at" in parsed[0]
    assert "kdf_id" in parsed[0]


@pytest.mark.integration
@pytest.mark.slow
def test_user_show_format_json_returns_parseable_json(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
) -> None:
    patched_pw(ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "user",
            "show",
            "alice",
            "--format",
            "json",
            "--data-dir",
            str(vault_with_alice),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    assert parsed["username"] == "alice"
    assert "failed_unlock_count" in parsed


@pytest.mark.integration
def test_doctor_format_json_returns_parseable_json(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "doctor",
            "--format",
            "json",
            "--data-dir",
            str(tmp_path / "vault"),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    assert "data_dir" in parsed
    assert "db_present" in parsed
    assert "sqlcipher_available" in parsed


@pytest.mark.integration
def test_doctor_report_ssd_format_json_includes_is_ssd_field(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "doctor",
            "--report-ssd",
            "--format",
            "json",
            "--data-dir",
            str(tmp_path / "vault"),
        ],
    )
    assert result.exit_code == ExitCode.OK
    parsed = json.loads(result.stdout)
    assert "is_ssd" in parsed
    assert "storage_label" in parsed

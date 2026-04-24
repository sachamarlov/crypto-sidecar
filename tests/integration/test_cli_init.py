"""Integration tests for ``guardiabox init``."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from guardiabox.persistence.bootstrap import vault_paths
from guardiabox.security.vault_admin import read_admin_config
from guardiabox.ui.cli.io import ExitCode

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret

_TIMEOUT = 120


def _run_init(workdir: Path, data_dir: Path, password: str) -> subprocess.CompletedProcess[bytes]:
    """Invoke ``guardiabox init`` via subprocess so the CLI entry is exercised end-to-end."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "guardiabox",
            "init",
            "--data-dir",
            str(data_dir),
            "--password-stdin",
        ],
        cwd=str(workdir),
        input=(password + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
    )


@pytest.mark.integration
@pytest.mark.slow
def test_init_creates_data_dir_db_and_admin_config(tmp_path: Path) -> None:
    data_dir = tmp_path / "vault"
    result = _run_init(tmp_path, data_dir, STRONG_PASSWORD)

    assert result.returncode == ExitCode.OK, (
        f"init failed: rc={result.returncode} stderr={result.stderr!r}"
    )

    paths = vault_paths(data_dir)
    assert paths.data_dir.is_dir()
    assert paths.db.is_file()
    assert paths.admin_config.is_file()

    # Admin config is readable and matches the schema.
    config = read_admin_config(paths.admin_config)
    assert len(config.salt) == 16
    assert config.kdf_id == 1  # PBKDF2 by default


@pytest.mark.integration
@pytest.mark.slow
def test_init_refuses_to_overwrite_existing_admin(tmp_path: Path) -> None:
    data_dir = tmp_path / "vault"
    first = _run_init(tmp_path, data_dir, STRONG_PASSWORD)
    assert first.returncode == ExitCode.OK, first.stderr

    # Second call must refuse with ExitCode.USAGE.
    second = _run_init(tmp_path, data_dir, STRONG_PASSWORD)
    assert second.returncode == ExitCode.USAGE
    assert b"d" in second.stderr.lower()  # "déjà" in French message


@pytest.mark.integration
@pytest.mark.slow
def test_init_audit_log_has_one_genesis_row(tmp_path: Path) -> None:
    """After init, the audit log holds exactly one SYSTEM_STARTUP row."""
    from sqlalchemy import create_engine, text

    data_dir = tmp_path / "vault"
    result = _run_init(tmp_path, data_dir, STRONG_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr

    paths = vault_paths(data_dir)
    sync_engine = create_engine(f"sqlite:///{paths.db}")
    try:
        with sync_engine.connect() as conn:
            rows = list(conn.execute(text("SELECT sequence, action FROM audit_log")))
            assert len(rows) == 1
            assert rows[0][0] == 1  # sequence
            assert rows[0][1] == "system.startup"
    finally:
        sync_engine.dispose()


@pytest.mark.integration
def test_init_weak_password_exits_generic(tmp_path: Path) -> None:
    data_dir = tmp_path / "vault"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guardiabox",
            "init",
            "--data-dir",
            str(data_dir),
            "--password-stdin",
        ],
        cwd=str(tmp_path),
        input=b"weak\n",
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
    )
    assert result.returncode == ExitCode.GENERIC
    # The vault must not exist after a weak-password abort.
    assert not (data_dir / "vault.admin.json").exists()
    assert not (data_dir / "vault.db").exists() or (data_dir / "vault.db").stat().st_size == 0


@pytest.mark.integration
def test_init_help_advertises_command() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "guardiabox", "init", "--help"],
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
    )
    assert result.returncode == ExitCode.OK
    assert b"data-dir" in result.stdout
    assert b"kdf" in result.stdout

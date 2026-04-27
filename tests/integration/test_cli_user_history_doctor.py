"""Integration tests for the Phase C-2 CLI commands.

These tests drive the real CLI via ``subprocess.run`` so every code
path (argument parsing, Typer dispatch, async fixture teardown) runs
as a user would see it. Each scenario starts from a freshly
``init``-ed vault in a ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from guardiabox.ui.cli.io import ExitCode

STRONG = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
USER_PW = "User_Password_Another_Strong_42!"  # pragma: allowlist secret

_TIMEOUT = 180


def _run(
    args: list[str], *, stdin: str = "", cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run ``python -m guardiabox <args>`` with the given stdin payload."""
    return subprocess.run(
        [sys.executable, "-m", "guardiabox", *args],
        cwd=str(cwd) if cwd else None,
        input=stdin.encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
    )


@pytest.fixture(name="vault_dir")
def _vault_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "vault"
    result = _run(
        ["init", "--data-dir", str(data_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.OK, result.stderr
    return data_dir


# ---------------------------------------------------------------------------
# user create / list / show / delete
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_user_create_then_list_then_show_then_delete(vault_dir: Path) -> None:
    # Create
    created = _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    assert created.returncode == ExitCode.OK, created.stderr
    assert b"alice" in created.stdout

    # List
    listed = _run(
        ["user", "list", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert listed.returncode == ExitCode.OK, listed.stderr
    assert b"alice" in listed.stdout

    # Show
    shown = _run(
        ["user", "show", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert shown.returncode == ExitCode.OK, shown.stderr
    assert b"alice" in shown.stdout

    # Delete (with --yes so no confirm prompt)
    deleted = _run(
        ["user", "delete", "alice", "--yes", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert deleted.returncode == ExitCode.OK, deleted.stderr

    # List again -> empty
    empty = _run(
        ["user", "list", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert empty.returncode == ExitCode.OK
    assert b"(aucun" in empty.stdout


@pytest.mark.integration
@pytest.mark.slow
def test_user_create_duplicate_username_rejected(vault_dir: Path) -> None:
    first = _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    assert first.returncode == ExitCode.OK

    second = _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    assert second.returncode == ExitCode.USAGE
    assert b"d" in second.stderr.lower()


@pytest.mark.integration
@pytest.mark.slow
def test_user_show_unknown_exits_path_or_file(vault_dir: Path) -> None:
    result = _run(
        ["user", "show", "nobody", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.PATH_OR_FILE


@pytest.mark.integration
@pytest.mark.slow
def test_user_delete_unknown_exits_path_or_file(vault_dir: Path) -> None:
    result = _run(
        [
            "user",
            "delete",
            "ghost",
            "--yes",
            "--data-dir",
            str(vault_dir),
            "--password-stdin",
        ],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.PATH_OR_FILE


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_history_shows_system_startup_and_user_events(vault_dir: Path) -> None:
    # Create a user so the log has more than just SYSTEM_STARTUP.
    _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    result = _run(
        ["history", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.OK, result.stderr
    out = result.stdout
    assert b"system.startup" in out
    assert b"user.create" in out


@pytest.mark.integration
@pytest.mark.slow
def test_history_json_format_parseable(vault_dir: Path) -> None:
    _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    result = _run(
        [
            "history",
            "--format",
            "json",
            "--data-dir",
            str(vault_dir),
            "--password-stdin",
        ],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.OK
    payload = json.loads(result.stdout.decode("utf-8"))
    assert isinstance(payload, list)
    actions = {entry["action"] for entry in payload}
    assert "system.startup" in actions
    assert "user.create" in actions


@pytest.mark.integration
@pytest.mark.slow
def test_history_filter_by_action(vault_dir: Path) -> None:
    _run(
        ["user", "create", "alice", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{USER_PW}\n{STRONG}\n",
    )
    result = _run(
        [
            "history",
            "--action",
            "user.create",
            "--data-dir",
            str(vault_dir),
            "--password-stdin",
        ],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.OK
    out = result.stdout
    assert b"user.create" in out
    assert b"system.startup" not in out


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_doctor_reports_paths_without_unlock(vault_dir: Path) -> None:
    """Without --verify-audit, doctor must not prompt for a password."""
    result = _run(["doctor", "--data-dir", str(vault_dir)])
    assert result.returncode == ExitCode.OK, result.stderr
    out = result.stdout
    assert b"vault.db" in out
    assert b"vault.admin.json" in out


@pytest.mark.integration
@pytest.mark.slow
def test_doctor_verify_audit_clean_chain(vault_dir: Path) -> None:
    result = _run(
        ["doctor", "--verify-audit", "--data-dir", str(vault_dir), "--password-stdin"],
        stdin=f"{STRONG}\n",
    )
    assert result.returncode == ExitCode.OK, result.stderr
    # The French word "intègre" might be re-encoded by the Windows
    # console (cp1252) and unreadable as UTF-8. The [OK] marker is
    # pure ASCII and always survives; we assert on that.
    assert b"[OK]" in result.stdout


@pytest.mark.integration
def test_doctor_verify_audit_refuses_uninitialised(tmp_path: Path) -> None:
    result = _run(
        ["doctor", "--verify-audit", "--data-dir", str(tmp_path / "nope")],
    )
    assert result.returncode == ExitCode.CONFIG_ERROR


@pytest.mark.integration
def test_help_lists_new_commands() -> None:
    result = _run(["--help"])
    assert result.returncode == ExitCode.OK
    out = result.stdout
    assert b"init" in out
    assert b"user" in out
    assert b"history" in out
    assert b"doctor" in out

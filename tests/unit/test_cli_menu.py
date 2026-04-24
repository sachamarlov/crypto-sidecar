"""Smoke tests for ``guardiabox menu`` — the F-7 interactive REPL.

The REPL is driven via ``subprocess.run`` with ``stdin=`` piped input, not
``CliRunner``: Rich's :class:`rich.prompt.Prompt` opens its own
:class:`rich.console.Console` which bypasses Typer's test runner. Subprocess
captures the real stdout/stderr and lets us assert exit codes straight.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from guardiabox.ui.cli.io import ExitCode

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret

_MENU_TIMEOUT = 60


def _run_menu(cwd: Path, stdin_lines: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Pipe ``stdin_lines`` into ``python -m guardiabox menu``."""
    payload = ("\n".join(stdin_lines) + "\n").encode("utf-8")
    return subprocess.run(
        [sys.executable, "-m", "guardiabox", "menu"],
        cwd=str(cwd),
        input=payload,
        capture_output=True,
        check=False,
        timeout=_MENU_TIMEOUT,
    )


@pytest.mark.integration
def test_menu_quit_option_exits_zero(tmp_path: Path) -> None:
    """The explicit 'q' choice returns to the shell with exit 0."""
    result = _run_menu(tmp_path, ["q"])
    assert result.returncode == ExitCode.OK, (
        f"menu with 'q' must exit 0, got {result.returncode}. stderr={result.stderr!r}"
    )
    assert b"Au revoir" in result.stdout, result.stdout


@pytest.mark.integration
def test_menu_eof_on_choice_exits_interrupted(tmp_path: Path) -> None:
    """Closing stdin before typing a choice is treated as user interruption."""
    result = subprocess.run(
        [sys.executable, "-m", "guardiabox", "menu"],
        cwd=str(tmp_path),
        input=b"",  # empty stdin → immediate EOF
        capture_output=True,
        check=False,
        timeout=_MENU_TIMEOUT,
    )
    assert result.returncode in {ExitCode.INTERRUPTED, ExitCode.OK}, (
        f"EOF on menu must exit 130 or 0 (default 'q'), got {result.returncode}. "
        f"stderr={result.stderr!r}"
    )


@pytest.mark.integration
def test_menu_help_lists_menu_command() -> None:
    """``guardiabox --help`` must advertise the menu command (F-7 CDC)."""
    result = subprocess.run(
        [sys.executable, "-m", "guardiabox", "--help"],
        capture_output=True,
        check=False,
        timeout=_MENU_TIMEOUT,
    )
    assert result.returncode == 0, result.stderr
    assert b"menu" in result.stdout, (
        f"'menu' subcommand missing from --help output: {result.stdout!r}"
    )

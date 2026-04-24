"""CLI coverage for ``guardiabox secure-delete``."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="workdir")
def _workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _mock_hdd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every path lives on a rotational disk, so no SSD warning fires."""
    monkeypatch.setattr(
        "guardiabox.ui.cli.commands.secure_delete.is_ssd",
        lambda _path: False,
    )


def _mock_ssd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guardiabox.ui.cli.commands.secure_delete.is_ssd",
        lambda _path: True,
    )


def _mock_unknown_media(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate an is_ssd probe that can't decide (remote FS, unusual disk)."""
    monkeypatch.setattr(
        "guardiabox.ui.cli.commands.secure_delete.is_ssd",
        lambda _path: None,
    )


def test_secure_delete_happy_path_hdd(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_hdd(monkeypatch)
    target = workdir / "sensitive.bin"
    target.write_bytes(b"A" * 2048)
    result = runner.invoke(app, ["secure-delete", "sensitive.bin"])
    assert result.exit_code == ExitCode.OK, result.stderr
    assert not target.exists()


def test_secure_delete_custom_passes(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_hdd(monkeypatch)
    target = workdir / "p5.bin"
    target.write_bytes(b"data")
    result = runner.invoke(app, ["secure-delete", "p5.bin", "--passes", "5"])
    assert result.exit_code == ExitCode.OK
    assert not target.exists()


def test_secure_delete_missing_file_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["secure-delete", "nope.bin"])
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_secure_delete_rejects_path_traversal(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["secure-delete", "../escape.bin"])
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_secure_delete_on_ssd_prompts_and_aborts(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSD detected → warning + confirmation prompt. Answering 'n' aborts."""
    _mock_ssd(monkeypatch)
    target = workdir / "ssd.bin"
    target.write_bytes(b"data")
    result = runner.invoke(
        app,
        ["secure-delete", "ssd.bin"],
        input="n\n",
    )
    assert result.exit_code == ExitCode.GENERIC
    assert target.exists(), "Abort must leave the file untouched"
    assert "SSD" in result.stderr


def test_secure_delete_on_ssd_confirmed(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_ssd(monkeypatch)
    target = workdir / "ssd.bin"
    target.write_bytes(b"data")
    result = runner.invoke(
        app,
        ["secure-delete", "ssd.bin"],
        input="y\n",
    )
    assert result.exit_code == ExitCode.OK
    assert not target.exists()


def test_secure_delete_no_confirm_flag_bypasses_prompt(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_ssd(monkeypatch)
    target = workdir / "ssd.bin"
    target.write_bytes(b"data")
    result = runner.invoke(
        app,
        ["secure-delete", "ssd.bin", "--no-confirm"],
    )
    assert result.exit_code == ExitCode.OK
    assert not target.exists()


def test_secure_delete_on_unknown_media_prompts_and_aborts(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix-1.M -- is_ssd returning None must warn and ask for confirmation."""
    _mock_unknown_media(monkeypatch)
    target = workdir / "unknown.bin"
    target.write_bytes(b"data")
    result = runner.invoke(
        app,
        ["secure-delete", "unknown.bin"],
        input="n\n",
    )
    assert result.exit_code == ExitCode.GENERIC
    assert target.exists()
    assert "support" in result.stderr.lower() or "identifié" in result.stderr.lower()


def test_secure_delete_on_unknown_media_no_confirm(
    runner: CliRunner, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--no-confirm lets the unknown-media path proceed without prompting."""
    _mock_unknown_media(monkeypatch)
    target = workdir / "unknown.bin"
    target.write_bytes(b"data")
    result = runner.invoke(
        app,
        ["secure-delete", "unknown.bin", "--no-confirm"],
    )
    assert result.exit_code == ExitCode.OK
    assert not target.exists()


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and collapse whitespace.

    Rich formats Typer's help inside a bordered panel and may wrap long
    flags across lines with escape codes between characters. Tests
    asserting on flag names need to strip that markup.
    """
    import re

    stripped = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return re.sub(r"\s+", " ", stripped)


def test_secure_delete_help_mentions_method_and_passes(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["secure-delete", "--help"])
    assert result.exit_code == ExitCode.OK
    stripped = _strip_ansi(result.stdout)
    assert "method" in stripped
    assert "passes" in stripped


def test_secure_delete_registered_in_top_level_help(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == ExitCode.OK
    stripped = _strip_ansi(result.stdout).lower()
    assert "secure" in stripped
    assert "delete" in stripped

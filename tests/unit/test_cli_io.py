"""Unit tests for :mod:`guardiabox.ui.cli.io`."""

from __future__ import annotations

import io
import sys
from unittest import mock

import pytest
import typer

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    DecryptionError,
    GuardiaBoxError,
    IntegrityError,
    InvalidContainerError,
    PathTraversalError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
    WeakPasswordError,
)
from guardiabox.ui.cli.io import (
    ANTI_ORACLE_MESSAGE,
    ExitCode,
    exit_for,
    read_password,
)


def _assert_exits_with(exc: BaseException, expected_code: ExitCode) -> None:
    with pytest.raises(typer.Exit) as info:
        exit_for(exc)
    assert info.value.exit_code == expected_code


# ---------------------------------------------------------------------------
# exit_for — mapping
# ---------------------------------------------------------------------------


def test_passthrough_existing_typer_exit() -> None:
    """A typer.Exit already raised by a caller is re-raised verbatim."""
    original = typer.Exit(code=64)
    with pytest.raises(typer.Exit) as info:
        exit_for(original)
    assert info.value is original


def test_keyboard_interrupt_maps_to_130() -> None:
    _assert_exits_with(KeyboardInterrupt(), ExitCode.INTERRUPTED)


def test_weak_password_error_maps_to_1() -> None:
    _assert_exits_with(WeakPasswordError("too short"), ExitCode.GENERIC)


@pytest.mark.parametrize(
    "exc",
    [
        PathTraversalError("escape"),
        SymlinkEscapeError("symlink"),
        FileNotFoundError("nope.txt"),
    ],
)
def test_path_or_file_errors_map_to_3(exc: Exception) -> None:
    _assert_exits_with(exc, ExitCode.PATH_OR_FILE)


@pytest.mark.parametrize(
    "exc",
    [
        InvalidContainerError("bad magic"),
        UnsupportedVersionError("v99"),
        UnknownKdfError("0x7e"),
        WeakKdfParametersError("iter 1"),
        CorruptedContainerError("truncated"),
    ],
)
def test_data_errors_map_to_65(exc: Exception) -> None:
    _assert_exits_with(exc, ExitCode.DATA_ERROR)


@pytest.mark.parametrize(
    "exc",
    [
        DecryptionError("wrong password"),
        IntegrityError("tag mismatch"),
    ],
)
def test_auth_failures_map_to_2_with_anti_oracle_message(
    exc: Exception, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(typer.Exit) as info:
        exit_for(exc)
    assert info.value.exit_code == ExitCode.AUTH_FAILED
    captured = capsys.readouterr()
    assert captured.err.strip() == ANTI_ORACLE_MESSAGE


def test_os_error_maps_to_generic() -> None:
    _assert_exits_with(OSError("disk full"), ExitCode.GENERIC)


def test_unknown_guardiabox_error_maps_to_generic() -> None:
    _assert_exits_with(GuardiaBoxError("whatever"), ExitCode.GENERIC)


def test_unknown_exception_maps_to_generic() -> None:
    _assert_exits_with(RuntimeError("unexpected"), ExitCode.GENERIC)


# ---------------------------------------------------------------------------
# read_password
# ---------------------------------------------------------------------------


def test_read_password_from_stdin_strips_lf_only() -> None:
    with mock.patch.object(sys, "stdin", io.StringIO("hunter2 \n")):
        assert read_password(stdin=True) == "hunter2 "


def test_read_password_from_stdin_strips_crlf() -> None:
    with mock.patch.object(sys, "stdin", io.StringIO("hunter2\r\n")):
        assert read_password(stdin=True) == "hunter2"


def test_read_password_from_stdin_preserves_unterminated_line() -> None:
    with mock.patch.object(sys, "stdin", io.StringIO("noEOL")):
        assert read_password(stdin=True) == "noEOL"


def test_read_password_interactive_delegates_to_typer(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_prompt(prompt: str, *, hide_input: bool, confirmation_prompt: bool) -> str:
        captured["prompt"] = prompt
        captured["hide_input"] = hide_input
        captured["confirmation_prompt"] = confirmation_prompt
        return "from-typer"

    # Fix-1.L -- read_password now fails-loud on a non-TTY stdin without
    # --password-stdin. The interactive code path assumes a real terminal,
    # so we fake isatty() = True for this branch.
    monkeypatch.setattr("guardiabox.ui.cli.io.sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("guardiabox.ui.cli.io.typer.prompt", fake_prompt)

    assert read_password(stdin=False, confirm=True, prompt="Saisissez") == "from-typer"
    assert captured == {
        "prompt": "Saisissez",
        "hide_input": True,
        "confirmation_prompt": True,
    }


def test_read_password_empty_stdin_exits_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix-1.L -- piping an empty stdin with --password-stdin is a usage error."""
    with mock.patch.object(sys, "stdin", io.StringIO("\n")), pytest.raises(typer.Exit) as info:
        read_password(stdin=True)
    assert info.value.exit_code == ExitCode.USAGE


def test_read_password_non_tty_without_flag_exits_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix-1.L -- non-TTY stdin without --password-stdin surfaces a clear error
    instead of letting typer.prompt emit a confusing message."""
    monkeypatch.setattr("guardiabox.ui.cli.io.sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.Exit) as info:
        read_password(stdin=False)
    assert info.value.exit_code == ExitCode.USAGE

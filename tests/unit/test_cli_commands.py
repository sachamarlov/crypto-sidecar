"""In-process tests of the Typer CLI commands.

The integration suite exercises the full subprocess launch path; this file
additionally drives the Typer app with :class:`typer.testing.CliRunner` so
coverage tooling can see the command implementations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.ui.cli.main import app

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="workdir")
def _workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version_flag(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "guardiabox" in result.stdout.lower()


def test_help_mentions_commands(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.stdout.lower()
    assert "encrypt" in output
    assert "decrypt" in output


def test_encrypt_requires_path_or_message(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["encrypt", "--password-stdin"], input=f"{STRONG_PASSWORD}\n")
    assert result.exit_code == 1
    assert "--message" in result.stderr or "chemin" in result.stderr.lower()


def test_encrypt_file_then_decrypt(runner: CliRunner, workdir: Path) -> None:
    source = workdir / "plain.txt"
    source.write_bytes(b"hello world inline")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0, enc.stderr
    assert (workdir / "plain.txt.crypt").exists()

    dec = runner.invoke(
        app,
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert dec.exit_code == 0, dec.stderr
    assert (workdir / "plain.txt.decrypt").read_bytes() == b"hello world inline"


def test_encrypt_weak_password_exits_1(runner: CliRunner, workdir: Path) -> None:
    (workdir / "plain.txt").write_bytes(b"x")
    result = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input="weak\n",
    )
    assert result.exit_code == 1
    assert "faible" in result.stderr.lower()


def test_encrypt_path_traversal_exits_1(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "../escape.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1
    assert "refus" in result.stderr.lower() or "chemin" in result.stderr.lower()


def test_encrypt_missing_file_exits_1(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "missing.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1


def test_encrypt_message_requires_output(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "--message", "payload", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1
    assert "output" in result.stderr.lower() or "-o" in result.stderr


def test_encrypt_message_then_decrypt_message(runner: CliRunner, workdir: Path) -> None:
    enc = runner.invoke(
        app,
        [
            "encrypt",
            "--message",
            "inline payload",
            "-o",
            "msg.crypt",
            "--password-stdin",
        ],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0, enc.stderr
    dec = runner.invoke(
        app,
        ["decrypt", "msg.crypt", "--message", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert dec.exit_code == 0, dec.stderr
    assert dec.stdout == "inline payload"


def test_decrypt_wrong_password_exits_2(runner: CliRunner, workdir: Path) -> None:
    (workdir / "plain.txt").write_bytes(b"secret")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0, enc.stderr
    result = runner.invoke(
        app,
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        input="Another_But_Strong_Password_42!\n",
    )
    assert result.exit_code == 2


def test_decrypt_missing_file_exits_1(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["decrypt", "nope.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1


def test_decrypt_invalid_container_exits_1(runner: CliRunner, workdir: Path) -> None:
    bad = workdir / "bad.crypt"
    bad.write_bytes(b"this is not a gbox container")
    result = runner.invoke(
        app,
        ["decrypt", "bad.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1
    assert b"conteneur" in result.stderr.encode().lower() or b"invalid" in (
        result.stderr.encode().lower()
    )


def test_decrypt_path_traversal_exits_1(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["decrypt", "../escape.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1


def test_encrypt_with_argon2id_and_decrypt(runner: CliRunner, workdir: Path) -> None:
    (workdir / "data.bin").write_bytes(b"\xab" * 4096)
    enc = runner.invoke(
        app,
        [
            "encrypt",
            "data.bin",
            "--kdf",
            "argon2id",
            "--password-stdin",
        ],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0, enc.stderr
    dec = runner.invoke(
        app,
        ["decrypt", "data.bin.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert dec.exit_code == 0

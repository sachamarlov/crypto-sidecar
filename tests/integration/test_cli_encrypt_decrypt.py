"""End-to-end CLI tests executed as real subprocesses.

We drive the Typer app through ``python -m guardiabox`` to cover the full
launch path: argv parsing, exit codes, stderr messages, stdout behaviour.
Each test isolates itself to a ``tmp_path`` working directory.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


def _run(
    args: list[str],
    cwd: Path,
    *,
    stdin: bytes | None = None,
    expected_exit: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        [sys.executable, "-m", "guardiabox", *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if expected_exit is not None:
        assert completed.returncode == expected_exit, (
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


@pytest.mark.integration
def test_cli_encrypt_then_decrypt_file(tmp_path: Path) -> None:
    source = tmp_path / "plain.txt"
    source.write_bytes(b"super secret content")

    _run(
        ["encrypt", "plain.txt", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    encrypted = tmp_path / "plain.txt.crypt"
    assert encrypted.exists()
    assert encrypted.read_bytes().startswith(b"GBOX")

    _run(
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    decrypted = tmp_path / "plain.txt.decrypt"
    assert decrypted.read_bytes() == b"super secret content"


@pytest.mark.integration
def test_cli_rejects_weak_password(tmp_path: Path) -> None:
    (tmp_path / "plain.txt").write_bytes(b"x")
    result = _run(
        ["encrypt", "plain.txt", "--password-stdin"],
        cwd=tmp_path,
        stdin=b"weak\n",
        expected_exit=1,
    )
    assert b"faible" in result.stderr.lower()
    assert not (tmp_path / "plain.txt.crypt").exists()


@pytest.mark.integration
def test_cli_rejects_path_traversal(tmp_path: Path) -> None:
    result = _run(
        ["encrypt", "../escape.txt", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=1,
    )
    assert b"chemin" in result.stderr.lower() or b"refus" in result.stderr.lower()


@pytest.mark.integration
def test_cli_wrong_password_exits_2(tmp_path: Path) -> None:
    source = tmp_path / "plain.txt"
    source.write_bytes(b"data")
    _run(
        ["encrypt", "plain.txt", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    _run(
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        cwd=tmp_path,
        stdin=b"Another_Strong_But_Wrong_42!\n",
        expected_exit=2,
    )
    assert not (tmp_path / "plain.txt.decrypt").exists()


@pytest.mark.integration
def test_cli_encrypt_decrypt_message(tmp_path: Path) -> None:
    _run(
        [
            "encrypt",
            "--message",
            "hidden payload",
            "-o",
            "msg.crypt",
            "--password-stdin",
        ],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    assert (tmp_path / "msg.crypt").exists()

    result = _run(
        ["decrypt", "msg.crypt", "--message", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    assert result.stdout == b"hidden payload"


@pytest.mark.integration
def test_cli_encrypt_with_argon2id(tmp_path: Path) -> None:
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02" * 2048)
    _run(
        ["encrypt", "data.bin", "--kdf", "argon2id", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    _run(
        ["decrypt", "data.bin.crypt", "--password-stdin"],
        cwd=tmp_path,
        stdin=(STRONG_PASSWORD + "\n").encode(),
        expected_exit=0,
    )
    assert (tmp_path / "data.bin.decrypt").read_bytes() == (tmp_path / "data.bin").read_bytes()


@pytest.mark.integration
def test_cli_help_lists_encrypt_and_decrypt(tmp_path: Path) -> None:
    result = _run(["--help"], cwd=tmp_path, expected_exit=0)
    output = result.stdout.lower()
    assert b"encrypt" in output
    assert b"decrypt" in output

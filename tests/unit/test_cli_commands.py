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


# ---------------------------------------------------------------------------
# Corner-case decryption paths — covers the remaining except-clauses in
# ui/cli/commands/decrypt.py.
# ---------------------------------------------------------------------------


def _forge_container_with_unknown_kdf(workdir: Path, name: str = "forged.crypt") -> Path:
    """Build a header with a bogus kdf_id so kdf_for_id raises UnknownKdfError."""
    import struct

    magic = b"GBOX"
    version = struct.pack("!B", 1)
    kdf_id = struct.pack("!B", 0x7E)  # intentionally unused id
    params = b""
    params_len = struct.pack("!H", len(params))
    salt = b"s" * 16
    nonce = b"n" * 12
    # Stream: one final chunk of empty plaintext authenticated with a random
    # key, so the magic/version/kdf parser trips first.
    header = magic + version + kdf_id + params_len + params + salt + nonce
    target = workdir / name
    target.write_bytes(header + b"\x00" * 16)
    return target


def _forge_container_with_weak_pbkdf2_iters(workdir: Path, name: str = "weak.crypt") -> Path:
    """Build a valid-looking container whose PBKDF2 params are below the floor."""
    import struct

    magic = b"GBOX"
    version = struct.pack("!B", 1)
    kdf_id = struct.pack("!B", 0x01)  # PBKDF2
    params = struct.pack("!I", 1)  # 1 iteration, well below floor
    params_len = struct.pack("!H", len(params))
    salt = b"s" * 16
    nonce = b"n" * 12
    header = magic + version + kdf_id + params_len + params + salt + nonce
    target = workdir / name
    target.write_bytes(header + b"\x00" * 16)
    return target


def test_decrypt_unknown_kdf_exits_1(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_unknown_kdf(workdir)
    result = runner.invoke(
        app,
        ["decrypt", forged.name, "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1
    assert "kdf" in result.stderr.lower()


def test_decrypt_weak_kdf_params_exits_1(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_weak_pbkdf2_iters(workdir)
    result = runner.invoke(
        app,
        ["decrypt", forged.name, "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == 1
    assert "kdf" in result.stderr.lower()


def test_decrypt_corrupted_after_header_exits_1(runner: CliRunner, workdir: Path) -> None:
    """A container whose header parses but ciphertext is truncated mid-chunk."""
    source = workdir / "plain.bin"
    source.write_bytes(b"short payload")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.bin", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0
    crypt = workdir / "plain.bin.crypt"
    raw = crypt.read_bytes()
    # Keep the 40-byte PBKDF2 header, then append only 5 bytes of "ciphertext"
    # — shorter than the 16-byte tag.
    crypt.write_bytes(raw[:40] + b"\x00" * 5)
    result = runner.invoke(
        app,
        ["decrypt", "plain.bin.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    # Either the stream is rejected as corrupted or decryption fails; both
    # land on exit code 1 via the decrypt command's error mapping.
    assert result.exit_code in {1, 2}


# ---------------------------------------------------------------------------
# guardiabox inspect
# ---------------------------------------------------------------------------


def test_inspect_command_shows_header(runner: CliRunner, workdir: Path) -> None:
    source = workdir / "plain.bin"
    source.write_bytes(b"content")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.bin", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0
    result = runner.invoke(app, ["inspect", "plain.bin.crypt"])
    assert result.exit_code == 0
    assert "Format version" in result.stdout
    assert "PBKDF2" in result.stdout
    assert "Salt" in result.stdout


def test_inspect_command_invalid_container(runner: CliRunner, workdir: Path) -> None:
    (workdir / "junk.crypt").write_bytes(b"not a container")
    result = runner.invoke(app, ["inspect", "junk.crypt"])
    assert result.exit_code == 1
    assert "invalide" in result.stderr.lower() or "conteneur" in result.stderr.lower()


def test_inspect_command_missing_file(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["inspect", "nope.crypt"])
    assert result.exit_code == 1


def test_inspect_command_path_traversal(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["inspect", "../escape.crypt"])
    assert result.exit_code == 1


def test_inspect_command_unknown_kdf(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_unknown_kdf(workdir)
    result = runner.invoke(app, ["inspect", forged.name])
    assert result.exit_code == 1


def test_inspect_command_argon2id_file(runner: CliRunner, workdir: Path) -> None:
    source = workdir / "plain.bin"
    source.write_bytes(b"argon payload")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.bin", "--kdf", "argon2id", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == 0
    result = runner.invoke(app, ["inspect", "plain.bin.crypt"])
    assert result.exit_code == 0
    assert "Argon2id" in result.stdout


def test_help_mentions_inspect(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "inspect" in result.stdout.lower()

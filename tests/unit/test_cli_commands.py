"""In-process tests of the Typer CLI commands.

The integration suite exercises the full subprocess launch path; this file
additionally drives the Typer app with :class:`typer.testing.CliRunner` so
coverage tooling can see the command implementations.

Exit-code expectations follow :class:`guardiabox.ui.cli.io.ExitCode` which
aligns with ``docs/specs/000-cli/plan.md``:

* ``0`` success
* ``1`` generic
* ``2`` wrong password / anti-oracle decrypt failure
* ``3`` path refused / file not found
* ``64`` usage error
* ``65`` data error (malformed container, unknown KDF, weak params)
"""

from __future__ import annotations

from pathlib import Path
import struct

import pytest
from typer.testing import CliRunner

from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="workdir")
def _workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Forged-container helpers
# ---------------------------------------------------------------------------


def _forge_container_with_unknown_kdf(workdir: Path, name: str = "forged.crypt") -> Path:
    """Build a header with a bogus kdf_id so kdf_for_id raises UnknownKdfError."""
    magic = b"GBOX"
    version = struct.pack("!B", 1)
    kdf_id = struct.pack("!B", 0x7E)  # intentionally unused id
    params = b""
    params_len = struct.pack("!H", len(params))
    salt = b"s" * 16
    nonce = b"n" * 12
    header = magic + version + kdf_id + params_len + params + salt + nonce
    target = workdir / name
    target.write_bytes(header + b"\x00" * 16)
    return target


def _forge_container_with_weak_pbkdf2_iters(workdir: Path, name: str = "weak.crypt") -> Path:
    """Build a valid-looking container whose PBKDF2 params are below the floor."""
    magic = b"GBOX"
    version = struct.pack("!B", 1)
    kdf_id = struct.pack("!B", 0x01)  # PBKDF2
    params = struct.pack("!I", 1)  # 1 iteration, well below the 600 000 floor
    params_len = struct.pack("!H", len(params))
    salt = b"s" * 16
    nonce = b"n" * 12
    header = magic + version + kdf_id + params_len + params + salt + nonce
    target = workdir / name
    target.write_bytes(header + b"\x00" * 16)
    return target


# ---------------------------------------------------------------------------
# Version + help
# ---------------------------------------------------------------------------


def test_version_flag(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == ExitCode.OK
    assert "guardiabox" in result.stdout.lower()


def test_help_mentions_commands(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == ExitCode.OK
    output = result.stdout.lower()
    assert "encrypt" in output
    assert "decrypt" in output
    assert "inspect" in output


# ---------------------------------------------------------------------------
# Encrypt happy path
# ---------------------------------------------------------------------------


def test_encrypt_file_then_decrypt(runner: CliRunner, workdir: Path) -> None:
    source = workdir / "plain.txt"
    source.write_bytes(b"hello world inline")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK, enc.stderr
    assert (workdir / "plain.txt.crypt").exists()

    dec = runner.invoke(
        app,
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert dec.exit_code == ExitCode.OK, dec.stderr
    assert (workdir / "plain.txt.decrypt").read_bytes() == b"hello world inline"


def test_encrypt_message_then_decrypt_stdout(runner: CliRunner, workdir: Path) -> None:
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
    assert enc.exit_code == ExitCode.OK, enc.stderr

    # --stdout is the new canonical flag; --message remains as an alias.
    for flag in ("--stdout", "-m", "--message"):
        dec = runner.invoke(
            app,
            ["decrypt", "msg.crypt", flag, "--password-stdin"],
            input=f"{STRONG_PASSWORD}\n",
        )
        assert dec.exit_code == ExitCode.OK, dec.stderr
        assert dec.stdout == "inline payload"


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
    assert enc.exit_code == ExitCode.OK, enc.stderr
    dec = runner.invoke(
        app,
        ["decrypt", "data.bin.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert dec.exit_code == ExitCode.OK


# ---------------------------------------------------------------------------
# Encrypt error paths
# ---------------------------------------------------------------------------


def test_encrypt_requires_path_or_message(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["encrypt", "--password-stdin"], input=f"{STRONG_PASSWORD}\n")
    assert result.exit_code == ExitCode.USAGE
    assert "--message" in result.stderr or "chemin" in result.stderr.lower()


def test_encrypt_weak_password_exits_generic(runner: CliRunner, workdir: Path) -> None:
    (workdir / "plain.txt").write_bytes(b"x")
    result = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input="weak\n",
    )
    assert result.exit_code == ExitCode.GENERIC
    assert "faible" in result.stderr.lower()


def test_encrypt_path_traversal_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "../escape.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE
    assert "refus" in result.stderr.lower() or "chemin" in result.stderr.lower()


def test_encrypt_missing_file_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "missing.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_encrypt_message_requires_output(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["encrypt", "--message", "payload", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.USAGE
    assert "output" in result.stderr.lower() or "-o" in result.stderr


# ---------------------------------------------------------------------------
# Decrypt error paths — anti-oracle and data-error distinctions
# ---------------------------------------------------------------------------


def test_decrypt_wrong_password_exits_2(runner: CliRunner, workdir: Path) -> None:
    (workdir / "plain.txt").write_bytes(b"secret")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.txt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK, enc.stderr
    result = runner.invoke(
        app,
        ["decrypt", "plain.txt.crypt", "--password-stdin"],
        input="Another_But_Strong_Password_42!\n",  # pragma: allowlist secret
    )
    assert result.exit_code == ExitCode.AUTH_FAILED


def test_decrypt_missing_file_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["decrypt", "nope.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_decrypt_invalid_container_exits_65(runner: CliRunner, workdir: Path) -> None:
    bad = workdir / "bad.crypt"
    bad.write_bytes(b"this is not a gbox container")
    result = runner.invoke(
        app,
        ["decrypt", "bad.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.DATA_ERROR
    assert "conteneur" in result.stderr.lower() or "invalid" in result.stderr.lower()


def test_decrypt_path_traversal_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(
        app,
        ["decrypt", "../escape.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_decrypt_unknown_kdf_exits_65(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_unknown_kdf(workdir)
    result = runner.invoke(
        app,
        ["decrypt", forged.name, "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.DATA_ERROR
    assert "kdf" in result.stderr.lower()


def test_decrypt_weak_kdf_params_exits_65(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_weak_pbkdf2_iters(workdir)
    result = runner.invoke(
        app,
        ["decrypt", forged.name, "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert result.exit_code == ExitCode.DATA_ERROR
    assert "kdf" in result.stderr.lower()


def test_decrypt_corrupted_after_header_exits_data_or_auth(
    runner: CliRunner, workdir: Path
) -> None:
    """A container whose header parses but ciphertext is truncated mid-chunk."""
    source = workdir / "plain.bin"
    source.write_bytes(b"short payload")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.bin", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK
    crypt = workdir / "plain.bin.crypt"
    raw = crypt.read_bytes()
    # Keep the 40-byte PBKDF2 header, then append only 5 bytes of ciphertext —
    # shorter than the 16-byte tag. That tears at the decoder.
    crypt.write_bytes(raw[:40] + b"\x00" * 5)
    result = runner.invoke(
        app,
        ["decrypt", "plain.bin.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    # Either the stream is rejected as corrupted (data error 65) or
    # decryption fails authentication (2) — both are acceptable for a
    # post-header tear. The important property is that the CLI never exits 0.
    assert result.exit_code in {ExitCode.DATA_ERROR, ExitCode.AUTH_FAILED}


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
    assert enc.exit_code == ExitCode.OK
    result = runner.invoke(app, ["inspect", "plain.bin.crypt"])
    assert result.exit_code == ExitCode.OK
    assert "Format version" in result.stdout
    assert "PBKDF2" in result.stdout
    assert "Salt" in result.stdout


def test_inspect_command_invalid_container_exits_65(runner: CliRunner, workdir: Path) -> None:
    (workdir / "junk.crypt").write_bytes(b"not a container")
    result = runner.invoke(app, ["inspect", "junk.crypt"])
    assert result.exit_code == ExitCode.DATA_ERROR
    assert "invalide" in result.stderr.lower() or "conteneur" in result.stderr.lower()


def test_inspect_command_missing_file_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["inspect", "nope.crypt"])
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_inspect_command_path_traversal_exits_3(runner: CliRunner, workdir: Path) -> None:
    result = runner.invoke(app, ["inspect", "../escape.crypt"])
    assert result.exit_code == ExitCode.PATH_OR_FILE


def test_inspect_command_unknown_kdf_exits_65(runner: CliRunner, workdir: Path) -> None:
    forged = _forge_container_with_unknown_kdf(workdir)
    result = runner.invoke(app, ["inspect", forged.name])
    assert result.exit_code == ExitCode.DATA_ERROR


def test_inspect_command_argon2id_file(runner: CliRunner, workdir: Path) -> None:
    source = workdir / "plain.bin"
    source.write_bytes(b"argon payload")
    enc = runner.invoke(
        app,
        ["encrypt", "plain.bin", "--kdf", "argon2id", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK
    result = runner.invoke(app, ["inspect", "plain.bin.crypt"])
    assert result.exit_code == ExitCode.OK
    assert "Argon2id" in result.stdout

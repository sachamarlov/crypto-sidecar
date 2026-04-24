"""Anti-oracle tests for ``guardiabox decrypt``.

The spec 002 acceptance criterion is that **an attacker observing the CLI's
output cannot distinguish wrong-password from tampered-ciphertext**. The
failing command must emit the exact same stderr bytes and exit code in
both cases. If a refactor accidentally adds details from the exception
(which would differ between ``DecryptionError`` and ``IntegrityError``),
this test catches it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.ui.cli.io import ANTI_ORACLE_MESSAGE, ExitCode
from guardiabox.ui.cli.main import app

STRONG_PASSWORD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.fixture(name="runner")
def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(name="workdir")
def _workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _encrypt_sample(runner: CliRunner, workdir: Path) -> Path:
    """Encrypt a small sample file and return the path of the resulting .crypt."""
    source = workdir / "sample.bin"
    source.write_bytes(b"secret content used for anti-oracle tests")
    enc = runner.invoke(
        app,
        ["encrypt", "sample.bin", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )
    assert enc.exit_code == ExitCode.OK, enc.stderr
    return workdir / "sample.bin.crypt"


def test_wrong_password_and_tampered_chunk_share_exact_stderr(
    runner: CliRunner, workdir: Path
) -> None:
    """Anti-oracle: bytes on stderr must be identical in both failure modes."""
    crypt = _encrypt_sample(runner, workdir)

    wrong_pwd = runner.invoke(
        app,
        ["decrypt", "sample.bin.crypt", "--password-stdin"],
        input="A_Different_Strong_Password_42!\n",  # pragma: allowlist secret
    )

    # Flip the last byte of the ciphertext chunk (before the tag) to trigger
    # an AES-GCM InvalidTag → our DecryptionError with the correct password.
    raw = bytearray(crypt.read_bytes())
    raw[-1] ^= 0x01
    crypt.write_bytes(bytes(raw))

    tampered = runner.invoke(
        app,
        ["decrypt", "sample.bin.crypt", "--password-stdin"],
        input=f"{STRONG_PASSWORD}\n",
    )

    # Both paths must exit with the same code and render the exact same
    # stderr text — byte-for-byte.
    assert wrong_pwd.exit_code == ExitCode.AUTH_FAILED
    assert tampered.exit_code == ExitCode.AUTH_FAILED
    assert wrong_pwd.stderr == tampered.stderr
    assert ANTI_ORACLE_MESSAGE in wrong_pwd.stderr


def test_anti_oracle_message_constant_is_stable() -> None:
    """Guard against someone accidentally moving the anti-oracle string.

    The constant is part of the CLI's behavioural contract — locking its
    value in a test turns any unintentional rewording into a signal.
    """
    assert ANTI_ORACLE_MESSAGE == (
        "Échec du déchiffrement : mot de passe incorrect ou données altérées."
    )


def test_wrong_password_does_not_create_decrypt_file(runner: CliRunner, workdir: Path) -> None:
    """No .decrypt file must linger after a failed decryption."""
    crypt = _encrypt_sample(runner, workdir)
    result = runner.invoke(
        app,
        ["decrypt", "sample.bin.crypt", "--password-stdin"],
        input="A_Different_Strong_Password_42!\n",  # pragma: allowlist secret
    )
    assert result.exit_code == ExitCode.AUTH_FAILED
    assert not (workdir / "sample.bin.decrypt").exists()
    # And the original .crypt is left intact.
    assert crypt.exists()

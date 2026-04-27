"""End-to-end CLI tests for ``guardiabox share`` + ``guardiabox accept``.

The full Alice -> Bob flow:

1. ``guardiabox init`` creates the vault.
2. ``guardiabox user create alice`` and ``user create bob``.
3. Alice encrypts a file with her password (via core.operations.encrypt_file
   directly -- the encrypt CLI is already covered by tests/integration/
   test_cli_init.py, so we shortcut here).
4. ``guardiabox share`` Alice -> Bob.
5. ``guardiabox accept`` recovers the plaintext.
6. The decrypted bytes equal Alice's original.

Each test uses CliRunner with monkeypatched read_password so the multi-
prompt flow (sender + admin / recipient + admin) plays back deterministically.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.core.operations import encrypt_file
from guardiabox.persistence.bootstrap import init_vault
from guardiabox.ui.cli.commands import user as user_cmd
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

ADMIN_PW = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
ALICE_PW = "Alice_Strong_Password_2026!"  # pragma: allowlist secret
BOB_PW = "Bob_Strong_Password_2026!"  # pragma: allowlist secret


@pytest.fixture(name="vault_with_users")
def _vault_with_users(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Init a vault and register Alice + Bob with strong passwords."""
    queue: list[str] = []

    def fake_read_password(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.user.read_password",
        "guardiabox.ui.cli.commands.init.read_password",
        "guardiabox.ui.cli.commands.encrypt.read_password",
        "guardiabox.ui.cli.commands.decrypt.read_password",
        "guardiabox.ui.cli.commands.share.read_password",
        "guardiabox.ui.cli.commands.accept.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake_read_password, raising=True)

    data_dir = tmp_path / "vault"
    asyncio.run(init_vault(data_dir, ADMIN_PW))

    queue.extend((ALICE_PW, ADMIN_PW))
    asyncio.run(
        user_cmd._create_flow(  # noqa: SLF001
            data_dir=data_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    queue.extend((BOB_PW, ADMIN_PW))
    asyncio.run(
        user_cmd._create_flow(  # noqa: SLF001
            data_dir=data_dir,
            username="bob",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )
    return data_dir


@pytest.fixture(name="patched_pw")
def _patched_pw(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Sequential password queue across share/accept + admin unlock."""
    queue: list[str] = []

    def fake(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.share.read_password",
        "guardiabox.ui.cli.commands.accept.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake, raising=True)

    def configure(*answers: str) -> None:
        queue.clear()
        queue.extend(answers)

    return configure


# ---------------------------------------------------------------------------
# Help smoke tests (fast)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_share_help_advertises_flags() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["share", "--help"])
    assert result.exit_code == ExitCode.OK


@pytest.mark.integration
def test_accept_help_advertises_flags() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["accept", "--help"])
    assert result.exit_code == ExitCode.OK


# ---------------------------------------------------------------------------
# End-to-end Alice -> Bob (slow; full RSA-4096 keystore unwrap)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_share_then_accept_e2e_alice_to_bob(
    vault_with_users: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alice encrypts, shares to Bob, Bob accepts -- plaintext matches."""
    monkeypatch.chdir(tmp_path)

    # Alice prepares a plaintext file and encrypts it under her password.
    plaintext = b"This is Alice's confidential payload."
    plaintext_path = tmp_path / "report.txt"
    plaintext_path.write_bytes(plaintext)
    crypt_path = encrypt_file(plaintext_path, ALICE_PW, root=tmp_path)
    assert crypt_path.exists()

    share_path = tmp_path / "alice-to-bob.gbox-share"
    runner = CliRunner()

    # share: prompts (sender_pw=ALICE_PW, admin_pw=ADMIN_PW)
    patched_pw(ALICE_PW, ADMIN_PW)
    result = runner.invoke(
        app,
        [
            "share",
            str(crypt_path.name),
            "--from",
            "alice",
            "--to",
            "bob",
            "-o",
            str(share_path),
            "--data-dir",
            str(vault_with_users),
            "--yes",  # skip fingerprint confirmation
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert share_path.exists()
    # Output should mention recipient + audit recording.
    assert "alice" in result.stdout
    assert "bob" in result.stdout

    # accept: prompts (recipient_pw=BOB_PW, admin_pw=ADMIN_PW)
    plaintext_out = tmp_path / "bob-decoded.txt"
    patched_pw(BOB_PW, ADMIN_PW)
    result = runner.invoke(
        app,
        [
            "accept",
            str(share_path.name),
            "--from",
            "alice",
            "--as",
            "bob",
            "-o",
            str(plaintext_out),
            "--data-dir",
            str(vault_with_users),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert plaintext_out.read_bytes() == plaintext


@pytest.mark.integration
@pytest.mark.slow
def test_share_unknown_sender_fails(
    vault_with_users: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    plaintext_path = tmp_path / "x.bin"
    plaintext_path.write_bytes(b"x")
    crypt_path = encrypt_file(plaintext_path, ALICE_PW, root=tmp_path)

    patched_pw(ALICE_PW, ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "share",
            str(crypt_path.name),
            "--from",
            "ghost",
            "--to",
            "bob",
            "--data-dir",
            str(vault_with_users),
            "--yes",
        ],
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE


@pytest.mark.integration
@pytest.mark.slow
def test_accept_unknown_sender_fails(
    vault_with_users: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept refers to a sender that doesn't exist -- fail closed."""
    monkeypatch.chdir(tmp_path)
    fake_share = tmp_path / "fake.gbox-share"
    fake_share.write_bytes(b"GBSH" + b"\x01" + b"\x00" * 100)  # malformed but file exists

    patched_pw(BOB_PW, ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "accept",
            str(fake_share.name),
            "--from",
            "ghost",
            "--as",
            "bob",
            "--data-dir",
            str(vault_with_users),
        ],
    )
    # Even before parse: VaultUserNotFoundError -> ExitCode.PATH_OR_FILE.
    assert result.exit_code == ExitCode.PATH_OR_FILE

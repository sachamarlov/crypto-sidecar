"""Integration tests for ``guardiabox secure-delete --method crypto-erase``.

Phase B2 (spec 004 follow-up). Validates the metadata-erase + ciphertext
overwrite + audit attribution flow end-to-end.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from guardiabox.core.operations import encrypt_file
from guardiabox.persistence.bootstrap import init_vault, vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import UserRepository, VaultItemRepository
from guardiabox.security.vault_admin import derive_admin_key, read_admin_config
from guardiabox.ui.cli.commands import user as user_cmd
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

ADMIN_PW = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
ALICE_PW = "Alice_Strong_Password_2026!"  # pragma: allowlist secret


@pytest.fixture(name="vault_with_alice_item")
def _vault_with_alice_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    """Init vault, create Alice, encrypt a file as Alice (creates vault_items row).

    Returns (data_dir, crypt_path).
    """
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
        "guardiabox.ui.cli.commands.secure_delete.read_password",
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

    # Encrypt a file as Alice so a vault_items row exists.
    plaintext_path = tmp_path / "secret.txt"
    plaintext_path.write_bytes(b"Alice's confidential payload to be erased.")
    crypt_path = encrypt_file(plaintext_path, ALICE_PW, root=tmp_path)

    # Manually persist the vault_items row (the encrypt CLI flow does this
    # via --vault-user; we replicate it here so the test focuses on the
    # crypto-erase teardown).
    queue.extend([])  # reset

    async def _seed_row() -> None:
        config = read_admin_config(vault_paths(data_dir).admin_config)
        admin_key = derive_admin_key(config, ADMIN_PW)
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(data_dir).db}")
        try:
            async with session_scope(engine) as session:
                user_repo = UserRepository(session, admin_key)
                alice = await user_repo.get_by_username("alice")
                assert alice is not None
                item_repo = VaultItemRepository(session, admin_key)
                await item_repo.create(
                    item_id="01HVAULTITEMTESTABCDEF0001",
                    owner_user_id=alice.id,
                    filename=crypt_path.name,
                    original_path=str(plaintext_path),
                    container_path=str(crypt_path),
                    ciphertext_sha256=b"\x42" * 32,
                    ciphertext_size=crypt_path.stat().st_size,
                    kdf_id=1,
                )
        finally:
            await engine.dispose()

    asyncio.run(_seed_row())
    return data_dir, crypt_path


@pytest.fixture(name="patched_pw")
def _patched_pw(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    queue: list[str] = []

    def fake(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.secure_delete.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake, raising=True)

    def configure(*answers: str) -> None:
        queue.clear()
        queue.extend(answers)

    return configure


# ---------------------------------------------------------------------------
# Round-trip: crypto-erase removes the row and the .crypt
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_crypto_erase_removes_row_and_unlinks_crypt(
    vault_with_alice_item: tuple[Path, Path],
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir, crypt_path = vault_with_alice_item
    monkeypatch.chdir(tmp_path)

    patched_pw(ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "secure-delete",
            crypt_path.name,
            "--method",
            "crypto-erase",
            "--vault-user",
            "alice",
            "--data-dir",
            str(data_dir),
            "--no-confirm",
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr

    # Ciphertext file is unlinked.
    assert not crypt_path.exists()

    # vault_items row is deleted.
    paths = vault_paths(data_dir)

    async def _check() -> tuple[int, int]:
        engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
        try:
            async with session_scope(engine) as session:
                row_count = (
                    await session.execute(text("SELECT COUNT(*) FROM vault_items"))
                ).scalar_one()
                audit_count = (
                    await session.execute(
                        text("SELECT COUNT(*) FROM audit_log WHERE action = 'file.secure_delete'")
                    )
                ).scalar_one()
                return int(row_count), int(audit_count)
        finally:
            await engine.dispose()

    items_remaining, audit_rows = asyncio.run(_check())
    assert items_remaining == 0
    assert audit_rows == 1


# ---------------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_crypto_erase_without_vault_user_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--method crypto-erase without --vault-user must exit USAGE."""
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "stray.crypt"
    target.write_bytes(b"GBOX" + b"\x00" * 100)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "secure-delete",
            "stray.crypt",
            "--method",
            "crypto-erase",
            "--no-confirm",
        ],
    )
    assert result.exit_code == ExitCode.USAGE
    # File must still exist -- we rejected before the overwrite branch.
    assert target.exists()


@pytest.mark.integration
@pytest.mark.slow
def test_crypto_erase_unknown_filename_raises_key_not_found(
    vault_with_alice_item: tuple[Path, Path],
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A .crypt that has no vault_items row must surface KeyNotFoundError."""
    data_dir, _ = vault_with_alice_item
    monkeypatch.chdir(tmp_path)

    # New crypt that was never registered in the vault DB.
    plaintext = tmp_path / "stray.txt"
    plaintext.write_bytes(b"stray")
    crypt = encrypt_file(plaintext, ALICE_PW, root=tmp_path)

    patched_pw(ADMIN_PW)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "secure-delete",
            crypt.name,
            "--method",
            "crypto-erase",
            "--vault-user",
            "alice",
            "--data-dir",
            str(data_dir),
            "--no-confirm",
        ],
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE
    # Stray .crypt must not be unlinked when KeyNotFoundError fires (the
    # overwrite has not yet run when the lookup fails).
    assert crypt.exists()


# ---------------------------------------------------------------------------
# Doctor --report-ssd smoke
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_doctor_report_ssd_emits_verdict(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "doctor",
            "--report-ssd",
            "--data-dir",
            str(tmp_path / "vault"),
        ],
    )
    assert result.exit_code == ExitCode.OK
    assert "Type de support" in result.stdout


# ---------------------------------------------------------------------------
# Help smoke test for the extended secure-delete surface
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_secure_delete_help_lists_crypto_erase_method() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["secure-delete", "--help"])
    assert result.exit_code == ExitCode.OK
    flat = " ".join(result.stdout.split())
    assert "crypto-erase" in flat or "crypto" in flat

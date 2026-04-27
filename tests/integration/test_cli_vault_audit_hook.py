"""Integration tests for the encrypt/decrypt vault audit hook (T-000mu.13).

When the user passes ``--vault-user <name>`` to ``encrypt`` or
``decrypt``, the CLI should:

* Run the underlying crypto operation as it would standalone (the
  ``.crypt`` payload is identical -- this is opt-in observability,
  not a new crypto path).
* Open the vault, look up the user by HMAC index, append a
  ``file.encrypt`` / ``file.decrypt`` audit row, and (for encrypt)
  persist a ``vault_items`` record.

We exercise the CliRunner path so coverage tracks the new flag plumbing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardiabox.persistence.bootstrap import init_vault, vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import AuditRepository, VaultItemRepository
from guardiabox.security.vault_admin import derive_admin_key, read_admin_config
from guardiabox.ui.cli._vault_audit import VaultUserNotFoundError
from guardiabox.ui.cli.commands import user as user_cmd
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

ADMIN_PW = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
USER_PW = "Different_Horse_Battery_Staple_42!"  # pragma: allowlist secret


@pytest.fixture(name="vault_with_alice")
def _vault_with_alice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Init a vault and create a user 'alice' inside it."""
    queue: list[str] = [USER_PW, ADMIN_PW]

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
    ]
    for target in targets:
        monkeypatch.setattr(target, fake_read_password, raising=True)

    data_dir = tmp_path / "vault"
    asyncio.run(init_vault(data_dir, ADMIN_PW))

    asyncio.run(
        user_cmd._create_flow(
            data_dir=data_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )
    return data_dir


@pytest.fixture(name="patched_pw")
def _patched_pw(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Sequential password queue across encrypt/decrypt + admin unlock."""
    queue: list[str] = []

    def fake(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        return queue.pop(0)

    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.user.read_password",
        "guardiabox.ui.cli.commands.init.read_password",
        "guardiabox.ui.cli.commands.encrypt.read_password",
        "guardiabox.ui.cli.commands.decrypt.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake, raising=True)

    def configure(*answers: str) -> None:
        queue.clear()
        queue.extend(answers)

    return configure


# ---------------------------------------------------------------------------
# encrypt --vault-user
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_encrypt_with_vault_user_records_audit_and_vault_item(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The audit log holds file.encrypt; vault_items holds the new row."""
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "report.bin"
    source.write_bytes(b"sensitive payload")

    # read_password is monkeypatched: one call per logical prompt
    # (the typer-level confirm loop is collapsed into a single fake
    # call). So queue = [user_pw_for_encrypt, admin_pw_for_audit_hook].
    patched_pw(USER_PW, ADMIN_PW)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "encrypt",
            "report.bin",
            "--vault-user",
            "alice",
            "--data-dir",
            str(vault_with_alice),
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert "Audit" in result.stdout
    assert "alice" in result.stdout

    # Inspect the DB: one file.encrypt audit row + one vault_items row.
    config = read_admin_config(vault_paths(vault_with_alice).admin_config)
    admin_key = derive_admin_key(config, ADMIN_PW)

    async def _read() -> tuple[int, int]:
        from guardiabox.persistence.repositories import UserRepository

        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_with_alice).db}")
        try:
            async with session_scope(engine) as session:
                user_repo = UserRepository(session, admin_key)
                alice = await user_repo.get_by_username("alice")
                assert alice is not None

                audit_repo = AuditRepository(session, admin_key)
                rows = await audit_repo.list_filtered(action="file.encrypt")

                items = VaultItemRepository(session, admin_key)
                item = await items.find_by_filename(
                    owner_user_id=alice.id,
                    filename="report.bin.crypt",
                )
                return len(rows), 1 if item is not None else 0
        finally:
            await engine.dispose()

    n_audit, n_items = asyncio.run(_read())
    assert n_audit == 1
    assert n_items == 1


@pytest.mark.integration
@pytest.mark.slow
def test_encrypt_with_unknown_vault_user_exits_path_or_file(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "x.bin"
    source.write_bytes(b"x")

    patched_pw(USER_PW, ADMIN_PW)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "encrypt",
            "x.bin",
            "--vault-user",
            "ghost",
            "--data-dir",
            str(vault_with_alice),
        ],
    )
    assert result.exit_code == ExitCode.PATH_OR_FILE


# ---------------------------------------------------------------------------
# decrypt --vault-user
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_decrypt_with_vault_user_records_audit(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The decrypt path appends a file.decrypt audit row (no VaultItem write)."""
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "in.bin"
    source.write_bytes(b"hello")

    # First encrypt the file (no --vault-user so no audit hook runs).
    patched_pw(USER_PW)
    runner = CliRunner()
    enc_result = runner.invoke(
        app,
        ["encrypt", "in.bin", "--data-dir", str(vault_with_alice)],
    )
    assert enc_result.exit_code == ExitCode.OK, enc_result.stderr

    crypt = source.with_name(source.name + ".crypt")
    assert crypt.exists()

    # Now decrypt with --vault-user; audit hook fires.
    # decrypt prompt + audit hook prompt = 2 pops.
    patched_pw(USER_PW, ADMIN_PW)
    dec_result = runner.invoke(
        app,
        [
            "decrypt",
            "in.bin.crypt",
            "--vault-user",
            "alice",
            "--data-dir",
            str(vault_with_alice),
        ],
    )
    assert dec_result.exit_code == ExitCode.OK, dec_result.stderr
    assert "Audit" in dec_result.stdout

    config = read_admin_config(vault_paths(vault_with_alice).admin_config)
    admin_key = derive_admin_key(config, ADMIN_PW)

    async def _read() -> int:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_with_alice).db}")
        try:
            async with session_scope(engine) as session:
                repo = AuditRepository(session, admin_key)
                rows = await repo.list_filtered(action="file.decrypt")
                return len(rows)
        finally:
            await engine.dispose()

    assert asyncio.run(_read()) == 1


@pytest.mark.integration
def test_record_encrypt_unknown_user_raises_dedicated_error(
    vault_with_alice: Path,
    patched_pw: Callable[..., None],
    tmp_path: Path,
) -> None:
    """Calling the helper directly with an unknown user surfaces the typed exc."""
    from guardiabox.ui.cli._vault_audit import record_encrypt_event

    source = tmp_path / "x.bin"
    source.write_bytes(b"x")
    crypt = tmp_path / "x.bin.crypt"
    crypt.write_bytes(b"GBOX" + b"\x00" * 100)  # placeholder, hash check is local

    patched_pw(ADMIN_PW)
    with pytest.raises(VaultUserNotFoundError):
        record_encrypt_event(
            data_dir=vault_with_alice,
            password_stdin=False,
            vault_username="ghost",
            plaintext_path=source,
            container_path=crypt,
            ciphertext_sha256=b"\x00" * 32,
            kdf_id=1,
        )

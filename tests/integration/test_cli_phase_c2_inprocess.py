"""In-process tests for Phase C-2 CLI commands.

The subprocess-based suite (``test_cli_user_history_doctor.py``) is the
real end-to-end contract — it spawns the actual CLI binary, so it
covers argument parsing, Typer dispatch, asyncio teardown, and stdout
encoding the way a user sees them. But ``pytest-cov`` cannot trace
into a child process, so the new modules only show up at 25-60%
coverage even though every code path runs.

This file fills the coverage gap by driving the same async flows
**in-process** through ``asyncio.run``. The functional contract is
identical to the subprocess tests; only the way coverage is collected
differs. We keep both layers because:

* in-process: fast, traces every line, easy to monkeypatch.
* subprocess: catches argument parsing + console encoding + Typer
  bootstrap regressions the in-process layer cannot see.

We also run a couple of CliRunner-based smoke checks for the synchronous
top-level commands (``init`` arg parsing, ``doctor`` without
``--verify-audit``) since those run in-process by design.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from guardiabox.persistence.bootstrap import init_vault, vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.models import AuditEntry
from guardiabox.persistence.repositories import AuditRepository, UserRepository
from guardiabox.security.audit import AuditAction, append, verify
from guardiabox.security.vault_admin import (
    VaultAdminConfigMissingError,
    derive_admin_key,
    read_admin_config,
)
from guardiabox.ui.cli._session import (
    open_vault_session,
    resolve_vault_paths,
    unlock_vault,
)
from guardiabox.ui.cli.commands import (
    history as history_cmd,
    user as user_cmd,
)
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

STRONG = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
USER_PW = "Different_Horse_Battery_Staple_42!"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(name="vault_dir")
def _vault_dir(tmp_path: Path) -> Path:
    """Spin up a fresh vault in ``tmp_path`` via the real init_vault path.

    Marked slow because the PBKDF2 derivation runs at the production
    iteration count. One vault per test keeps cases isolated.
    """
    data_dir = tmp_path / "vault"
    asyncio.run(init_vault(data_dir, STRONG))
    return data_dir


@pytest.fixture(name="patched_passwords")
def _patched_passwords(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Helper to monkeypatch ``read_password`` with a queue of answers.

    Returns a configurator ``set(*answers)`` that the test calls right
    before invoking the flow. Each subsequent ``read_password`` call
    pops one answer from the queue.
    """
    queue: list[str] = []

    def fake_read_password(*, stdin: bool, confirm: bool = False, prompt: str = "") -> str:
        del stdin, confirm, prompt
        if not queue:
            raise AssertionError("read_password called more times than tests configured")
        return queue.pop(0)

    # Patch *both* the io module and every command module that imported
    # the symbol via `from ... import read_password` (Python-level
    # shallow copy, not a live reference).
    targets = [
        "guardiabox.ui.cli.io.read_password",
        "guardiabox.ui.cli._session.read_password",
        "guardiabox.ui.cli.commands.user.read_password",
        "guardiabox.ui.cli.commands.init.read_password",
    ]
    for target in targets:
        monkeypatch.setattr(target, fake_read_password, raising=True)

    def configure(*answers: str) -> None:
        queue.clear()
        queue.extend(answers)

    return configure


# ---------------------------------------------------------------------------
# _session helpers
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_resolve_vault_paths_falls_back_to_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``data_dir=None`` reads ``Settings.data_dir``."""
    home_dir = tmp_path / "fake-vault"
    monkeypatch.setenv("GUARDIABOX_DATA_DIR", str(home_dir))
    paths = resolve_vault_paths(None)
    assert paths.data_dir == home_dir.resolve()


@pytest.mark.integration
@pytest.mark.slow
def test_unlock_vault_then_open_session_yields_engine(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(STRONG)
    vault = unlock_vault(vault_dir, password_stdin=False)
    assert len(vault.admin_key) == 32

    async def _body() -> int:
        async with open_vault_session(vault_dir, password_stdin=True) as (
            v,
            session,
            engine,
        ):
            assert v.admin_key == vault.admin_key
            assert engine is not None
            repo = AuditRepository(session, v.admin_key)
            entries = await repo.all_in_order()
            return len(entries)

    patched_passwords(STRONG)
    count = asyncio.run(_body())
    assert count >= 1  # at least the SYSTEM_STARTUP genesis row


@pytest.mark.integration
def test_unlock_vault_missing_admin_config_raises(tmp_path: Path) -> None:
    """No init -> no admin config -> dedicated error class."""
    with pytest.raises(VaultAdminConfigMissingError):
        unlock_vault(tmp_path / "nope", password_stdin=True)


# ---------------------------------------------------------------------------
# init command (CliRunner -- runs in-process, no subprocess)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_init_via_cli_runner_creates_vault(
    tmp_path: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """The ``init`` Typer entry point runs end-to-end through CliRunner."""
    patched_passwords(STRONG)
    runner = CliRunner()
    data_dir = tmp_path / "vault"
    result = runner.invoke(
        app,
        ["init", "--data-dir", str(data_dir)],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    paths = vault_paths(data_dir)
    assert paths.admin_config.is_file()
    assert paths.db.is_file()


@pytest.mark.integration
@pytest.mark.slow
def test_init_refuses_re_initialisation(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """The early-exit branch in ``_dispatch`` fires when the admin file exists."""
    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["init", "--data-dir", str(vault_dir)],
    )
    assert result.exit_code == ExitCode.USAGE


@pytest.mark.integration
def test_init_kdf_choice_argon2id_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Argon2id branch of ``_build_kdf`` is reached via the enum value.

    We use the ``init`` module's enum so the entire dispatch path
    (KdfChoice -> Argon2idKdf instantiation in the function body) is
    exercised. Skipping the real KDF derivation by monkeypatching
    ``init_vault`` keeps the test fast.
    """
    captured: dict[str, Any] = {}

    async def fake_init(data_dir: Path, password: str, *, kdf: object = None) -> object:
        del password
        captured["kdf"] = kdf
        await asyncio.sleep(0)  # keep the function genuinely async
        return vault_paths(data_dir)

    monkeypatch.setattr("guardiabox.ui.cli.commands.init.init_vault", fake_init)
    monkeypatch.setattr(
        "guardiabox.ui.cli.commands.init.read_password",
        lambda *, stdin, confirm=False, prompt="": STRONG,
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["init", "--data-dir", str(tmp_path / "vault"), "--kdf", "argon2id"],
    )
    assert result.exit_code == ExitCode.OK
    from guardiabox.core.kdf import Argon2idKdf

    assert isinstance(captured["kdf"], Argon2idKdf)


# ---------------------------------------------------------------------------
# user create / list / show / delete
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_user_create_flow_persists_user_and_audits(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """``_create_flow`` adds a row + emits a USER_CREATE audit entry."""
    patched_passwords(USER_PW, STRONG)  # user pw, then admin pw

    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    # Verify side effects against the DB.
    config = read_admin_config(vault_paths(vault_dir).admin_config)
    admin_key = derive_admin_key(config, STRONG)

    async def _read() -> tuple[int, str]:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_dir).db}")
        try:
            async with session_scope(engine) as session:
                user_repo = UserRepository(session, admin_key)
                fetched = await user_repo.get_by_username("alice")
                assert fetched is not None
                username = user_repo.decrypt_username(fetched)

                audit_repo = AuditRepository(session, admin_key)
                rows = await audit_repo.list_filtered(action="user.create")
                return len(rows), username
        finally:
            await engine.dispose()

    n_create, name = asyncio.run(_read())
    assert n_create == 1
    assert name == "alice"


@pytest.mark.integration
@pytest.mark.slow
def test_user_create_flow_rejects_duplicate(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Trying to create the same username twice raises typer.Exit USAGE."""
    import typer

    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="bob",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(USER_PW, STRONG)
    with pytest.raises(typer.Exit) as info:
        asyncio.run(
            user_cmd._create_flow(
                data_dir=vault_dir,
                username="bob",
                kdf_choice=user_cmd.KdfChoice.PBKDF2,
                password_stdin=False,
            )
        )
    assert info.value.exit_code == ExitCode.USAGE


@pytest.mark.integration
@pytest.mark.slow
def test_user_list_flow_returns_dicts(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Phase E refactor: _list_flow now returns list[dict] for --format json wiring."""
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    rows = asyncio.run(user_cmd._list_flow(data_dir=vault_dir, password_stdin=False))
    assert len(rows) == 1
    assert rows[0]["username"] == "alice"
    assert "id" in rows[0]
    assert "created_at" in rows[0]
    assert "kdf_id" in rows[0]


@pytest.mark.integration
@pytest.mark.slow
def test_user_show_flow_returns_snapshot(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Phase E refactor: _show_flow now returns dict[str, Any] | None."""
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="charlie",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    snapshot = asyncio.run(
        user_cmd._show_flow(data_dir=vault_dir, username="charlie", password_stdin=False)
    )
    assert snapshot is not None
    assert snapshot["username"] == "charlie"
    assert "failed_unlock_count" in snapshot
    assert "kdf_id" in snapshot


@pytest.mark.integration
@pytest.mark.slow
def test_user_show_flow_unknown_returns_none(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(STRONG)
    snapshot = asyncio.run(
        user_cmd._show_flow(data_dir=vault_dir, username="ghost", password_stdin=False)
    )
    assert snapshot is None


@pytest.mark.integration
@pytest.mark.slow
def test_user_delete_flow_removes_user_and_audits(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="diana",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    deleted = asyncio.run(
        user_cmd._delete_flow(data_dir=vault_dir, username="diana", password_stdin=False)
    )
    assert deleted is True

    # Audit log records the delete.
    config = read_admin_config(vault_paths(vault_dir).admin_config)
    admin_key = derive_admin_key(config, STRONG)

    async def _audit_count() -> int:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_dir).db}")
        try:
            async with session_scope(engine) as session:
                repo = AuditRepository(session, admin_key)
                rows = await repo.list_filtered(action="user.delete")
                return len(rows)
        finally:
            await engine.dispose()

    assert asyncio.run(_audit_count()) == 1


@pytest.mark.integration
@pytest.mark.slow
def test_user_delete_flow_unknown_returns_false(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(STRONG)
    found = asyncio.run(
        user_cmd._delete_flow(data_dir=vault_dir, username="ghost", password_stdin=False)
    )
    assert found is False


# ---------------------------------------------------------------------------
# user create -- KDF Argon2id branch (via enum dispatch only, no real derive)
# ---------------------------------------------------------------------------


def test_user_build_kdf_argon2id() -> None:
    from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf

    pbkdf2 = user_cmd._build_kdf(user_cmd.KdfChoice.PBKDF2)
    argon2 = user_cmd._build_kdf(user_cmd.KdfChoice.ARGON2ID)
    assert isinstance(pbkdf2, Pbkdf2Kdf)
    assert isinstance(argon2, Argon2idKdf)


# ---------------------------------------------------------------------------
# history flow
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_history_flow_returns_entries_in_reverse_order(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    entries = asyncio.run(
        history_cmd._history_flow(
            data_dir=vault_dir,
            limit=10,
            user=None,
            action=None,
            password_stdin=False,
        )
    )
    actions = [e.action for e in entries]
    assert "user.create" in actions
    assert "system.startup" in actions
    # Sequence numbers strictly decreasing -- confirms reverse order.
    sequences = [e.sequence for e in entries]
    assert sequences == sorted(sequences, reverse=True)


@pytest.mark.integration
@pytest.mark.slow
def test_history_flow_filters_by_action(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="alice",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    entries = asyncio.run(
        history_cmd._history_flow(
            data_dir=vault_dir,
            limit=10,
            user=None,
            action="user.create",
            password_stdin=False,
        )
    )
    assert len(entries) == 1
    assert entries[0].action == "user.create"


@pytest.mark.integration
@pytest.mark.slow
def test_history_flow_filter_by_unknown_user_returns_empty(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Filtering on a non-existent user returns ``[]`` (not an error)."""
    patched_passwords(STRONG)
    entries = asyncio.run(
        history_cmd._history_flow(
            data_dir=vault_dir,
            limit=10,
            user="nobody",
            action=None,
            password_stdin=False,
        )
    )
    assert entries == []


@pytest.mark.integration
@pytest.mark.slow
def test_history_flow_filter_by_known_user(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="erin",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    entries = asyncio.run(
        history_cmd._history_flow(
            data_dir=vault_dir,
            limit=10,
            user="erin",
            action=None,
            password_stdin=False,
        )
    )
    # The user.create row records actor_user_id = the new user's id, so
    # filtering by username 'erin' must hit at least the create entry.
    assert any(e.action == "user.create" for e in entries)


@pytest.mark.integration
@pytest.mark.slow
def test_history_command_renders_table(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Smoke the table rendering through CliRunner -- exercises every echo line."""
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username="frank",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["history", "--data-dir", str(vault_dir), "--format", "table"],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert "user.create" in result.stdout
    assert "system.startup" in result.stdout


@pytest.mark.integration
@pytest.mark.slow
def test_history_command_renders_json(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["history", "--data-dir", str(vault_dir), "--format", "json"],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert payload, "history JSON output should not be empty"
    assert payload[0]["action"] == "system.startup"


@pytest.mark.integration
@pytest.mark.slow
def test_history_command_empty_log(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """When the log holds zero rows after a filter, table view prints "(journal vide)".

    We force this by filtering on an action that the freshly-init'ed
    vault never emits; it has only ``system.startup``.
    """
    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "history",
            "--data-dir",
            str(vault_dir),
            "--action",
            "file.share",
            "--format",
            "table",
        ],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert "journal vide" in result.stdout


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def test_doctor_command_without_verify_audit_does_not_unlock(
    tmp_path: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Plain ``doctor`` must not prompt for the password.

    We deliberately don't prime the password queue; if the command
    asked for one, the mocked ``read_password`` would raise.
    """
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["doctor", "--data-dir", str(tmp_path / "fake")],
    )
    assert result.exit_code == ExitCode.OK
    assert "absent" in result.stdout  # the DB and admin file don't exist


@pytest.mark.integration
@pytest.mark.slow
def test_doctor_verify_audit_clean_chain(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["doctor", "--verify-audit", "--data-dir", str(vault_dir)],
    )
    assert result.exit_code == ExitCode.OK, result.stderr
    assert "[OK]" in result.stdout


@pytest.mark.integration
def test_doctor_verify_audit_uninitialised_exits_config(
    tmp_path: Path,
) -> None:
    """``--verify-audit`` on an uninit-ed dir exits CONFIG_ERROR."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["doctor", "--verify-audit", "--data-dir", str(tmp_path / "missing")],
    )
    assert result.exit_code == ExitCode.CONFIG_ERROR


@pytest.mark.integration
@pytest.mark.slow
def test_doctor_verify_flow_detects_tampering(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Inject a tampered audit row, then assert ``_verify_flow`` flags it."""
    config = read_admin_config(vault_paths(vault_dir).admin_config)
    admin_key = derive_admin_key(config, STRONG)

    # Append a row whose ``entry_hash`` is wrong but ``prev_hash`` is right.
    async def _inject_bad_row() -> None:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_dir).db}")
        try:
            async with session_scope(engine) as session:
                # Get the latest entry to know the next sequence + prev_hash.
                repo = AuditRepository(session, admin_key)
                latest = await repo.latest()
                assert latest is not None
                # Manually craft a row with a deliberately broken entry_hash.
                broken = AuditEntry(
                    sequence=latest.sequence + 1,
                    timestamp=latest.timestamp,
                    actor_user_id=None,
                    action="user.unlock",
                    target_enc=None,
                    target_hmac=None,
                    metadata_enc=None,
                    prev_hash=latest.entry_hash,
                    entry_hash=b"\xde\xad" * 16,  # 32 bytes of 0xde 0xad
                )
                session.add(broken)
        finally:
            await engine.dispose()

    asyncio.run(_inject_bad_row())

    patched_passwords(STRONG)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["doctor", "--verify-audit", "--data-dir", str(vault_dir)],
    )
    assert result.exit_code == ExitCode.DATA_ERROR
    assert "[FAIL]" in result.stderr or "[FAIL]" in result.stdout


# ---------------------------------------------------------------------------
# Audit hash chain integrity (end-to-end)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.slow
def test_audit_chain_after_user_create_still_verifies(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """After every user op, the chain still verifies cleanly."""
    patched_passwords(USER_PW, STRONG)
    asyncio.run(
        user_cmd._create_flow(
            data_dir=vault_dir,
            username=f"user_{uuid4().hex[:8]}",
            kdf_choice=user_cmd.KdfChoice.PBKDF2,
            password_stdin=False,
        )
    )

    config = read_admin_config(vault_paths(vault_dir).admin_config)
    admin_key = derive_admin_key(config, STRONG)

    async def _verify() -> bool:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_dir).db}")
        try:
            async with session_scope(engine) as session:
                result = await verify(session, admin_key)
                return result.ok
        finally:
            await engine.dispose()

    assert asyncio.run(_verify()) is True


@pytest.mark.integration
@pytest.mark.slow
def test_explicit_append_writes_genesis_chain(
    vault_dir: Path,
    patched_passwords: Callable[..., None],
) -> None:
    """Appending another SYSTEM_STARTUP doesn't break the chain."""
    config = read_admin_config(vault_paths(vault_dir).admin_config)
    admin_key = derive_admin_key(config, STRONG)

    async def _append_and_verify() -> bool:
        engine = create_engine(f"sqlite+aiosqlite:///{vault_paths(vault_dir).db}")
        try:
            async with session_scope(engine) as session:
                await append(
                    session,
                    admin_key,
                    actor_user_id=None,
                    action=AuditAction.SYSTEM_STARTUP,
                    target=None,
                )
                result = await verify(session, admin_key)
                return result.ok
        finally:
            await engine.dispose()

    assert asyncio.run(_append_and_verify()) is True

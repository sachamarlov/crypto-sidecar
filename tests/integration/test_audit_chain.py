"""Integration tests for the audit log hash chain."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
import secrets

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.security.audit import (
    AUDIT_GENESIS_HASH,
    AuditAction,
    append,
    compute_entry_hash,
    verify,
)

ROOT = Path(__file__).resolve().parents[2]
VAULT_KEY = secrets.token_bytes(32)


def _alembic_config(db_path: Path) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    script_dir = ROOT / "src" / "guardiabox" / "persistence" / "migrations"
    cfg.set_main_option("script_location", str(script_dir))
    return cfg


def _run_alembic(db_path: Path) -> None:
    command.upgrade(_alembic_config(db_path), "head")


@pytest.fixture(name="engine")
async def _engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    db = tmp_path / "vault.db"
    await asyncio.to_thread(_run_alembic, db)
    engine = create_engine(f"sqlite+aiosqlite:///{db}")
    yield engine
    await engine.dispose()


# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_first_append_uses_genesis_prev_hash(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        entry = await append(
            session,
            VAULT_KEY,
            actor_user_id=None,
            action=AuditAction.SYSTEM_STARTUP,
        )
    assert entry.sequence == 1
    assert entry.prev_hash == AUDIT_GENESIS_HASH
    assert len(entry.entry_hash) == 32


@pytest.mark.integration
async def test_subsequent_appends_chain_on_previous_hash(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        e1 = await append(session, VAULT_KEY, actor_user_id=None, action=AuditAction.SYSTEM_STARTUP)
        e2 = await append(session, VAULT_KEY, actor_user_id=None, action=AuditAction.USER_CREATE)
    assert e2.sequence == e1.sequence + 1
    assert e2.prev_hash == e1.entry_hash


@pytest.mark.integration
async def test_append_with_target_and_metadata_encrypts_columns(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        entry = await append(
            session,
            VAULT_KEY,
            actor_user_id=None,
            action=AuditAction.FILE_ENCRYPT,
            target="invoice.pdf",
            metadata={"kdf": "pbkdf2", "size": "4096"},
        )
    assert entry.target_enc is not None
    assert entry.target_enc != b"invoice.pdf"
    assert entry.target_hmac is not None
    assert entry.metadata_enc is not None


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_verify_empty_log_is_ok(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        result = await verify(session, VAULT_KEY)
    assert result.ok is True
    assert result.first_bad_sequence is None
    assert result.entries_checked == 0


@pytest.mark.integration
async def test_verify_clean_chain_is_ok(engine: AsyncEngine) -> None:
    async with session_scope(engine) as session:
        for _i in range(5):
            await append(
                session,
                VAULT_KEY,
                actor_user_id=None,
                action=AuditAction.USER_UNLOCK,
            )

    async with session_scope(engine) as session:
        result = await verify(session, VAULT_KEY)
    assert result.ok is True
    assert result.entries_checked == 5


@pytest.mark.integration
async def test_verify_flags_tampered_entry(engine: AsyncEngine, tmp_path: Path) -> None:
    """Forge an out-of-band UPDATE via raw SQL; verify must point at it.

    The append-only trigger fires on the ``audit_log`` table; we
    detach and reattach via a separate sync engine so the trigger
    path is exercised in isolation when we attempt the mutation.
    """
    async with session_scope(engine) as session:
        for _i in range(3):
            await append(
                session,
                VAULT_KEY,
                actor_user_id=None,
                action=AuditAction.USER_UNLOCK,
            )

    # Attempting an UPDATE through the engine hits the SQLite trigger
    # and raises append-only. We instead drop the trigger, update,
    # then put the trigger back -- simulating an attacker with direct
    # file access that bypasses the ORM / trigger enforcement.
    from sqlalchemy import create_engine as sync_create

    db_path = engine.url.database
    sync_engine = sync_create(f"sqlite:///{db_path}")
    try:
        with sync_engine.begin() as conn:
            conn.execute(text("DROP TRIGGER audit_log_no_update"))
            conn.execute(text("UPDATE audit_log SET action = 'hacked' WHERE sequence = 2"))
            conn.execute(
                text(
                    "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
                    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
                )
            )
    finally:
        sync_engine.dispose()

    async with session_scope(engine) as session:
        result = await verify(session, VAULT_KEY)
    assert result.ok is False
    assert result.first_bad_sequence == 2


# ---------------------------------------------------------------------------
# compute_entry_hash
# ---------------------------------------------------------------------------


def test_compute_entry_hash_is_deterministic() -> None:
    ts = datetime(2026, 4, 24, 12, 0, 0, tzinfo=UTC)
    kwargs = {
        "sequence": 1,
        "timestamp": ts,
        "actor_user_id": None,
        "action": "user.create",
        "target_enc": b"\xaa" * 16,
        "target_hmac": b"\xbb" * 32,
        "metadata_enc": None,
        "prev_hash": b"\x00" * 32,
    }
    a = compute_entry_hash(**kwargs)  # type: ignore[arg-type]
    b = compute_entry_hash(**kwargs)  # type: ignore[arg-type]
    assert a == b
    assert len(a) == 32


def test_compute_entry_hash_changes_with_every_input() -> None:
    ts = datetime(2026, 4, 24, 12, 0, 0, tzinfo=UTC)
    base = {
        "sequence": 1,
        "timestamp": ts,
        "actor_user_id": None,
        "action": "user.create",
        "target_enc": None,
        "target_hmac": None,
        "metadata_enc": None,
        "prev_hash": b"\x00" * 32,
    }
    baseline = compute_entry_hash(**base)  # type: ignore[arg-type]

    # Flip each field in turn and assert the hash changes.
    variants = [
        {**base, "sequence": 2},
        {**base, "actor_user_id": "u-2"},
        {**base, "action": "user.unlock"},
        {**base, "target_enc": b"\x01"},
        {**base, "target_hmac": b"\x02" * 32},
        {**base, "metadata_enc": b"\x03"},
        {**base, "prev_hash": b"\xff" * 32},
    ]
    for v in variants:
        h = compute_entry_hash(**v)  # type: ignore[arg-type]
        assert h != baseline, f"hash must change when {set(v) - set(base)} changes"


def test_compute_entry_hash_rejects_wrong_prev_hash_length() -> None:
    ts = datetime(2026, 4, 24, tzinfo=UTC)
    with pytest.raises(ValueError, match="prev_hash"):
        compute_entry_hash(
            sequence=1,
            timestamp=ts,
            actor_user_id=None,
            action="a",
            target_enc=None,
            target_hmac=None,
            metadata_enc=None,
            prev_hash=b"\x00" * 10,
        )

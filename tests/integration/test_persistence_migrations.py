"""Integration tests for the Alembic initial migration.

Runs ``alembic upgrade head`` against a file-backed SQLite DB and
verifies:

* The four tables exist afterwards.
* The append-only triggers reject UPDATE and DELETE on ``audit_log``.
* ``alembic downgrade base`` tears everything down cleanly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(db_path: Path) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    script_dir = ROOT / "src" / "guardiabox" / "persistence" / "migrations"
    cfg.set_main_option("script_location", str(script_dir))
    return cfg


@pytest.mark.integration
def test_upgrade_head_creates_four_tables(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    cfg = _alembic_config(db)
    command.upgrade(cfg, "head")

    sync_engine = create_engine(f"sqlite:///{db}")
    try:
        inspector = inspect(sync_engine)
        names = set(inspector.get_table_names())
        assert {"users", "vault_items", "shares", "audit_log"}.issubset(names)
    finally:
        sync_engine.dispose()


def _insert_one_audit_row(db: Path) -> None:
    """Drop a single row into audit_log so the triggers have something to act on."""
    sync_engine = create_engine(f"sqlite:///{db}")
    with sync_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log "
                "(timestamp, actor_user_id, action, target_enc, target_hmac, "
                " metadata_enc, prev_hash, entry_hash) "
                "VALUES (:ts, NULL, 'test', NULL, NULL, NULL, :h, :h)"
            ),
            {"ts": datetime.now(UTC).isoformat(), "h": b"\x00" * 32},
        )
    sync_engine.dispose()


def _try_mutate(db: Path, stmt: str) -> None:
    """Open a sync engine and run the statement. Exceptions propagate."""
    sync_engine = create_engine(f"sqlite:///{db}")
    try:
        with sync_engine.begin() as conn:
            conn.execute(text(stmt))
    finally:
        sync_engine.dispose()


@pytest.mark.integration
def test_audit_log_rejects_update(tmp_path: Path) -> None:
    """UPDATE on any audit_log row must raise 'audit_log is append-only'."""
    db = tmp_path / "vault.db"
    command.upgrade(_alembic_config(db), "head")
    _insert_one_audit_row(db)

    from sqlalchemy.exc import IntegrityError, OperationalError

    with pytest.raises((IntegrityError, OperationalError), match="append-only"):
        _try_mutate(db, "UPDATE audit_log SET action = 'hacked' WHERE sequence = 1")


@pytest.mark.integration
def test_audit_log_rejects_delete(tmp_path: Path) -> None:
    """DELETE on any audit_log row must raise 'audit_log is append-only'."""
    db = tmp_path / "vault.db"
    command.upgrade(_alembic_config(db), "head")
    _insert_one_audit_row(db)

    from sqlalchemy.exc import IntegrityError, OperationalError

    with pytest.raises((IntegrityError, OperationalError), match="append-only"):
        _try_mutate(db, "DELETE FROM audit_log WHERE sequence = 1")


@pytest.mark.integration
def test_downgrade_base_removes_all_tables(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    cfg = _alembic_config(db)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    sync_engine = create_engine(f"sqlite:///{db}")
    try:
        inspector = inspect(sync_engine)
        names = set(inspector.get_table_names())
        # Only alembic_version is left after downgrade.
        remaining = names - {"alembic_version"}
        assert remaining == set(), f"unexpected tables after downgrade: {remaining}"
    finally:
        sync_engine.dispose()

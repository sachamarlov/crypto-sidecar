"""SQLAlchemy 2.0 async engine + session factory.

Phase C runs on a single async driver path (``sqlite+aiosqlite``) paired
with column-level AES-GCM encryption (see
:func:`guardiabox.core.crypto.encrypt_column`). This keeps the filename
and audit-metadata floor equal on every supported platform — Linux,
Windows, and macOS — without dragging in a platform-specific native
driver. ADR-0011 documents the original SQLCipher-or-fallback strategy;
the async codebase settled on the fallback path for simplicity and
uniformity. An opt-in SQLCipher path may land later behind a dedicated
extra if concrete demand shows up.

The module exposes two primitives:

* :func:`create_engine` — build an :class:`AsyncEngine` pointing at the
  given SQLite URL.
* :func:`session_scope` — async context manager that yields an
  :class:`AsyncSession`, commits on clean exit, rolls back on
  exception, and closes on both paths.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import importlib.util

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from guardiabox.logging import get_logger

__all__ = ["create_engine", "session_scope", "sqlcipher_available"]

_log = get_logger(__name__)


def sqlcipher_available() -> bool:
    """Return True when ``sqlcipher3`` is importable on this host.

    Currently purely informational: the async engine always goes through
    ``aiosqlite`` (see module docstring). Kept as a public probe so the
    CLI ``doctor`` command can report it.
    """
    return importlib.util.find_spec("sqlcipher3") is not None


def create_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    """Build an :class:`AsyncEngine` for ``database_url``.

    Args:
        database_url: Must use the ``sqlite+aiosqlite`` driver — the
            only async driver this module supports today. Examples:
            ``sqlite+aiosqlite:///:memory:`` for tests,
            ``sqlite+aiosqlite:////abs/path/vault.db`` in prod.
        echo: Forwarded to SQLAlchemy ``echo=`` for SQL tracing; keep
            ``False`` in production so the audit log stays the source
            of truth.

    Returns:
        A fresh :class:`AsyncEngine`. The caller owns its lifecycle and
        must call ``await engine.dispose()`` when done.
    """
    if not database_url.startswith("sqlite+aiosqlite"):
        raise ValueError(
            f"database_url must use the sqlite+aiosqlite driver, got {database_url!r}. "
            "SQLCipher support is tracked as future work; see docs/ARCHITECTURE.md."
        )
    engine = create_async_engine(
        database_url,
        echo=echo,
        future=True,
        pool_pre_ping=True,
    )

    # Audit A P0-4: SQLite ships with PRAGMA foreign_keys = OFF
    # by default, so the ON DELETE CASCADE / SET NULL clauses
    # declared on every model never fire. Activate it on every new
    # connection so the cascade is enforced. The amended audit_log_
    # no_update trigger (migration 20260429_0001) tolerates the
    # SET NULL cascade on actor_user_id; every other UPDATE is still
    # rejected to preserve append-only semantics.
    @event.listens_for(engine.sync_engine, "connect")
    def _enable_foreign_keys(dbapi_conn: object, _record: object) -> None:
        cursor = dbapi_conn.cursor()  # type: ignore[attr-defined]  # DBAPI Connection
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
        finally:
            cursor.close()

    _log.debug(
        "persistence.engine.created",
        driver="aiosqlite",
        sqlcipher_available=sqlcipher_available(),
    )
    return engine


@asynccontextmanager
async def session_scope(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Yield an :class:`AsyncSession`; commit on success, rollback on error.

    ``expire_on_commit=False`` so ORM instances returned by repository
    calls remain usable after commit without triggering a lazy-load.
    ``lazy="raise"`` on relationships (cf. models.py) catches silent
    N+1 queries that would otherwise only surface in prod.
    """
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

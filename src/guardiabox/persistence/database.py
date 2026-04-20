"""SQLAlchemy async engine + session factory, backed by SQLCipher.

The encryption key for SQLCipher is derived from the *vault administrator*
password (a separate keystore, distinct from per-user keystores) via PBKDF2 +
SQLCipher's PRAGMA key, so the database file is unreadable at rest without it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


def create_engine(database_url: str, *, sqlcipher_key: str | None = None) -> AsyncEngine:
    """Build an async SQLAlchemy engine, optionally with SQLCipher PRAGMAs."""
    raise NotImplementedError("See docs/specs/000-multi-user/plan.md")


@asynccontextmanager
async def session_scope(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Yield an :class:`AsyncSession` and commit/rollback automatically."""
    # The ``yield`` is unreachable but required so the function's return type
    # resolves to AsyncIterator[AsyncSession] for @asynccontextmanager (mypy
    # otherwise infers AsyncIterator[Never] and rejects the decorator).
    raise NotImplementedError("See docs/specs/000-multi-user/plan.md")
    yield  # type: ignore[unreachable]

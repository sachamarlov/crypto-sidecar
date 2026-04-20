"""SQLAlchemy async engine + session factory.

The engine is selected at runtime (cf. ADR-0011):

* If :mod:`sqlcipher3` is importable (Linux by default, Win/Mac via the
  ``sqlcipher-source`` extra), the engine is backed by **SQLCipher**: every
  page is encrypted via AES-256-CBC + HMAC-SHA-512, key derived from the
  vault administrator password.
* Otherwise, the engine is plain SQLite and **column-level AES-GCM
  encryption** (see :mod:`guardiabox.core.crypto`) is applied at the
  repository boundary so filenames and audit metadata stay encrypted at
  rest regardless of platform.

Implementation deliberately deferred — see
``docs/specs/000-multi-user/plan.md`` for SQLCipher path,
``docs/specs/002-decrypt-file/plan.md`` for the column-level helpers.
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

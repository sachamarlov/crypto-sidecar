"""FastAPI dependencies shared across routers (G-04+).

The token middleware (G-02) already gates inbound requests; the
``require_session`` dependency adds a second tier: routers that
need to read or mutate the persistence layer must additionally
present a valid ``X-GuardiaBox-Session`` header pointing at an
unlocked :class:`VaultSession` in the in-process
:class:`SessionStore`.

This file is the seam where every persistence-touching router
acquires its admin key + open DB engine. Centralising it keeps the
authentication logic in exactly one place; future changes (per-user
RBAC, session refresh tokens) edit a single dependency, not every
router.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from guardiabox.config import Settings
from guardiabox.persistence.bootstrap import vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.ui.tauri.sidecar.state import SessionStore, VaultSession

__all__ = [
    "SESSION_HEADER",
    "open_db_session",
    "require_session",
    "settings_dep",
    "store_dep",
]

#: Header carrying the active vault session id. The Tauri shell
#: stores it in Jotai (see frontend H-02) and forwards on every
#: request that needs admin context.
SESSION_HEADER = "x-guardiabox-session"  # nosec B105 -- header name


def settings_dep(request: Request) -> Settings:
    """Pull the :class:`Settings` instance attached at app construction."""
    settings: Settings = request.app.state.settings
    return settings


def store_dep(request: Request) -> SessionStore:
    """Pull the :class:`SessionStore` instance attached at app construction."""
    store: SessionStore = request.app.state.session_store
    return store


def require_session(
    request: Request,
    store: Annotated[SessionStore, Depends(store_dep)],
) -> VaultSession:
    """Resolve the active vault session or raise 401.

    Reads the ``X-GuardiaBox-Session`` header, looks it up in the
    store (which auto-expires + zero-fills on stale entries), and
    returns the live :class:`VaultSession`. If the header is missing
    or the session is unknown / expired, returns the same 401 body
    the auth middleware uses -- a deliberate choice (anti-oracle).
    """
    session_id = request.headers.get(SESSION_HEADER)
    if session_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="vault session required",
        )
    session = store.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="vault session required",
        )
    return session


@asynccontextmanager
async def open_db_session(
    settings: Settings,
) -> AsyncIterator[AsyncSession]:
    """Open an :class:`AsyncSession` rooted at ``settings.data_dir``.

    Creates a fresh engine per request (cheap with aiosqlite) and
    disposes it on context exit. The engine pool is overkill for a
    single-tenant sidecar; we accept the per-request startup cost
    for simplicity, but a future engine cache lives behind this
    one-line abstraction.
    """
    paths = vault_paths(settings.data_dir)
    engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
    try:
        async with session_scope(engine) as session:
            yield session
    finally:
        await engine.dispose()

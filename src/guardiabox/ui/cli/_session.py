"""Shared helpers for Phase C-2 vault-aware CLI commands.

Every command that touches the DB needs the same boilerplate:

1. Resolve the data dir (CLI flag > env var > default).
2. Read ``vault.admin.json`` (error out if the vault is not init-ed).
3. Prompt for the admin password + derive the admin key.
4. Open an async engine on the DB file.
5. Run the body in a single ``session_scope``.
6. Dispose the engine.

:class:`VaultSession` bundles steps 1 to 3; :func:`open_vault_session`
is the async context manager that does 4 to 6 around a user-supplied
coroutine.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from guardiabox.config import get_settings
from guardiabox.persistence.bootstrap import VaultPaths, vault_paths
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.security.vault_admin import (
    VaultAdminConfig,
    derive_admin_key,
    read_admin_config,
)
from guardiabox.ui.cli.io import read_password

__all__ = ["VaultSession", "open_vault_session", "resolve_vault_paths", "unlock_vault"]


@dataclass(frozen=True, slots=True)
class VaultSession:
    """Everything a vault-aware CLI command needs after unlock."""

    paths: VaultPaths
    config: VaultAdminConfig
    admin_key: bytes


def resolve_vault_paths(data_dir: Path | None) -> VaultPaths:
    """Resolve the vault paths from the CLI flag or the global Settings."""
    target = data_dir or get_settings().data_dir
    return vault_paths(target)


def unlock_vault(data_dir: Path | None, *, password_stdin: bool) -> VaultSession:
    """Read the admin config, prompt for the password, derive the key.

    Raises:
        VaultAdminConfigMissingError: If no ``vault.admin.json`` exists
            at the resolved location.
    """
    paths = resolve_vault_paths(data_dir)
    config = read_admin_config(paths.admin_config)
    password = read_password(
        stdin=password_stdin,
        prompt="Mot de passe administrateur",
    )
    admin_key = derive_admin_key(config, password)
    return VaultSession(paths=paths, config=config, admin_key=admin_key)


@asynccontextmanager
async def open_vault_session(
    data_dir: Path | None,
    *,
    password_stdin: bool,
) -> AsyncIterator[tuple[VaultSession, AsyncSession, AsyncEngine]]:
    """Yield ``(vault_session, db_session, engine)`` for a single request.

    The engine is disposed and the session committed (or rolled back)
    on context exit. Callers run one logical DB unit of work per
    invocation.
    """
    vault = unlock_vault(data_dir, password_stdin=password_stdin)
    engine = create_engine(f"sqlite+aiosqlite:///{vault.paths.db}")
    try:
        async with session_scope(engine) as db_session:
            yield vault, db_session, engine
    finally:
        await engine.dispose()

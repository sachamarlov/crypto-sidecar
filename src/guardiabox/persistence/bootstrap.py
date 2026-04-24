"""Vault filesystem bootstrap.

Provides the two paths that the CLI and every future adapter need:

* :func:`vault_paths(data_dir)` — canonical DB + admin-config paths.
* :func:`init_vault(data_dir, password, *, kdf=None)` — first-run
  bootstrap: mkdir the data dir, write the admin config, run
  ``alembic upgrade head`` to create the four tables + append-only
  triggers, record a ``SYSTEM_STARTUP`` entry in the audit log.

Keeping the initialisation sequence in a dedicated module lets the
CLI command stay a thin wrapper, and makes it straightforward to
call from tests or from a future setup wizard.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config

from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.logging import get_logger
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.security.audit import AuditAction, append
from guardiabox.security.vault_admin import (
    ADMIN_CONFIG_FILENAME,
    create_admin_config,
    derive_admin_key,
    write_admin_config,
)

__all__ = [
    "DB_FILENAME",
    "VaultPaths",
    "init_vault",
    "vault_paths",
]

#: Name of the SQLite file inside ``data_dir``. Kept alongside the
#: admin config for locality — a tarball of ``data_dir`` is everything
#: you need to back up.
DB_FILENAME = "vault.db"

_log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class VaultPaths:
    """Canonical paths for a vault rooted at ``data_dir``."""

    data_dir: Path
    db: Path
    admin_config: Path


def vault_paths(data_dir: Path) -> VaultPaths:
    """Return the canonical paths under ``data_dir``."""
    resolved = data_dir.expanduser().resolve()
    return VaultPaths(
        data_dir=resolved,
        db=resolved / DB_FILENAME,
        admin_config=resolved / ADMIN_CONFIG_FILENAME,
    )


def _alembic_config_for(db_path: Path) -> Config:
    """Build an Alembic ``Config`` pointing at ``db_path``.

    The script location follows the package layout. We look up the
    migrations directory relative to the ``guardiabox.persistence``
    package so the config works from any cwd — including the
    PyInstaller bundle where the source tree is relocated.
    """
    from guardiabox.persistence import migrations

    cfg = Config()
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    script_dir = Path(migrations.__file__).resolve().parent
    cfg.set_main_option("script_location", str(script_dir))
    cfg.set_main_option("path_separator", "os")
    return cfg


def _run_alembic_upgrade(db_path: Path) -> None:
    """Sync wrapper around ``alembic.command.upgrade`` for asyncio.to_thread."""
    command.upgrade(_alembic_config_for(db_path), "head")


async def init_vault(
    data_dir: Path,
    password: str,
    *,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
) -> VaultPaths:
    """Create ``data_dir``, write the admin config, run migrations, audit boot.

    Contract:

    * Refuses to re-init: if the admin config already exists, the
      caller must remove the file manually (prevents a silent wipe of
      the existing vault).
    * Runs ``alembic upgrade head`` in a thread because Alembic's
      online mode calls ``asyncio.run`` internally, which refuses to
      nest inside an active event loop.
    * Appends one ``SYSTEM_STARTUP`` audit entry before returning so
      every vault has at least one genesis row; subsequent verify()
      calls always see a populated chain.

    Returns the :class:`VaultPaths` for the freshly-initialised vault.
    """
    paths = vault_paths(data_dir)
    paths.data_dir.mkdir(parents=True, exist_ok=True)

    # The admin config write refuses to overwrite, which is the only
    # bulwark against a double-init. The alembic step runs on an empty
    # DB idempotently, but the audit log would get two SYSTEM_STARTUP
    # rows at sequence 1 and 2 — confusing during forensics.
    config = create_admin_config(password, kdf=kdf)
    write_admin_config(paths.admin_config, config)

    await asyncio.to_thread(_run_alembic_upgrade, paths.db)

    admin_key = derive_admin_key(config, password)
    engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
    try:
        async with session_scope(engine) as session:
            await append(
                session,
                admin_key,
                actor_user_id=None,
                action=AuditAction.SYSTEM_STARTUP,
                metadata={"event": "vault.init"},
            )
    finally:
        await engine.dispose()

    _log.info("vault.initialised", data_dir=str(paths.data_dir))
    return paths

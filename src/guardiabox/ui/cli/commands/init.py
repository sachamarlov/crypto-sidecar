"""``guardiabox init`` — first-run vault bootstrap.

Creates ``Settings.data_dir`` (typically ``~/.guardiabox/``), writes
the vault administrator config (salt + KDF params), runs every
Alembic migration, and records a single ``SYSTEM_STARTUP`` audit
entry so the log is populated from sequence 1 onwards.

Idempotency note: the command **refuses** to re-init if
``vault.admin.json`` already exists. A silent re-init would create a
fresh admin key and orphan every ciphertext column in the existing
DB -- unrecoverable without the old password. The user must remove
the admin config by hand to acknowledge the destruction.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path

import typer

from guardiabox.config import get_settings
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.persistence.bootstrap import VaultPaths, init_vault, vault_paths
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


class KdfChoice(StrEnum):
    """Selectable KDF flavours for the vault administrator password."""

    PBKDF2 = "pbkdf2"
    ARGON2ID = "argon2id"


@app.command("init")
def init_command(
    data_dir: Path | None = typer.Option(
        None,
        "--data-dir",
        help="Emplacement du coffre (défaut : $GUARDIABOX_DATA_DIR ou ~/.guardiabox).",
        show_default=False,
    ),
    kdf: KdfChoice = typer.Option(
        KdfChoice.PBKDF2,
        "--kdf",
        case_sensitive=False,
        help="Fonction de dérivation utilisée pour le mot de passe administrateur.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin (sans prompt).",
    ),
) -> None:
    """Initialiser le coffre (crée le répertoire, la base, et l'audit genèse)."""
    try:
        paths = _dispatch(data_dir=data_dir, kdf=kdf, password_stdin=password_stdin)
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Coffre initialisé dans {paths.data_dir}")
    typer.echo(f"  Base de données : {paths.db}")
    typer.echo(f"  Configuration   : {paths.admin_config}")


def _dispatch(
    *,
    data_dir: Path | None,
    kdf: KdfChoice,
    password_stdin: bool,
) -> VaultPaths:
    settings = get_settings()
    target_dir = (data_dir or settings.data_dir).expanduser()
    paths_preview = vault_paths(target_dir)

    # Refuse early if the vault is already initialised -- before we
    # prompt for a password the user does not need to type.
    if paths_preview.admin_config.exists():
        typer.echo(
            f"Erreur : le coffre est déjà initialisé dans {paths_preview.data_dir}. "
            f"Supprimer {paths_preview.admin_config} manuellement pour ré-initialiser.",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    password = read_password(
        stdin=password_stdin,
        confirm=not password_stdin,
        prompt="Mot de passe administrateur",
    )
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = Argon2idKdf() if kdf is KdfChoice.ARGON2ID else Pbkdf2Kdf()
    return asyncio.run(init_vault(target_dir, password, kdf=kdf_impl))

"""``guardiabox user`` — create / list / delete / show local users.

This command group is the CLI seat of ``spec 000-multi-user``.
Every operation unlocks the vault with the admin password, resolves
the user repository, and emits one audit entry so the chain stays
complete.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

import typer

from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.persistence.repositories import UserRepository
from guardiabox.security import keystore
from guardiabox.security.audit import AuditAction, append
from guardiabox.ui.cli._session import open_vault_session
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app

user_app = typer.Typer(
    name="user",
    help="Gérer les utilisateurs locaux du coffre.",
    no_args_is_help=True,
)
app.add_typer(user_app, name="user")


class KdfChoice(StrEnum):
    """KDF flavour for the user's own master password."""

    PBKDF2 = "pbkdf2"
    ARGON2ID = "argon2id"


def _build_kdf(choice: KdfChoice) -> Pbkdf2Kdf | Argon2idKdf:
    return Argon2idKdf() if choice is KdfChoice.ARGON2ID else Pbkdf2Kdf()


# ---------------------------------------------------------------------------
# user create
# ---------------------------------------------------------------------------


@user_app.command("create")
def user_create_command(
    username: str = typer.Argument(..., help="Nom du nouvel utilisateur."),
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    kdf: KdfChoice = typer.Option(
        KdfChoice.PBKDF2,
        "--kdf",
        case_sensitive=False,
        help="KDF utilisée pour le mot de passe utilisateur.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire les deux mots de passe depuis stdin (admin puis utilisateur).",
    ),
) -> None:
    """Créer un utilisateur local (admin puis utilisateur)."""
    try:
        asyncio.run(
            _create_flow(
                data_dir=data_dir,
                username=username,
                kdf_choice=kdf,
                password_stdin=password_stdin,
            )
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Utilisateur '{username}' créé.")


async def _create_flow(
    *,
    data_dir: Path | None,
    username: str,
    kdf_choice: KdfChoice,
    password_stdin: bool,
) -> None:
    # Read the user master password *before* opening the async vault
    # session so both prompts happen outside the DB transaction.
    user_password = read_password(
        stdin=password_stdin,
        confirm=not password_stdin,
        prompt=f"Mot de passe utilisateur pour '{username}'",
    )
    kdf_impl = _build_kdf(kdf_choice)
    ks = keystore.create(user_password, kdf=kdf_impl)

    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        repo = UserRepository(session, vault.admin_key)
        existing = await repo.get_by_username(username)
        if existing is not None:
            typer.echo(f"Erreur : utilisateur '{username}' déjà présent.", err=True)
            raise typer.Exit(code=ExitCode.USAGE)

        user_id = uuid4().hex
        created = await repo.create(
            user_id=user_id,
            username=username,
            salt=ks.salt,
            kdf_id=ks.kdf_id,
            kdf_params=ks.kdf_params,
            wrapped_vault_key=ks.wrapped_vault_key,
            wrapped_rsa_private=ks.wrapped_rsa_private,
            rsa_public_pem=ks.rsa_public_pem,
        )
        await append(
            session,
            vault.admin_key,
            actor_user_id=created.id,
            action=AuditAction.USER_CREATE,
            target=username,
        )


# ---------------------------------------------------------------------------
# user list
# ---------------------------------------------------------------------------


@user_app.command("list")
def user_list_command(
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin.",
    ),
) -> None:
    """Lister les utilisateurs locaux (déchiffre les noms côté client)."""
    try:
        rows = asyncio.run(_list_flow(data_dir=data_dir, password_stdin=password_stdin))
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if not rows:
        typer.echo("(aucun utilisateur)")
        return
    for row in rows:
        typer.echo(row)


async def _list_flow(
    *,
    data_dir: Path | None,
    password_stdin: bool,
) -> list[str]:
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        repo = UserRepository(session, vault.admin_key)
        users = await repo.list_all()
        return [
            f"{repo.decrypt_username(u)}  (id={u.id}, créé le {u.created_at.isoformat()})"
            for u in users
        ]


# ---------------------------------------------------------------------------
# user delete
# ---------------------------------------------------------------------------


@user_app.command("delete")
def user_delete_command(
    username: str = typer.Argument(..., help="Nom de l'utilisateur à supprimer."),
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Ne pas demander de confirmation interactive.",
    ),
) -> None:
    """Supprimer un utilisateur local et toutes ses entrées (CASCADE)."""
    if (
        not yes
        and not password_stdin
        and not typer.confirm(
            f"Supprimer l'utilisateur '{username}' et ses données ?", default=False
        )
    ):
        raise typer.Exit(code=ExitCode.GENERIC)

    try:
        deleted = asyncio.run(
            _delete_flow(data_dir=data_dir, username=username, password_stdin=password_stdin)
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if not deleted:
        typer.echo(f"Utilisateur '{username}' introuvable.", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)
    typer.echo(f"Utilisateur '{username}' supprimé.")


async def _delete_flow(
    *,
    data_dir: Path | None,
    username: str,
    password_stdin: bool,
) -> bool:
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        repo = UserRepository(session, vault.admin_key)
        target = await repo.get_by_username(username)
        if target is None:
            return False
        user_id = target.id
        await repo.delete(user_id)
        await append(
            session,
            vault.admin_key,
            actor_user_id=None,  # user is gone after delete
            action=AuditAction.USER_DELETE,
            target=username,
            metadata={"user_id": user_id},
        )
        return True


# ---------------------------------------------------------------------------
# user show (a minimal inspection)
# ---------------------------------------------------------------------------


@user_app.command("show")
def user_show_command(
    username: str = typer.Argument(..., help="Utilisateur à afficher."),
    data_dir: Path | None = typer.Option(None, "--data-dir", show_default=False),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin.",
    ),
) -> None:
    """Afficher les métadonnées publiques d'un utilisateur (pas de secret)."""
    try:
        data = asyncio.run(
            _show_flow(data_dir=data_dir, username=username, password_stdin=password_stdin)
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if data is None:
        typer.echo(f"Utilisateur '{username}' introuvable.", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)
    for line in data:
        typer.echo(line)


async def _show_flow(
    *,
    data_dir: Path | None,
    username: str,
    password_stdin: bool,
) -> list[str] | None:
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        repo = UserRepository(session, vault.admin_key)
        target = await repo.get_by_username(username)
        if target is None:
            return None
        last_unlock = (
            target.last_unlock_at.isoformat() if target.last_unlock_at is not None else "jamais"
        )
        return [
            f"Utilisateur    : {repo.decrypt_username(target)}",
            f"ID             : {target.id}",
            f"Créé le        : {target.created_at.isoformat()}",
            f"Dernier unlock : {last_unlock}",
            f"Échecs unlock  : {target.failed_unlock_count}",
            f"KDF id         : 0x{target.kdf_id:02x}",
        ]

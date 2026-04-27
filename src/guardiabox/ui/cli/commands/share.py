"""``guardiabox share`` — produce a ``.gbox-share`` token for another user.

Workflow (T-003.08 + T-003.10 fingerprint):

1. Resolve source ``.crypt`` path against the working directory.
2. Open the vault session (admin password) and look up sender + recipient
   rows in :class:`UserRepository`.
3. Re-derive the sender's master key from the sender password and unwrap
   their RSA private key.
4. Compute the recipient's RSA public key fingerprint (SHA-256 of the
   PEM blob, formatted as colon-separated hex). Print it and ask for
   confirmation unless ``--yes`` is set — defends against MITM where an
   attacker substituted the recipient's pubkey in the local DB.
5. Call :func:`core.operations.share_file` to write the token.
6. Append a ``file.share`` row to the audit chain.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from uuid import UUID

import typer

from guardiabox.core.operations import share_file
from guardiabox.core.rsa import load_private_key_der, load_public_key_pem
from guardiabox.core.share_token import PERMISSION_READ, PERMISSION_RESHARE
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import UserRepository
from guardiabox.security.audit import AuditAction, append as append_audit
from guardiabox.security.keystore import Keystore, unlock_rsa_private
from guardiabox.ui.cli._session import resolve_vault_paths
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


def _public_key_fingerprint(pem: bytes) -> str:
    """SHA-256 of the PEM blob, formatted as colon-separated hex pairs."""
    digest = hashlib.sha256(pem).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


@app.command("share")
def share_command(  # noqa: PLR0917 -- Typer commands expose one param per flag
    path: Path = typer.Argument(
        ...,
        help="Chemin du fichier .crypt à partager.",
    ),
    sender: str = typer.Option(
        ...,
        "--from",
        help="Nom de l'utilisateur émetteur.",
        show_default=False,
    ),
    recipient: str = typer.Option(
        ...,
        "--to",
        help="Nom de l'utilisateur destinataire.",
        show_default=False,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination .gbox-share. Défaut : <fichier>.gbox-share.",
        show_default=False,
    ),
    expires_days: int | None = typer.Option(
        None,
        "--expires",
        help="Expiration en jours depuis maintenant. Aucune si non précisé.",
        show_default=False,
    ),
    reshare: bool = typer.Option(
        False,
        "--reshare",
        help="Autoriser le destinataire à re-partager (permission RESHARE).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Écraser la destination si elle existe déjà.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accepter l'empreinte du destinataire sans confirmation interactive.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire les mots de passe depuis stdin (sender d'abord, puis admin).",
    ),
    data_dir: Path | None = typer.Option(
        None,
        "--data-dir",
        help="Répertoire du coffre (défaut : Settings.data_dir).",
        show_default=False,
    ),
) -> None:
    """Produire un jeton ``.gbox-share`` chiffré pour un autre utilisateur."""
    try:
        cwd = Path.cwd().resolve()
        safe_source = resolve_within(path, cwd)
        if not safe_source.is_file():
            typer.echo(f"Fichier introuvable : {safe_source}", err=True)
            raise typer.Exit(code=ExitCode.PATH_OR_FILE)  # noqa: TRY301 -- early exit on missing source

        if output is None:
            output = safe_source.with_suffix(safe_source.suffix + ".gbox-share")

        sender_password = read_password(stdin=password_stdin, prompt="Mot de passe émetteur")

        permission_flags = PERMISSION_READ | (PERMISSION_RESHARE if reshare else 0)
        expires_at = 0
        if expires_days is not None:
            import time

            expires_at = int(time.time()) + expires_days * 86400

        result_path = asyncio.run(
            _share_flow(
                source=safe_source,
                sender_username=sender,
                recipient_username=recipient,
                sender_password=sender_password,
                output=output,
                expires_at=expires_at,
                permission_flags=permission_flags,
                force=force,
                yes=yes,
                data_dir=data_dir,
                password_stdin=password_stdin,
            )
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Partage écrit : {result_path}")
    typer.echo(f"Audit     : opération enregistrée pour '{sender}' -> '{recipient}'.")


async def _share_flow(
    *,
    source: Path,
    sender_username: str,
    recipient_username: str,
    sender_password: str,
    output: Path,
    expires_at: int,
    permission_flags: int,
    force: bool,
    yes: bool,
    data_dir: Path | None,
    password_stdin: bool,
) -> Path:
    """Async body: opens the vault, resolves users, calls share_file, audits."""
    from guardiabox.security.vault_admin import derive_admin_key, read_admin_config

    paths = resolve_vault_paths(data_dir)
    config = read_admin_config(paths.admin_config)
    admin_password = read_password(stdin=password_stdin, prompt="Mot de passe administrateur")
    admin_key = derive_admin_key(config, admin_password)

    engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
    try:
        async with session_scope(engine) as session:
            user_repo = UserRepository(session, admin_key)
            sender_row = await user_repo.get_by_username(sender_username)
            if sender_row is None:
                from guardiabox.core.exceptions import VaultUserNotFoundError

                raise VaultUserNotFoundError(f"sender '{sender_username}' not found")
            recipient_row = await user_repo.get_by_username(recipient_username)
            if recipient_row is None:
                from guardiabox.core.exceptions import VaultUserNotFoundError

                raise VaultUserNotFoundError(f"recipient '{recipient_username}' not found")

            # Fingerprint confirmation (T-003.10).
            fingerprint = _public_key_fingerprint(recipient_row.rsa_public_pem)
            typer.echo(f"Destinataire   : {recipient_username}")
            typer.echo("Empreinte clé publique (SHA-256) :")
            typer.echo(f"  {fingerprint[:48]}")
            typer.echo(f"  {fingerprint[48:]}")
            if not yes and not typer.confirm(
                "Confirmer l'envoi à ce destinataire ?", default=False
            ):
                typer.echo("Annulé par l'utilisateur.", err=True)
                raise typer.Exit(code=ExitCode.USAGE)

            # Build sender keystore from User row + unwrap RSA private.
            sender_keystore = Keystore(
                salt=sender_row.salt,
                kdf_id=sender_row.kdf_id,
                kdf_params=sender_row.kdf_params,
                wrapped_vault_key=sender_row.wrapped_vault_key,
                wrapped_rsa_private=sender_row.wrapped_rsa_private,
                rsa_public_pem=sender_row.rsa_public_pem,
            )
            sender_priv_der = unlock_rsa_private(sender_keystore, sender_password)
            sender_priv = load_private_key_der(sender_priv_der)
            recipient_pub = load_public_key_pem(recipient_row.rsa_public_pem)

            # Sync call -- decrypt + re-encrypt + sign + atomic write.
            result_path = share_file(
                source=source,
                sender_password=sender_password,
                sender_user_id=UUID(sender_row.id),
                sender_private_key=sender_priv,
                recipient_user_id=UUID(recipient_row.id),
                recipient_public_key=recipient_pub,
                output=output,
                expires_at=expires_at,
                permission_flags=permission_flags,
                force=force,
            )

            # Append audit row.
            await append_audit(
                session,
                admin_key,
                actor_user_id=sender_row.id,
                action=AuditAction.FILE_SHARE,
                target=recipient_username,
                metadata={
                    "share_path": str(result_path),
                    "expires_at": str(expires_at),
                    "permission_flags": str(permission_flags),
                },
            )
        return result_path
    finally:
        await engine.dispose()

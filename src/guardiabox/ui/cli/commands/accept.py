"""``guardiabox accept`` — verify, decrypt and consume a ``.gbox-share`` token.

Workflow (T-003.09):

1. Resolve the share path.
2. Open the vault session (admin password) and look up sender + recipient
   rows in :class:`UserRepository`.
3. Re-derive the recipient's master key from their password and unwrap
   their RSA private key.
4. Call :func:`core.operations.accept_share` which:
   - parses the token,
   - verifies the RSA-PSS signature **first** (anti-oracle),
   - checks the recipient_user_id matches,
   - checks the expiry,
   - unwraps the DEK,
   - decrypts the embedded ciphertext,
   - writes the plaintext atomically.
5. Append a ``file.share_accept`` row to the audit chain.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

import typer

from guardiabox.core.operations import accept_share
from guardiabox.core.rsa import load_private_key_der, load_public_key_pem
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import UserRepository
from guardiabox.security.audit import AuditAction, append as append_audit
from guardiabox.security.keystore import Keystore, unlock_rsa_private
from guardiabox.ui.cli._session import resolve_vault_paths
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


@app.command("accept")
def accept_command(  # noqa: PLR0917
    path: Path = typer.Argument(
        ...,
        help="Chemin du jeton .gbox-share à accepter.",
    ),
    sender: str = typer.Option(
        ...,
        "--from",
        help="Nom de l'utilisateur émetteur (clé publique pour vérifier la signature).",
        show_default=False,
    ),
    recipient: str = typer.Option(
        ...,
        "--as",
        help="Nom de l'utilisateur destinataire (déchiffrera avec sa clé privée).",
        show_default=False,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination du texte clair. Défaut : <jeton>.decrypt.",
        show_default=False,
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Écraser la destination si elle existe déjà.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire les mots de passe depuis stdin (recipient d'abord, puis admin).",
    ),
    data_dir: Path | None = typer.Option(
        None,
        "--data-dir",
        help="Répertoire du coffre (défaut : Settings.data_dir).",
        show_default=False,
    ),
) -> None:
    """Accepter un jeton ``.gbox-share`` et déchiffrer son contenu."""
    try:
        cwd = Path.cwd().resolve()
        safe_source = resolve_within(path, cwd)
        if not safe_source.is_file():
            typer.echo(f"Fichier introuvable : {safe_source}", err=True)
            raise typer.Exit(code=ExitCode.PATH_OR_FILE)  # noqa: TRY301 -- early exit on missing source

        if output is None:
            output = safe_source.with_suffix(".decrypt")

        recipient_password = read_password(stdin=password_stdin, prompt="Mot de passe destinataire")

        result_path = asyncio.run(
            _accept_flow(
                source=safe_source,
                sender_username=sender,
                recipient_username=recipient,
                recipient_password=recipient_password,
                output=output,
                force=force,
                data_dir=data_dir,
                password_stdin=password_stdin,
            )
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    typer.echo(f"Déchiffré : {result_path}")
    typer.echo(f"Audit     : opération enregistrée pour '{recipient}' (de '{sender}').")


async def _accept_flow(
    *,
    source: Path,
    sender_username: str,
    recipient_username: str,
    recipient_password: str,
    output: Path,
    force: bool,
    data_dir: Path | None,
    password_stdin: bool,
) -> Path:
    """Async body: opens the vault, resolves users, verifies + decrypts + audits."""
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

            # Build recipient keystore + unwrap their RSA private.
            recipient_keystore = Keystore(
                salt=recipient_row.salt,
                kdf_id=recipient_row.kdf_id,
                kdf_params=recipient_row.kdf_params,
                wrapped_vault_key=recipient_row.wrapped_vault_key,
                wrapped_rsa_private=recipient_row.wrapped_rsa_private,
                rsa_public_pem=recipient_row.rsa_public_pem,
            )
            recipient_priv_der = unlock_rsa_private(recipient_keystore, recipient_password)
            recipient_priv = load_private_key_der(recipient_priv_der)
            sender_pub = load_public_key_pem(sender_row.rsa_public_pem)

            # Sync call: parse + verify + unwrap + decrypt + atomic write.
            result_path = accept_share(
                source=source,
                recipient_private_key=recipient_priv,
                sender_public_key=sender_pub,
                expected_recipient_user_id=UUID(recipient_row.id),
                output=output,
                force=force,
            )

            # Append audit row.
            await append_audit(
                session,
                admin_key,
                actor_user_id=recipient_row.id,
                action=AuditAction.FILE_SHARE_ACCEPT,
                target=sender_username,
                metadata={
                    "share_path": str(source),
                    "plaintext_path": str(result_path),
                },
            )
        return result_path
    finally:
        await engine.dispose()

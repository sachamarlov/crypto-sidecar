"""``guardiabox secure-delete`` — DoD overwrite or crypto-erase.

Two modes are supported:

* ``--method overwrite`` (or ``--method auto`` on HDD/unknown media) —
  DoD 5220.22-M three-pass overwrite then unlink. Pure-core path,
  unchanged since Phase B1.

* ``--method crypto-erase --vault-user <name>`` (Phase B2) — combines
  the DoD overwrite with a database cleanup: looks up the matching
  ``vault_items`` row by filename HMAC, deletes it from the DB
  (encrypted columns vanish along with the row), runs the overwrite
  pass on the ciphertext file, unlinks it, and appends a
  ``file.secure_delete`` audit row. **Honest scope**: GuardiaBox does
  not currently persist a per-file DEK separate from the ``.crypt``
  payload, so what we ship is *metadata-erase + ciphertext overwrite +
  audit attribution*, not a NIST SP 800-88 crypto-erase in the strict
  sense. The mode rejects calls without ``--vault-user`` because the
  metadata path is what makes the option meaningful versus a plain
  overwrite.

On SSDs the CLI emits a NIST SP 800-88r2 warning and asks for
confirmation unless ``--no-confirm`` is passed. On HDDs or unknown
media the command proceeds silently.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path

import typer

from guardiabox.core.exceptions import (
    CryptoEraseRequiresVaultUserError,
    KeyNotFoundError,
)
from guardiabox.core.secure_delete import (
    DEFAULT_OVERWRITE_PASSES,
    MAX_OVERWRITE_PASSES,
    SecureDeleteMethod,
    secure_delete,
)
from guardiabox.fileio.platform import is_ssd
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.persistence.database import create_engine, session_scope
from guardiabox.persistence.repositories import UserRepository, VaultItemRepository
from guardiabox.security.audit import AuditAction, append as append_audit
from guardiabox.ui.cli._session import resolve_vault_paths
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


class _MethodChoice(StrEnum):
    """Methods exposed on the CLI surface. ``auto`` picks per media type."""

    AUTO = "auto"
    OVERWRITE = "overwrite"
    CRYPTO_ERASE = "crypto-erase"


@app.command("secure-delete")
def secure_delete_command(  # noqa: PLR0917 -- Typer commands expose one param per flag
    path: Path = typer.Argument(..., help="Chemin du fichier à supprimer de manière sûre."),
    method: _MethodChoice = typer.Option(
        _MethodChoice.AUTO,
        "--method",
        case_sensitive=False,
        help=(
            "Stratégie. 'auto' détecte le support ; 'overwrite' force l'écrasement DoD ; "
            "'crypto-erase' nécessite --vault-user (efface aussi la ligne DB)."
        ),
    ),
    passes: int = typer.Option(
        DEFAULT_OVERWRITE_PASSES,
        "--passes",
        min=1,
        max=MAX_OVERWRITE_PASSES,
        help="Nombre de passes d'écrasement (zéro / un / aléatoire en cycle).",
    ),
    no_confirm: bool = typer.Option(
        False,
        "--no-confirm",
        help="Ne pas demander de confirmation, même sur SSD détecté.",
    ),
    vault_user: str | None = typer.Option(
        None,
        "--vault-user",
        help="Propriétaire du vault_items à effacer (requis pour --method crypto-erase).",
        show_default=False,
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe administrateur depuis stdin (mode crypto-erase).",
    ),
    data_dir: Path | None = typer.Option(
        None,
        "--data-dir",
        help="Répertoire du coffre (défaut : Settings.data_dir).",
        show_default=False,
    ),
) -> None:
    """Supprimer un fichier de façon sécurisée (écrasement DoD ou crypto-erase)."""
    try:
        _dispatch(
            path=path,
            method=method,
            passes=passes,
            no_confirm=no_confirm,
            vault_user=vault_user,
            password_stdin=password_stdin,
            data_dir=data_dir,
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if method is _MethodChoice.CRYPTO_ERASE:
        typer.echo(f"Supprimé (crypto-erase) : {path}")
        typer.echo(f"Audit     : opération enregistrée pour '{vault_user}'.")
    else:
        typer.echo(f"Supprimé : {path} ({passes} passe(s) d'écrasement)")


def _dispatch(
    *,
    path: Path,
    method: _MethodChoice,
    passes: int,
    no_confirm: bool,
    vault_user: str | None,
    password_stdin: bool,
    data_dir: Path | None,
) -> None:
    cwd = Path.cwd().resolve()
    safe = resolve_within(path, cwd)
    if not safe.is_file():
        typer.echo(f"Fichier introuvable : {safe}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)

    if method is _MethodChoice.CRYPTO_ERASE:
        if vault_user is None:
            raise CryptoEraseRequiresVaultUserError(
                "crypto-erase nécessite --vault-user (sinon il n'y a pas de "
                "métadonnées DB à effacer; utiliser --method overwrite)"
            )
        # Crypto-erase still benefits from the SSD warning since a DoD pass
        # runs on the ciphertext too — keep parity with the overwrite branch.
        ssd = is_ssd(safe)
        if ssd is True or ssd is None:
            _warn_ssd_for_crypto_erase(no_confirm=no_confirm)

        asyncio.run(
            _crypto_erase_flow(
                path=safe,
                vault_user=vault_user,
                passes=passes,
                password_stdin=password_stdin,
                data_dir=data_dir,
            )
        )
        return

    # Overwrite path (default + auto on HDD / unknown).
    ssd = is_ssd(safe)
    if ssd is True:
        _warn_ssd(no_confirm=no_confirm)
    elif ssd is None:
        _warn_unknown_media(no_confirm=no_confirm)
    secure_delete(safe, method=SecureDeleteMethod.OVERWRITE_DOD, passes=passes)


async def _crypto_erase_flow(
    *,
    path: Path,
    vault_user: str,
    passes: int,
    password_stdin: bool,
    data_dir: Path | None,
) -> None:
    """Open vault, look up the row, overwrite-then-unlink, delete row, audit."""
    from guardiabox.security.vault_admin import (
        derive_admin_key,
        read_admin_config,
    )

    paths = resolve_vault_paths(data_dir)
    config = read_admin_config(paths.admin_config)
    admin_password = read_password(stdin=password_stdin, prompt="Mot de passe administrateur")
    admin_key = derive_admin_key(config, admin_password)

    engine = create_engine(f"sqlite+aiosqlite:///{paths.db}")
    try:
        async with session_scope(engine) as session:
            user_repo = UserRepository(session, admin_key)
            user_row = await user_repo.get_by_username(vault_user)
            if user_row is None:
                from guardiabox.core.exceptions import VaultUserNotFoundError

                raise VaultUserNotFoundError(f"vault user '{vault_user}' not found")

            item_repo = VaultItemRepository(session, admin_key)
            item = await item_repo.find_by_filename(owner_user_id=user_row.id, filename=path.name)
            if item is None:
                raise KeyNotFoundError(
                    f"no vault_items row found for '{path.name}' owned by '{vault_user}'"
                )
            item_id = item.id

            # Physical wipe BEFORE removing the row so a crash mid-run still
            # leaves the row available for retry.
            secure_delete(path, method=SecureDeleteMethod.OVERWRITE_DOD, passes=passes)

            # Row delete (encrypted columns vanish along with it).
            await item_repo.delete(item_id)

            await append_audit(
                session,
                admin_key,
                actor_user_id=user_row.id,
                action=AuditAction.FILE_SECURE_DELETE,
                target=path.name,
                metadata={
                    "method": "crypto-erase",
                    "passes": str(passes),
                    "vault_item_id": item_id,
                },
            )
    finally:
        await engine.dispose()


def _warn_ssd(*, no_confirm: bool) -> None:
    msg = (
        "Attention : le support détecté est un SSD. L'écrasement est un effort "
        "best-effort sur mémoire flash (NIST SP 800-88r2 §5.2). Pour un effacement "
        "plus complet, utiliser --method crypto-erase --vault-user <nom> (Phase B2)."
    )
    typer.echo(msg, err=True)
    if no_confirm:
        return
    if not typer.confirm("Poursuivre l'écrasement quand même ?", default=False):
        raise typer.Exit(code=ExitCode.GENERIC)


def _warn_ssd_for_crypto_erase(*, no_confirm: bool) -> None:
    """SSD warning specialised for crypto-erase mode.

    Crypto-erase combines the overwrite pass with a metadata removal,
    so the user-visible note is shorter — they already opted into the
    stronger mode. We still ask for confirmation by default to avoid
    silent destruction of a vault entry.
    """
    if no_confirm:
        return
    msg = (
        "Mode crypto-erase : la ligne vault_items sera supprimée du coffre "
        "et le ciphertext écrasé puis unlinké. Cette opération est irréversible."
    )
    typer.echo(msg, err=True)
    if not typer.confirm("Poursuivre ?", default=False):
        raise typer.Exit(code=ExitCode.GENERIC)


def _warn_unknown_media(*, no_confirm: bool) -> None:
    """Conservative fallback when the platform probe can't decide.

    NIST SP 800-88r2 §5 recommends presuming flash when the media type
    is uncertain: overwrite offers a weaker guarantee than on rotational
    storage, so the user must opt in rather than get a false assurance.
    """
    msg = (
        "Attention : le type de support n'a pas pu être identifié. Par prudence "
        "nous le traitons comme de la mémoire flash (NIST SP 800-88r2). "
        "L'écrasement n'est donc qu'un effort best-effort ; pour un effacement "
        "plus complet, utiliser --method crypto-erase --vault-user <nom>."
    )
    typer.echo(msg, err=True)
    if no_confirm:
        return
    if not typer.confirm("Poursuivre l'écrasement quand même ?", default=False):
        raise typer.Exit(code=ExitCode.GENERIC)

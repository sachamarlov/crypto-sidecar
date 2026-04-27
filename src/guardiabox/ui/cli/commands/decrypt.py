"""``guardiabox decrypt`` — decrypt a ``.crypt`` file or emit to stdout."""

from __future__ import annotations

from pathlib import Path
import sys

import typer

from guardiabox.core.operations import decrypt_file, decrypt_message
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli._vault_audit import record_decrypt_event
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app


@app.command("decrypt")
def decrypt_command(  # noqa: PLR0917 -- Typer commands expose one param per flag
    path: Path = typer.Argument(
        ...,
        help="Chemin du fichier .crypt à déchiffrer.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination. Défaut : remplace .crypt par .decrypt.",
        show_default=False,
    ),
    to_stdout: bool = typer.Option(
        False,
        "--stdout",
        "-m",
        "--message",
        help="Écrire le contenu déchiffré sur stdout sans toucher au disque.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe depuis stdin (pas de prompt interactif).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Écraser la destination si elle existe déjà.",
    ),
    vault_user: str | None = typer.Option(
        None,
        "--vault-user",
        help="Nom de l'utilisateur du coffre (active l'enregistrement audit).",
        show_default=False,
    ),
    data_dir: Path | None = typer.Option(
        None,
        "--data-dir",
        help="Répertoire du coffre (défaut : Settings.data_dir).",
        show_default=False,
    ),
) -> None:
    """Déchiffrer un fichier ``.crypt`` vers son contenu d'origine."""
    try:
        target = _dispatch(
            path=path,
            output=output,
            to_stdout=to_stdout,
            password_stdin=password_stdin,
            force=force,
        )
    except (Exception, KeyboardInterrupt) as exc:
        exit_for(exc)

    if target is not None:
        typer.echo(f"Déchiffré : {target}")

    if vault_user is not None:
        try:
            record_decrypt_event(
                data_dir=data_dir,
                password_stdin=password_stdin,
                vault_username=vault_user,
                container_path=path,
                plaintext_path=target,
            )
            typer.echo(f"Audit     : opération enregistrée pour '{vault_user}'.")
        except (Exception, KeyboardInterrupt) as exc:
            exit_for(exc)


def _dispatch(
    *,
    path: Path,
    output: Path | None,
    to_stdout: bool,
    password_stdin: bool,
    force: bool,
) -> Path | None:
    cwd = Path.cwd().resolve()
    safe_source = resolve_within(path, cwd)
    if not safe_source.is_file():
        typer.echo(f"Fichier introuvable : {safe_source}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)

    password = read_password(stdin=password_stdin)

    if to_stdout:
        plaintext = decrypt_message(safe_source, password)
        sys.stdout.buffer.write(plaintext)
        sys.stdout.flush()
        return None

    return decrypt_file(safe_source, password, root=cwd, dest=output, force=force)

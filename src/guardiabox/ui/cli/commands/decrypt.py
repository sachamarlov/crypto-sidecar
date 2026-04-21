"""``guardiabox decrypt`` — decrypt a ``.crypt`` file or message."""

from __future__ import annotations

from pathlib import Path
import sys

import typer

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    DecryptionError,
    IntegrityError,
    InvalidContainerError,
    PathTraversalError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
)
from guardiabox.core.operations import decrypt_file, decrypt_message
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.main import app


@app.command("decrypt")
def decrypt_command(
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
    as_message: bool = typer.Option(
        False,
        "--message",
        "-m",
        help="Afficher le contenu déchiffré sur stdout sans écrire de fichier.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Lire le mot de passe depuis stdin (pas de prompt interactif).",
    ),
) -> None:
    """Déchiffrer un fichier ``.crypt`` vers son contenu d'origine."""
    try:
        cwd = Path.cwd().resolve()
        safe_source = resolve_within(path, cwd)
        if not safe_source.is_file():
            typer.echo(f"Fichier introuvable : {safe_source}", err=True)
            raise typer.Exit(1)

        password = _read_password(stdin=password_stdin)

        if as_message:
            plaintext = decrypt_message(safe_source, password)
            sys.stdout.buffer.write(plaintext)
            sys.stdout.flush()
            return

        safe_output = resolve_within(output, cwd) if output is not None else None
        target = decrypt_file(safe_source, password, dest=safe_output)
    except (PathTraversalError, SymlinkEscapeError) as exc:
        typer.echo(f"Chemin refusé : {exc}", err=True)
        raise typer.Exit(1) from exc
    except FileNotFoundError as exc:
        typer.echo(f"Fichier introuvable : {exc}", err=True)
        raise typer.Exit(1) from exc
    except (InvalidContainerError, UnsupportedVersionError) as exc:
        typer.echo(f"Conteneur invalide : {exc}", err=True)
        raise typer.Exit(1) from exc
    except (UnknownKdfError, WeakKdfParametersError) as exc:
        typer.echo(f"Paramètres KDF non supportés : {exc}", err=True)
        raise typer.Exit(1) from exc
    except CorruptedContainerError as exc:
        typer.echo(f"Conteneur corrompu : {exc}", err=True)
        raise typer.Exit(1) from exc
    except (DecryptionError, IntegrityError) as exc:
        typer.echo(
            "Échec du déchiffrement : mot de passe incorrect ou données altérées.",
            err=True,
        )
        raise typer.Exit(2) from exc
    except KeyboardInterrupt as exc:
        raise typer.Exit(130) from exc
    except OSError as exc:
        typer.echo(f"Erreur disque : {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Déchiffré : {target}")


def _read_password(*, stdin: bool) -> str:
    if stdin:
        raw = sys.stdin.readline()
        return raw.rstrip("\n").rstrip("\r")
    result: str = typer.prompt(
        "Mot de passe",
        hide_input=True,
        confirmation_prompt=False,
    )
    return result

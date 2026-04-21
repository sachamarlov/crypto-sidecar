"""``guardiabox inspect`` — dump ``.crypt`` header without decrypting.

Useful for auditing or debugging a container: the command resolves the
input path, validates magic/version/kdf, and prints the decoded header
values. No password is required and no plaintext is ever read.
"""

from __future__ import annotations

from pathlib import Path

import typer

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    PathTraversalError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
)
from guardiabox.core.operations import inspect_container
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.main import app


@app.command("inspect")
def inspect_command(
    path: Path = typer.Argument(
        ...,
        help="Chemin du fichier .crypt à analyser.",
    ),
) -> None:
    """Afficher l'en-tête d'un fichier ``.crypt`` (aucun déchiffrement)."""
    try:
        cwd = Path.cwd().resolve()
        safe_source = resolve_within(path, cwd)
        if not safe_source.is_file():
            typer.echo(f"Fichier introuvable : {safe_source}", err=True)
            raise typer.Exit(1)
        info = inspect_container(safe_source)
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
    except OSError as exc:
        typer.echo(f"Erreur disque : {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Fichier          : {info.path}")
    typer.echo(f"Format version   : {info.version}")
    typer.echo(f"KDF              : {info.kdf_name} (id=0x{info.kdf_id:02x})")
    typer.echo(f"KDF paramètres   : {info.kdf_params_summary}")
    typer.echo(f"Salt (hex)       : {info.salt_hex}")
    typer.echo(f"Nonce de base    : {info.base_nonce_hex}")
    typer.echo(f"Taille en-tête   : {info.header_size} octets")
    typer.echo(f"Taille ciphertxt : {info.ciphertext_size} octets")

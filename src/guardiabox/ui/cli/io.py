"""Shared I/O helpers for the CLI layer.

Centralises three concerns that were previously duplicated across the
per-command modules:

* :class:`ExitCode` — POSIX-ish exit code constants, used by every
  command so the mapping stays uniform.
* :func:`exit_for` — maps a domain exception to a localised French
  user-facing message and the matching exit code. Crucially enforces
  the **anti-oracle** guarantee for :class:`DecryptionError` /
  :class:`IntegrityError`: both surface the exact same stderr line, so
  an attacker cannot distinguish "wrong password" from "tampered
  ciphertext" by observing the CLI's output.
* :func:`read_password` — single password-prompt helper (no-echo,
  optional confirmation, optional stdin read).
"""

from __future__ import annotations

from enum import IntEnum
import sys
from typing import NoReturn

import typer

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    CryptoEraseRequiresVaultUserError,
    DecryptionError,
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    GuardiaBoxError,
    IntegrityError,
    InvalidContainerError,
    KeyNotFoundError,
    MessageTooLargeError,
    PathTraversalError,
    ShareExpiredError,
    SymlinkEscapeError,
    UnknownKdfError,
    UnsupportedVersionError,
    VaultUserNotFoundError,
    WeakKdfParametersError,
    WeakPasswordError,
)
from guardiabox.security.vault_admin import (
    VaultAdminConfigAlreadyExistsError,
    VaultAdminConfigInvalidError,
    VaultAdminConfigMissingError,
)

__all__ = [
    "ANTI_ORACLE_MESSAGE",
    "ExitCode",
    "exit_for",
    "read_password",
]


class ExitCode(IntEnum):
    """POSIX-aligned process exit codes used by every GuardiaBox CLI command.

    The mapping follows the table in ``docs/specs/000-cli/plan.md``:

    * ``0`` success
    * ``1`` generic / unrecoverable error
    * ``2`` wrong password or decryption failed (anti-oracle branch)
    * ``3`` file not found, path refused
    * ``64`` usage error (EX_USAGE)
    * ``65`` data error (EX_DATAERR) — malformed container, unknown KDF, etc.
    * ``78`` configuration error (EX_CONFIG)
    * ``130`` interrupted by user (SIGINT)
    """

    OK = 0
    GENERIC = 1
    AUTH_FAILED = 2
    PATH_OR_FILE = 3
    USAGE = 64
    DATA_ERROR = 65
    CONFIG_ERROR = 78
    INTERRUPTED = 130


# Single source of truth for the "decryption failed" message. Referenced by
# tests asserting the anti-oracle guarantee — any change here must keep the
# message identical for both wrong-password and tampered-ciphertext failures.
ANTI_ORACLE_MESSAGE: str = "Échec du déchiffrement : mot de passe incorrect ou données altérées."


def exit_for(exc: BaseException) -> NoReturn:  # noqa: PLR0912, PLR0915 -- wide dispatch by design
    """Emit the localised message for ``exc`` and exit with the mapped code.

    Never returns — always raises :class:`typer.Exit`. Pass-through for
    already-wrapped :class:`typer.Exit` so a caller that already
    requested a specific exit code keeps it.

    The branch count is intentional: each GuardiaBox exception class
    maps to a distinct French-language message and POSIX exit code; a
    lookup dict would hide the per-branch wording that tests read.
    """
    if isinstance(exc, typer.Exit):
        raise exc

    if isinstance(exc, KeyboardInterrupt):
        raise typer.Exit(code=ExitCode.INTERRUPTED) from exc

    if isinstance(exc, WeakPasswordError):
        typer.echo(f"Mot de passe trop faible (score zxcvbn < 3) : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    if isinstance(exc, (PathTraversalError, SymlinkEscapeError)):
        typer.echo(f"Chemin refusé : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, DestinationCollidesWithSourceError):
        typer.echo(
            f"Destination identique à la source (écrasement refusé) : {exc}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, DestinationAlreadyExistsError):
        typer.echo(
            f"Destination déjà existante (utiliser --force pour écraser) : {exc}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, MessageTooLargeError):
        typer.echo(f"Message trop volumineux : {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, VaultAdminConfigMissingError):
        typer.echo(f"Coffre non initialisé : {exc}", err=True)
        raise typer.Exit(code=ExitCode.CONFIG_ERROR) from exc

    if isinstance(exc, VaultAdminConfigAlreadyExistsError):
        typer.echo(
            f"Coffre déjà initialisé (retirer le fichier pour recommencer) : {exc}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, VaultAdminConfigInvalidError):
        typer.echo(f"Configuration du coffre invalide : {exc}", err=True)
        raise typer.Exit(code=ExitCode.CONFIG_ERROR) from exc

    if isinstance(exc, VaultUserNotFoundError):
        typer.echo(f"Utilisateur du coffre introuvable : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, KeyNotFoundError):
        typer.echo(f"Cible introuvable dans le coffre : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, CryptoEraseRequiresVaultUserError):
        typer.echo(f"Mode crypto-erase non applicable : {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if isinstance(exc, ShareExpiredError):
        typer.echo(f"Jeton de partage expiré : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    if isinstance(exc, FileNotFoundError):
        typer.echo(f"Fichier introuvable : {exc}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE) from exc

    if isinstance(exc, (InvalidContainerError, UnsupportedVersionError)):
        typer.echo(f"Conteneur invalide : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    if isinstance(exc, (UnknownKdfError, WeakKdfParametersError)):
        typer.echo(f"Paramètres KDF non supportés : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    if isinstance(exc, CorruptedContainerError):
        typer.echo(f"Conteneur corrompu : {exc}", err=True)
        raise typer.Exit(code=ExitCode.DATA_ERROR) from exc

    # Anti-oracle: DecryptionError (wrong password OR tag mismatch) and
    # IntegrityError (explicit tamper detection) collapse into the exact
    # same user-facing output. No exception detail is surfaced — that
    # would leak information about which failure mode fired.
    if isinstance(exc, (DecryptionError, IntegrityError)):
        typer.echo(ANTI_ORACLE_MESSAGE, err=True)
        raise typer.Exit(code=ExitCode.AUTH_FAILED) from exc

    if isinstance(exc, OSError):
        typer.echo(f"Erreur disque : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    if isinstance(exc, GuardiaBoxError):
        typer.echo(f"Erreur GuardiaBox : {exc}", err=True)
        raise typer.Exit(code=ExitCode.GENERIC) from exc

    # Unknown exception — should not happen in normal flow; surface it
    # rather than hide it under a generic code.
    typer.echo(f"Erreur inattendue : {type(exc).__name__}: {exc}", err=True)
    raise typer.Exit(code=ExitCode.GENERIC) from exc


def read_password(*, stdin: bool, confirm: bool = False, prompt: str = "Mot de passe") -> str:
    """Return a password from stdin or an interactive no-echo prompt.

    Stripping is conservative: only the trailing newline / carriage return
    of the stdin line is removed, other whitespace is kept verbatim so a
    legitimate trailing-space password is preserved.

    An empty password is refused fail-loud instead of silently falling
    through ``read_password`` then being caught much later by the
    policy layer. A non-TTY stdin without ``--password-stdin`` almost
    always means "the user piped nothing and typer will fail with a
    confusing error"; we surface a clear message instead.
    """
    if stdin:
        raw = sys.stdin.readline()
        if raw.endswith("\r\n"):
            password = raw[:-2]
        elif raw.endswith("\n"):
            password = raw[:-1]
        else:
            password = raw
        if not password:
            typer.echo(
                "Erreur : mot de passe vide reçu sur stdin (--password-stdin).",
                err=True,
            )
            raise typer.Exit(code=ExitCode.USAGE)
        return password

    if not sys.stdin.isatty():
        typer.echo(
            "Erreur : stdin n'est pas un terminal. Utiliser --password-stdin "
            "et fournir le mot de passe par un pipe.",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    result: str = typer.prompt(
        prompt,
        hide_input=True,
        confirmation_prompt=confirm,
    )
    if not result:
        typer.echo("Erreur : mot de passe vide.", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    return result

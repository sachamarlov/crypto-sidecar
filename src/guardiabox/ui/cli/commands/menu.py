"""``guardiabox menu`` — interactive REPL satisfying the CDC F-7 requirement.

The academic brief (``docs/cahier-des-charges/``) explicitly requires
a console menu with the three mandatory options:

    1. Chiffrer un fichier ou un message
    2. Déchiffrer un fichier ou un message
    3. Quitter

This module implements that menu on top of Rich's :class:`Prompt` so the
same colour / line-wrapping behaviour as the rest of the CLI is kept.
Each numbered action delegates to :mod:`guardiabox.core.operations` —
no business logic is duplicated.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
import typer

from guardiabox.core.operations import (
    decrypt_file,
    decrypt_message,
    encrypt_file,
    encrypt_message,
    inspect_container,
)
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.cli.io import ExitCode, exit_for, read_password
from guardiabox.ui.cli.main import app

_console = Console()


@app.command("menu")
def menu_command() -> None:
    """Lancer le menu console interactif (CDC F-7)."""
    cwd = Path.cwd().resolve()
    try:
        _run_repl(cwd)
    except (KeyboardInterrupt, EOFError):
        _console.print()
        _console.print("[yellow]Interrompu par l'utilisateur.[/yellow]")
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except Exception as exc:
        exit_for(exc)


def _run_repl(cwd: Path) -> None:
    _console.print(
        Panel.fit(
            "[bold]GuardiaBox — menu interactif[/bold]\n"
            "Coffre-fort numérique local. Saisissez un chiffre pour choisir une action.",
            border_style="cyan",
        )
    )

    while True:
        _console.print()
        _console.print("[bold]Actions :[/bold]")
        _console.print(" [cyan]1[/cyan] Chiffrer un fichier ou un message")
        _console.print(" [cyan]2[/cyan] Déchiffrer un fichier ou un message")
        _console.print(" [cyan]3[/cyan] Inspecter un conteneur .crypt (sans déchiffrement)")
        _console.print(" [cyan]4[/cyan] Supprimer un fichier de manière sécurisée")
        _console.print(" [cyan]q[/cyan] Quitter")
        choice = Prompt.ask("Choix", choices=["1", "2", "3", "4", "q"], default="q")

        if choice == "q":
            _console.print("[green]Au revoir.[/green]")
            return

        try:
            if choice == "1":
                _flow_encrypt(cwd)
            elif choice == "2":
                _flow_decrypt(cwd)
            elif choice == "3":
                _flow_inspect(cwd)
            elif choice == "4":
                _flow_secure_delete(cwd)
        except typer.Exit:
            raise
        except Exception as exc:
            # REPL: exit_for renders the error, then we swallow its
            # typer.Exit so the loop continues instead of killing the
            # session on a single failure.
            try:
                exit_for(exc)
            except typer.Exit:
                _console.print("[red]Opération annulée.[/red]")


def _flow_encrypt(cwd: Path) -> None:
    mode = Prompt.ask("Fichier (f) ou message (m) ?", choices=["f", "m"], default="f")
    kdf_choice = Prompt.ask(
        "Algorithme de dérivation",
        choices=["pbkdf2", "argon2id"],
        default="pbkdf2",
    )
    from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf

    kdf = Argon2idKdf() if kdf_choice == "argon2id" else Pbkdf2Kdf()

    if mode == "f":
        source = resolve_within(Path(Prompt.ask("Chemin du fichier à chiffrer")), cwd)
        if not source.is_file():
            _console.print(f"[red]Fichier introuvable : {source}[/red]")
            return
        dest_raw = Prompt.ask("Chemin de sortie", default=str(source) + ".crypt")
        dest = resolve_within(Path(dest_raw), cwd)
        password = read_password(stdin=False, confirm=True)
        target = encrypt_file(source, password, root=cwd, kdf=kdf, dest=dest)
        _console.print(f"[green]Chiffré :[/green] {target}")
        return

    text = Prompt.ask("Message à chiffrer (UTF-8)")
    dest = resolve_within(Path(Prompt.ask("Chemin de sortie (.crypt)")), cwd)
    password = read_password(stdin=False, confirm=True)
    target = encrypt_message(text.encode("utf-8"), password, root=cwd, dest=dest, kdf=kdf)
    _console.print(f"[green]Chiffré :[/green] {target}")


def _flow_decrypt(cwd: Path) -> None:
    source = resolve_within(Path(Prompt.ask("Chemin du fichier .crypt")), cwd)
    if not source.is_file():
        _console.print(f"[red]Fichier introuvable : {source}[/red]")
        return

    to_stdout = Confirm.ask(
        "Afficher le contenu sur la console (au lieu d'un fichier) ?",
        default=False,
    )
    password = read_password(stdin=False)

    if to_stdout:
        plaintext = decrypt_message(source, password)
        try:
            _console.print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            _console.print("[yellow]Contenu binaire — non affiché.[/yellow]")
        return

    dest_raw = Prompt.ask("Chemin de sortie", default="")
    dest = resolve_within(Path(dest_raw), cwd) if dest_raw else None
    target = decrypt_file(source, password, root=cwd, dest=dest)
    _console.print(f"[green]Déchiffré :[/green] {target}")


def _flow_inspect(cwd: Path) -> None:
    source = resolve_within(Path(Prompt.ask("Chemin du fichier .crypt")), cwd)
    if not source.is_file():
        _console.print(f"[red]Fichier introuvable : {source}[/red]")
        return
    info = inspect_container(source)
    _console.print(
        f"[bold]Fichier :[/bold] {info.path}\n"
        f"[bold]Version :[/bold] {info.version}\n"
        f"[bold]KDF :[/bold] {info.kdf_name} (id=0x{info.kdf_id:02x})\n"
        f"[bold]Paramètres :[/bold] {info.kdf_params_summary}\n"
        f"[bold]Salt :[/bold] {info.salt_hex}\n"
        f"[bold]Nonce :[/bold] {info.base_nonce_hex}\n"
        f"[bold]En-tête :[/bold] {info.header_size} octets\n"
        f"[bold]Ciphertexte :[/bold] {info.ciphertext_size} octets"
    )


def _flow_secure_delete(cwd: Path) -> None:
    from guardiabox.core.secure_delete import secure_delete
    from guardiabox.fileio.platform import is_ssd

    target = resolve_within(Path(Prompt.ask("Chemin du fichier à supprimer")), cwd)
    if not target.is_file():
        _console.print(f"[red]Fichier introuvable : {target}[/red]")
        return

    ssd = is_ssd(target)
    if ssd is True:
        _console.print(
            "[yellow]Support SSD détecté. L'écrasement est un effort "
            "best-effort sur flash (NIST SP 800-88r2).[/yellow]"
        )
        if not Confirm.ask("Continuer quand même ?", default=False):
            return

    passes = int(Prompt.ask("Nombre de passes", default="3"))
    secure_delete(target, passes=passes)
    _console.print(f"[green]Supprimé :[/green] {target}")

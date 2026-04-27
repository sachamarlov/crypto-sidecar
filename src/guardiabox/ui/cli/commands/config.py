"""``guardiabox config`` — read the runtime settings (T-000cli.08).

Sub-Typer with two operations:

* ``config list`` — print every key/value pair from
  :class:`guardiabox.config.Settings` (and its nested groups).
* ``config get <key>`` — print one value, dotted path supported
  (e.g. ``crypto.pbkdf2_iterations``).

The ``set`` operation is intentionally **not** part of MVP: pydantic-
settings is sourced from environment variables and ``.env`` files; a
persistent ``set`` would require either writing to ``.env`` (tied to
the cwd, surprising for a CLI) or a project-managed TOML file (a new
storage to design + audit). Documented as a post-MVP follow-up — for
now, users override values via ``GUARDIABOX_<KEY>`` env vars or by
editing ``.env``.
"""

from __future__ import annotations

from typing import Any

import typer

from guardiabox.config import get_settings
from guardiabox.ui.cli.io import ExitCode
from guardiabox.ui.cli.main import app

config_app = typer.Typer(
    name="config",
    help="Lire la configuration courante (env vars + .env). 'set' réservé post-MVP.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(config_app, name="config")


def _settings_to_flat_dict() -> dict[str, Any]:
    """Flatten the nested Settings model into ``dotted.key -> value`` pairs."""
    settings = get_settings()
    raw = settings.model_dump()
    return _flatten(raw, parent="")


def _flatten(node: Any, *, parent: str) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    if not isinstance(node, dict):
        return {parent: node}
    for key, value in node.items():
        full = f"{parent}.{key}" if parent else key
        if isinstance(value, dict):
            flat.update(_flatten(value, parent=full))
        else:
            flat[full] = value
    return flat


@config_app.command("list")
def config_list() -> None:
    """Afficher toutes les valeurs courantes (clé : valeur)."""
    flat = _settings_to_flat_dict()
    width = max((len(k) for k in flat), default=0)
    for key in sorted(flat):
        typer.echo(f"{key.ljust(width)} : {flat[key]}")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(
        ...,
        help="Clé en notation pointée (ex. crypto.pbkdf2_iterations).",
    ),
) -> None:
    """Afficher la valeur d'une clé."""
    flat = _settings_to_flat_dict()
    if key not in flat:
        typer.echo(f"Clé inconnue : {key}", err=True)
        raise typer.Exit(code=ExitCode.PATH_OR_FILE)
    typer.echo(str(flat[key]))


@config_app.command("set")
def config_set(
    _key: str = typer.Argument(..., metavar="KEY"),
    _value: str = typer.Argument(..., metavar="VALUE"),
) -> None:
    """Persister une valeur (réservé post-MVP)."""
    typer.echo(
        "Erreur : 'config set' n'est pas disponible dans le MVP.\n"
        "Utiliser une variable d'environnement GUARDIABOX_<KEY> ou éditer le .env "
        "dans le répertoire courant.",
        err=True,
    )
    raise typer.Exit(code=ExitCode.USAGE)

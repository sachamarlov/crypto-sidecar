"""User-facing adapters.

Three independent front-ends share the :mod:`guardiabox.core` engine:

* :mod:`guardiabox.ui.cli`     — Typer command-line interface.
* :mod:`guardiabox.ui.tui`     — Textual rich-terminal interface.
* :mod:`guardiabox.ui.tauri`   — FastAPI sidecar consumed by the React/Tauri shell.
"""

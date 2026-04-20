"""Textual application skeleton.

The implementation will mirror the desktop GUI's information architecture
(sidebar, vault table, action bar) within terminal constraints.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header


class GuardiaBoxApp(App[None]):
    """Top-level Textual application."""

    TITLE = "GuardiaBox"
    SUB_TITLE = "Local secure vault"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()

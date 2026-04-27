"""Textual screens for the GuardiaBox TUI."""

from __future__ import annotations

from guardiabox.ui.tui.screens.dashboard import DashboardScreen
from guardiabox.ui.tui.screens.decrypt import DecryptScreen
from guardiabox.ui.tui.screens.encrypt import EncryptScreen
from guardiabox.ui.tui.screens.history import HistoryScreen
from guardiabox.ui.tui.screens.settings import SettingsScreen
from guardiabox.ui.tui.screens.share import ShareScreen

__all__ = [
    "DashboardScreen",
    "DecryptScreen",
    "EncryptScreen",
    "HistoryScreen",
    "SettingsScreen",
    "ShareScreen",
]

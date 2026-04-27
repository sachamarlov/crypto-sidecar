"""Integration tests for the TUI Phase F (Textual app).

Uses :meth:`textual.app.App.run_test` which spins the app inside the
asyncio event loop without real terminal I/O. Each test asserts on the
DOM tree -- presence of widgets, focus, screen stack -- rather than on
ANSI output. That gives us deterministic checks without pulling in
``pytest-textual-snapshot`` (deferred post-MVP).
"""

from __future__ import annotations

import pytest

from guardiabox.ui.tui.app import GuardiaBoxApp
from guardiabox.ui.tui.main import _is_reduced_motion
from guardiabox.ui.tui.screens.dashboard import DashboardScreen
from guardiabox.ui.tui.screens.decrypt import DecryptScreen
from guardiabox.ui.tui.screens.encrypt import EncryptScreen
from guardiabox.ui.tui.screens.history import HistoryScreen
from guardiabox.ui.tui.screens.settings import SettingsScreen
from guardiabox.ui.tui.screens.share import ShareScreen
from guardiabox.ui.tui.widgets.password_field import PasswordField
from guardiabox.ui.tui.widgets.toast import Toast, ToastVariant

# ---------------------------------------------------------------------------
# App boot + screen stack
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_app_boots_with_dashboard_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        # The default screen is DashboardScreen, pushed in on_mount.
        assert isinstance(app.screen, DashboardScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pressing_e_pushes_encrypt_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, EncryptScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pressing_d_pushes_decrypt_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, DecryptScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pressing_s_pushes_share_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, ShareScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pressing_h_pushes_history_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("h")
        await pilot.pause()
        assert isinstance(app.screen, HistoryScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pressing_c_pushes_settings_screen() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_share_screen_close_button_pops_back_to_dashboard() -> None:
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, ShareScreen)
        # Pop via the close button.
        await pilot.click("#share-close")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


# ---------------------------------------------------------------------------
# PasswordField + Toast unit-ish checks (require an App context)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_password_field_updates_reactive_on_input() -> None:
    """The reactive ``password`` attribute mirrors what was typed."""
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        pwd = app.screen.query_one("#encrypt-password", PasswordField)
        from textual.widgets import Input

        inp = pwd.query_one("#password-input", Input)
        # Programmatic assignment fires the Changed event handler.
        sample_pw = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
        inp.value = sample_pw
        await pilot.pause()
        assert pwd.password == sample_pw


@pytest.mark.integration
@pytest.mark.asyncio
async def test_toast_mounts_in_dom_and_auto_dismisses() -> None:
    """Toast appears in the screen DOM, then self-removes after timeout."""
    app = GuardiaBoxApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        toast = Toast("test message", variant=ToastVariant.INFO, timeout=1.0)
        await app.screen.mount(toast)
        await pilot.pause(0.05)
        # The toast lives under the screen subtree.
        toasts = list(app.screen.query(Toast))
        assert len(toasts) == 1
        # Wait past the timeout and verify it auto-removed.
        await pilot.pause(1.5)
        toasts_after = list(app.screen.query(Toast))
        assert len(toasts_after) == 0


@pytest.mark.integration
def test_toast_variant_class_mapping() -> None:
    """Each variant adds a ``toast-<variant>`` CSS class."""
    for variant in ToastVariant:
        toast = Toast("msg", variant=variant)
        assert f"toast-{variant.value}" in toast.classes
        assert "toast" in toast.classes


# ---------------------------------------------------------------------------
# Reduced-motion entry point probe (T-000tui.13)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_reduced_motion_detects_term_dumb(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.delenv("CI", raising=False)
    assert _is_reduced_motion() is True


@pytest.mark.integration
def test_reduced_motion_detects_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("CI", "true")
    assert _is_reduced_motion() is True


@pytest.mark.integration
def test_reduced_motion_off_for_normal_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("CI", raising=False)
    assert _is_reduced_motion() is False

"""No-echo password input + live zxcvbn strength bar (T-000tui.04).

The widget composes an :class:`Input` with ``password=True`` and a
:class:`Static` indicator that updates on every keystroke with the
zxcvbn score and a coloured strength bar. Score thresholds align with
:mod:`guardiabox.security.password` policy: score < 3 is rejected by
the policy layer; we surface the live verdict so the user knows
**before** they submit.

The strength label is rendered with rich markup (``[red]``, ``[yellow]``,
``[green]``) for visual feedback in the dark theme.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import Input, Static

from guardiabox.security.password import evaluate

_BAR_STEPS: int = 20
"""Width of the strength bar in characters (visual only)."""


def _score_to_label(score: int) -> str:
    """Map zxcvbn score (0..4) to a coloured label + tip."""
    if score >= 4:
        return "[bold green]Excellent[/bold green]"
    if score == 3:
        return "[green]Bon[/green]"
    if score == 2:
        return "[yellow]Moyen[/yellow]"
    if score == 1:
        return "[red]Faible[/red]"
    return "[bold red]Très faible[/bold red]"


def _score_to_bar(score: int) -> str:
    """Render a 20-char strength bar coloured by zxcvbn score."""
    filled = int((score / 4) * _BAR_STEPS) if score > 0 else 1
    color = "green" if score >= 3 else ("yellow" if score == 2 else "red")
    return f"[{color}]{'█' * filled}[/{color}]{'░' * (_BAR_STEPS - filled)}"


class PasswordField(Vertical):
    """A composite widget: password Input + zxcvbn live strength indicator.

    Parent screens read the typed password via :attr:`password`
    (reactive). The indicator is purely visual — the policy enforcement
    (length >= 12, score >= 3) lives in
    :func:`guardiabox.security.password.assert_strong` which the screen
    calls on submit.
    """

    DEFAULT_CSS = """
    PasswordField {
        height: auto;
    }
    PasswordField > Input {
        margin-bottom: 0;
    }
    PasswordField > Static {
        margin-bottom: 1;
    }
    """

    password: reactive[str] = reactive("")

    def __init__(
        self,
        *,
        placeholder: str = "Mot de passe",
        widget_id: str | None = None,
        live_strength: bool = True,
    ) -> None:
        super().__init__(id=widget_id)
        self._placeholder = placeholder
        self._live_strength = live_strength

    def compose(self) -> ComposeResult:
        yield Input(
            placeholder=self._placeholder,
            password=True,
            id="password-input",
        )
        if self._live_strength:
            yield Static("Force : (saisir un mot de passe)", id="zxcvbn-strength")

    def on_input_changed(self, event: Input.Changed) -> None:
        """Update the strength indicator on every keystroke."""
        if event.input.id != "password-input":
            return
        self.password = event.value
        if not self._live_strength:
            return
        indicator = self.query_one("#zxcvbn-strength", Static)
        if not event.value:
            indicator.update("Force : (saisir un mot de passe)")
            return
        try:
            outcome = evaluate(event.value)
        except Exception:
            indicator.update("Force : (évaluation indisponible)")
            return
        label = _score_to_label(outcome.score)
        bar = _score_to_bar(outcome.score)
        indicator.update(f"Force : {label}  {bar}")

    def clear(self) -> None:
        """Reset the input + indicator, e.g. after submit."""
        self.query_one("#password-input", Input).value = ""  # nosec B105 -- empty reset
        self.password = ""  # nosec B105 -- reactive reset
        if self._live_strength:
            self.query_one("#zxcvbn-strength", Static).update("Force : (saisir un mot de passe)")

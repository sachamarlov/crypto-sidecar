"""Password policy and strength estimation.

Backed by :mod:`zxcvbn` for entropy estimation rather than naive char-class
checks ("must contain a symbol"). Real passwords are scored 0..4; we require
at least 3 by default and surface the estimated cracking time to the UI.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Final

from zxcvbn import zxcvbn

from guardiabox.core.exceptions import WeakPasswordError

__all__ = [
    "MIN_LENGTH",
    "MIN_ZXCVBN_SCORE",
    "StrengthReport",
    "WeakPasswordError",
    "assert_strong",
    "evaluate",
]

MIN_LENGTH: Final[int] = 12
MIN_ZXCVBN_SCORE: Final[int] = 3


@dataclass(frozen=True, slots=True)
class StrengthReport:
    """Outcome of :func:`evaluate`."""

    score: int
    entropy_bits: float
    crack_time_seconds: float
    feedback: tuple[str, ...]


def evaluate(password: str) -> StrengthReport:
    """Run zxcvbn against ``password`` and return a structured report.

    ``crack_time_seconds`` is the ``offline_slow_hashing_1e4_per_second``
    estimate, representative of an attacker with a realistic Argon2id-class
    KDF budget. Entropy is derived from ``log2(guesses)``.
    """
    raw: dict[str, Any] = zxcvbn(password)
    score: int = int(raw["score"])
    guesses: float = max(float(raw.get("guesses", 1)), 1.0)
    crack_times: dict[str, Any] = raw.get("crack_times_seconds") or {}
    crack_time_seconds: float = float(crack_times.get("offline_slow_hashing_1e4_per_second", 0.0))
    feedback = _collect_feedback(raw.get("feedback") or {})
    return StrengthReport(
        score=score,
        entropy_bits=math.log2(guesses),
        crack_time_seconds=crack_time_seconds,
        feedback=feedback,
    )


def assert_strong(password: str) -> None:
    """Raise :class:`WeakPasswordError` if the policy is not met."""
    if len(password) < MIN_LENGTH:
        raise WeakPasswordError(
            f"password must be at least {MIN_LENGTH} characters (got {len(password)})"
        )
    report = evaluate(password)
    if report.score < MIN_ZXCVBN_SCORE:
        hint = " ; ".join(report.feedback) if report.feedback else "low entropy"
        raise WeakPasswordError(
            f"password strength {report.score}/4 below required {MIN_ZXCVBN_SCORE}/4: {hint}"
        )


def _collect_feedback(feedback: dict[str, Any]) -> tuple[str, ...]:
    messages: list[str] = []
    warning = feedback.get("warning") or ""
    if warning:
        messages.append(str(warning))
    suggestions = feedback.get("suggestions") or []
    messages.extend(str(s) for s in suggestions if s)
    return tuple(messages)

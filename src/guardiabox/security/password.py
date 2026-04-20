"""Password policy and strength estimation.

Backed by :mod:`zxcvbn` for entropy estimation rather than naive char-class
checks ("must contain a symbol"). Real passwords are scored 0..4; we require
at least 3 by default and surface the estimated cracking time to the UI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

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
    """Run zxcvbn against ``password`` and return a structured report."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")


def assert_strong(password: str) -> None:
    """Raise :class:`WeakPasswordError` if the policy is not met."""
    raise NotImplementedError("See docs/specs/001-encrypt-file/plan.md")

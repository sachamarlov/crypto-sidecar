"""Tests for :mod:`guardiabox.security.password`."""

from __future__ import annotations

import pytest

from guardiabox.core.exceptions import WeakPasswordError
from guardiabox.security.password import (
    MAX_LENGTH,
    MIN_LENGTH,
    MIN_ZXCVBN_SCORE,
    assert_strong,
    evaluate,
)


@pytest.mark.parametrize(
    "password",
    [
        "password",
        "123456",
        "letmein",
        "qwerty123",
    ],
)
def test_known_weak_passwords_rejected(password: str) -> None:
    with pytest.raises(WeakPasswordError):
        assert_strong(password)


@pytest.mark.parametrize(
    "password",
    [
        "Correct_Horse_Battery_Staple_42!",
        "Tr0ub4dor&3x_P-Long-Passphrase_zz",
        "anti-gravity-green-tea-eclipse-7#",
    ],
)
def test_known_strong_passwords_accepted(password: str) -> None:
    assert_strong(password)


def test_password_shorter_than_min_length_rejected() -> None:
    short = "Ab1!" * (MIN_LENGTH // 5)
    with pytest.raises(WeakPasswordError, match="at least"):
        assert_strong(short)


def test_evaluate_reports_score_and_entropy() -> None:
    report = evaluate("Correct_Horse_Battery_Staple_42!")
    assert 0 <= report.score <= 4
    assert report.score >= MIN_ZXCVBN_SCORE
    assert report.entropy_bits > 0
    assert report.crack_time_seconds >= 0
    assert isinstance(report.feedback, tuple)


def test_evaluate_short_password_has_feedback() -> None:
    report = evaluate("abc")
    assert report.score < MIN_ZXCVBN_SCORE


def test_long_but_low_entropy_password_rejected_via_score() -> None:
    """A 12+ character password that zxcvbn still scores below 3 must raise.

    The length check passes but the score check then fails, exercising the
    ``assert_strong`` branch that crafts the score-based error message.
    """
    long_but_weak = "password12345"  # 13 chars, zxcvbn dictionary hit
    with pytest.raises(WeakPasswordError, match="strength"):
        assert_strong(long_but_weak)


def test_long_but_low_entropy_password_error_mentions_feedback() -> None:
    long_but_weak = "passwordpassword"
    with pytest.raises(WeakPasswordError) as exc_info:
        assert_strong(long_but_weak)
    # Either the feedback text or the generic "low entropy" must appear.
    message = str(exc_info.value)
    assert "strength" in message


def test_password_above_max_length_rejected_before_zxcvbn() -> None:
    """Fix-1.L -- a huge input must fail fast before zxcvbn walks it."""
    oversized = "A" * (MAX_LENGTH + 1)
    with pytest.raises(WeakPasswordError, match="maximum"):
        assert_strong(oversized)

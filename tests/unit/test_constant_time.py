"""Tests for :func:`guardiabox.security.constant_time.equal_constant_time`."""

from __future__ import annotations

import pytest

from guardiabox.security.constant_time import equal_constant_time


def test_equal_on_identical_bytes() -> None:
    assert equal_constant_time(b"abc123", b"abc123") is True


def test_unequal_on_different_content() -> None:
    assert equal_constant_time(b"abc123", b"abc124") is False


def test_unequal_on_different_length() -> None:
    assert equal_constant_time(b"abc", b"abc123") is False


def test_empty_inputs_equal() -> None:
    assert equal_constant_time(b"", b"") is True


def test_accepts_bytearray_and_memoryview() -> None:
    assert equal_constant_time(bytearray(b"hello"), b"hello") is True
    assert equal_constant_time(memoryview(b"hello"), b"hello") is True


def test_rejects_non_bytes_like() -> None:
    with pytest.raises(TypeError):
        equal_constant_time("abc", b"abc")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        equal_constant_time(b"abc", 42)  # type: ignore[arg-type]

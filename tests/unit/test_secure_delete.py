"""Tests for :mod:`guardiabox.core.secure_delete`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.secure_delete import (
    DEFAULT_OVERWRITE_PASSES,
    MAX_OVERWRITE_PASSES,
    SecureDeleteMethod,
    secure_delete,
)


def test_overwrite_removes_file(tmp_path: Path) -> None:
    target = tmp_path / "sensitive.bin"
    target.write_bytes(b"A" * 4096)
    secure_delete(target)
    assert not target.exists()


def test_overwrite_unlinks_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    secure_delete(target)
    assert not target.exists()


def test_overwrite_large_file(tmp_path: Path) -> None:
    target = tmp_path / "big.bin"
    target.write_bytes(b"Q" * (1024 * 1024 + 17))  # > chunk size and not aligned
    secure_delete(target)
    assert not target.exists()


def test_default_passes_is_three() -> None:
    assert DEFAULT_OVERWRITE_PASSES == 3


def test_passes_must_be_positive(tmp_path: Path) -> None:
    target = tmp_path / "t.bin"
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="passes"):
        secure_delete(target, passes=0)
    assert target.exists()


def test_passes_above_max_refused(tmp_path: Path) -> None:
    """Fix-1.K -- DoS guard: an unreasonable ``passes`` is refused before
    any I/O. The file must survive the error."""
    target = tmp_path / "t.bin"
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="passes"):
        secure_delete(target, passes=MAX_OVERWRITE_PASSES + 1)
    assert target.exists()


def test_passes_at_max_accepted(tmp_path: Path) -> None:
    """The exact ceiling ``MAX_OVERWRITE_PASSES`` is still valid."""
    target = tmp_path / "ceiling.bin"
    target.write_bytes(b"x")
    secure_delete(target, passes=MAX_OVERWRITE_PASSES)
    assert not target.exists()


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        secure_delete(tmp_path / "nope.bin")


def test_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IsADirectoryError):
        secure_delete(tmp_path)


def test_unsupported_method_raises(tmp_path: Path) -> None:
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")

    class _Bogus:
        value = "nope"

    with pytest.raises(ValueError, match="unsupported method"):
        secure_delete(target, method=_Bogus())  # type: ignore[arg-type]


def test_secure_delete_method_enum_has_overwrite_only() -> None:
    """Until Phase B2 lands, CRYPTO_ERASE must not be selectable."""
    values = {m.value for m in SecureDeleteMethod}
    assert values == {"overwrite-dod"}


@pytest.mark.parametrize("passes", [1, 2, 3, 5, 7])
def test_variable_passes(tmp_path: Path, passes: int) -> None:
    target = tmp_path / f"p{passes}.bin"
    target.write_bytes(b"Z" * 513)
    secure_delete(target, passes=passes)
    assert not target.exists()


def test_patterns_cycle_through_zero_one_random(tmp_path: Path) -> None:
    """Byte-level check: intermediate passes leave the expected fill.

    We can't observe the intermediate file contents after ``secure_delete``
    completes (the file is unlinked), so we exercise the internal
    ``_overwrite_dod`` directly with a 3-pass count and inspect the file
    bytes after the last pass without unlinking.
    """
    from guardiabox.core.secure_delete import _overwrite_dod

    target = tmp_path / "patterns.bin"
    target.write_bytes(b"original" * 128)
    # Run 3 passes — pattern cycle is [zero, one, random].
    _overwrite_dod(target, passes=3)
    # The file still exists (no unlink), and its bytes should no longer be
    # "original". They carry the random pattern of pass #3, which has
    # overwhelming probability of not matching the original.
    assert target.exists()
    final = target.read_bytes()
    assert len(final) == len(b"original" * 128)
    assert final != b"original" * 128
    assert final != b"\x00" * len(final)
    assert final != b"\xff" * len(final)

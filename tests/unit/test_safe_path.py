"""Tests for :func:`guardiabox.fileio.safe_path.resolve_within`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardiabox.core.exceptions import PathTraversalError, SymlinkEscapeError
from guardiabox.fileio.safe_path import resolve_within


def test_relative_path_is_resolved_under_root(tmp_path: Path) -> None:
    target = tmp_path / "inner" / "file.txt"
    target.parent.mkdir()
    resolved = resolve_within(Path("inner/file.txt"), tmp_path)
    assert resolved == target.resolve()


def test_absolute_path_inside_root_ok(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    resolved = resolve_within(target, tmp_path)
    assert resolved == target.resolve()


def test_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathTraversalError):
        resolve_within(Path("../outside.txt"), tmp_path)


def test_absolute_outside_root_rejected(tmp_path: Path) -> None:
    other = tmp_path.parent / "other.txt"
    with pytest.raises(PathTraversalError):
        resolve_within(other, tmp_path)


def test_root_itself_is_within(tmp_path: Path) -> None:
    resolved = resolve_within(tmp_path, tmp_path)
    assert resolved == tmp_path.resolve()


def test_symlink_rejected_when_disallowed(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_bytes(b"content")
    link = tmp_path / "link.txt"
    try:
        Path(link).symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported on this platform/user")
    with pytest.raises(SymlinkEscapeError):
        resolve_within(link, tmp_path)


def test_symlink_followed_when_allowed(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_bytes(b"content")
    link = tmp_path / "link.txt"
    try:
        Path(link).symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported on this platform/user")
    resolved = resolve_within(link, tmp_path, allow_symlinks=True)
    assert resolved == target.resolve()

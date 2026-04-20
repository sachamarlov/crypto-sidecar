"""Top-level pytest configuration and shared fixtures.

Per-suite fixtures live in ``tests/<suite>/conftest.py`` to keep the global
namespace tight and import time fast.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Always run with UTC and a deterministic seed for reproducibility.
os.environ.setdefault("TZ", "UTC")


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Absolute path to the repository root (containing pyproject.toml)."""
    return Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolate_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect GuardiaBox's data dir to a per-test tmp path.

    Prevents tests from accidentally reading or polluting the developer's real
    ``~/.guardiabox`` directory.
    """
    data_dir = tmp_path / "guardiabox-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARDIABOX_DATA_DIR", str(data_dir))
    return data_dir


@pytest.fixture(scope="session", autouse=True)
def _platform_guard() -> None:
    """Skip Windows-only assertions when running on POSIX, and vice versa."""
    if sys.platform not in {"win32", "linux", "darwin"}:
        pytest.skip(f"Unsupported platform: {sys.platform}")

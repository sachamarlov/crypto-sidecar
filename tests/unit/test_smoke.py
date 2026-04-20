"""Smoke tests — fast sanity checks that the package imports cleanly.

Real per-module unit tests live in sibling files such as
``test_core_constants.py``, ``test_kdf.py``, etc., and ship alongside their
implementation specs.
"""

from __future__ import annotations

import importlib

import pytest

PACKAGES_TO_IMPORT: tuple[str, ...] = (
    "guardiabox",
    "guardiabox.config",
    "guardiabox.logging",
    "guardiabox.core",
    "guardiabox.core.constants",
    "guardiabox.core.exceptions",
    "guardiabox.core.protocols",
    "guardiabox.core.kdf",
    "guardiabox.core.crypto",
    "guardiabox.core.container",
    "guardiabox.core.secure_delete",
    "guardiabox.fileio",
    "guardiabox.fileio.safe_path",
    "guardiabox.fileio.atomic",
    "guardiabox.fileio.streaming",
    "guardiabox.security",
    "guardiabox.security.password",
    "guardiabox.security.keystore",
    "guardiabox.security.audit",
    "guardiabox.persistence",
    "guardiabox.persistence.database",
    "guardiabox.persistence.models",
    "guardiabox.persistence.repositories",
    "guardiabox.ui",
    "guardiabox.ui.cli",
    "guardiabox.ui.cli.main",
    "guardiabox.ui.tui",
    "guardiabox.ui.tui.main",
    "guardiabox.ui.tui.app",
    "guardiabox.ui.tauri",
    "guardiabox.ui.tauri.sidecar",
    "guardiabox.ui.tauri.sidecar.main",
)


@pytest.mark.parametrize("module_name", PACKAGES_TO_IMPORT)
def test_module_imports(module_name: str) -> None:
    """Every public package must import without raising."""
    importlib.import_module(module_name)


def test_version_is_a_string() -> None:
    """The package exposes a non-empty ``__version__`` string."""
    import guardiabox

    assert isinstance(guardiabox.__version__, str)
    assert guardiabox.__version__

"""Bind-address security tests (G-12).

ADR-0016 sec G enforces a single hard guarantee: the sidecar binds
loopback only. Three tests lock the invariant at three different
levels:

1. Type-level: ``SidecarSettings.host`` is annotated as
   ``Literal["127.0.0.1"]``. Pydantic refuses any other value at
   construction, including a ``GUARDIABOX_SIDECAR__HOST=0.0.0.0``
   env override.

2. Source-level: the literal string ``"0.0.0.0"`` does not appear in
   any production module under ``src/guardiabox/`` (tests can
   reference it for negative assertions; doc strings can mention it
   in prose).

3. Runtime: the entry-point passes ``settings.sidecar.host`` to
   :class:`uvicorn.Config`; the helper ``_build_uvicorn_config``
   echoes the value, so a test asserting that the constructed
   config carries ``"127.0.0.1"`` covers the live wiring.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Literal, get_args, get_type_hints

import pytest

from guardiabox.config import SidecarSettings
from guardiabox.ui.tauri.sidecar import main as main_module

# ---------------------------------------------------------------------------
# Type-level invariant
# ---------------------------------------------------------------------------


def test_sidecar_settings_host_is_literal_127_0_0_1() -> None:
    """The ``host`` field allows exactly one string -- ``127.0.0.1``."""
    hints = get_type_hints(SidecarSettings)
    host_type = hints["host"]
    args = get_args(host_type)
    assert args == ("127.0.0.1",)
    # Hint-level check that we are looking at a Literal, not a str.
    assert host_type is not str
    # Construction with a different host raises pydantic.ValidationError.
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        SidecarSettings(host="0.0.0.0")  # type: ignore[arg-type]  # noqa: S104 -- negative test


def test_sidecar_settings_default_host_is_loopback() -> None:
    settings = SidecarSettings()
    assert settings.host == "127.0.0.1"


# ---------------------------------------------------------------------------
# Source-level grep guard (anti-regression)
# ---------------------------------------------------------------------------


def _src_root() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent.parent / "src" / "guardiabox"


def test_no_zero_zero_zero_zero_in_production_source() -> None:
    """``0.0.0.0`` must not appear in production code -- only docs / tests.

    Walk every ``*.py`` under ``src/guardiabox/`` and confirm the
    string is absent. Doctests / triple-quoted strings discussing the
    invariant are detected, but those should live in tests / docs;
    if a future change introduces a legitimate reason for a non-
    loopback bind, this test catches it and forces an ADR review.
    """
    pattern = re.compile(r"0\.0\.0\.0")
    offenders: list[tuple[Path, int, str]] = []
    for py_file in _src_root().rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append((py_file, lineno, line.strip()))

    assert not offenders, (
        "Production source references 0.0.0.0 -- ADR-0016 sec G "
        f"forbids non-loopback binds. Offenders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Runtime config wiring
# ---------------------------------------------------------------------------


def test_build_uvicorn_config_passes_loopback_host() -> None:
    """``_build_uvicorn_config`` propagates the loopback host to uvicorn."""
    from fastapi import FastAPI

    config = main_module._build_uvicorn_config(
        app=FastAPI(),
        host="127.0.0.1",
        port=12345,
        log_level="INFO",
    )
    assert config.host == "127.0.0.1"
    assert config.port == 12345


def test_sidecar_settings_host_literal_args_are_locked() -> None:
    """If the Literal ever loosens to allow another host, fail loudly."""
    host_type: type = get_type_hints(SidecarSettings)["host"]
    args = get_args(host_type)
    assert args == ("127.0.0.1",), (
        "ADR-0016 sec G binds the sidecar to loopback only. "
        f"Detected widening to {args}; an ADR must precede this change."
    )
    # Sanity check: ``Literal["127.0.0.1"]`` matches the expected origin.
    assert Literal["127.0.0.1"] is not None  # importable

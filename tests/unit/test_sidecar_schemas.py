"""Unit tests for the shared sidecar Pydantic v2 base classes (G-02)."""

from __future__ import annotations

import pydantic
import pytest

from guardiabox.ui.tauri.sidecar.api.schemas import (
    ErrorResponse,
    SidecarBaseModel,
)


class _Probe(SidecarBaseModel):
    """Minimal subclass to exercise the cross-cutting model_config."""

    name: str
    count: int


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(pydantic.ValidationError, match="Extra inputs are not permitted"):
        _Probe(name="alpha", count=1, ghost="extra")  # type: ignore[call-arg]


def test_strict_mode_rejects_loose_int_coercion() -> None:
    """A string that *looks* like an int does not slip through."""
    with pytest.raises(pydantic.ValidationError):
        _Probe(name="alpha", count="1")  # type: ignore[arg-type]


def test_instance_is_frozen() -> None:
    probe = _Probe(name="alpha", count=1)
    with pytest.raises(pydantic.ValidationError, match="frozen"):
        probe.name = "beta"  # type: ignore[misc]


def test_error_response_carries_detail_string() -> None:
    err = ErrorResponse(detail="decryption failed")
    assert err.detail == "decryption failed"

    dumped = err.model_dump()
    assert dumped == {"detail": "decryption failed"}


def test_error_response_rejects_extra_fields() -> None:
    with pytest.raises(pydantic.ValidationError):
        ErrorResponse(detail="x", code=42)  # type: ignore[call-arg]

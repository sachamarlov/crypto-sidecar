"""Property-based tests for the sidecar Pydantic schemas (G-19).

Hypothesis generates arbitrary dicts and confirms that the strict
Pydantic v2 schemas refuse every shape that drifts from the
expected contract. This catches regressions where a future schema
change accidentally widens the surface (e.g. dropping
``extra='forbid'`` somewhere).
"""

from __future__ import annotations

from hypothesis import given, strategies as st
import pydantic
import pytest

from guardiabox.ui.tauri.sidecar.api.schemas import (
    ErrorResponse,
    SidecarBaseModel,
)
from guardiabox.ui.tauri.sidecar.api.v1.encrypt import EncryptRequest
from guardiabox.ui.tauri.sidecar.api.v1.users import UserCreateRequest


@given(
    extra_key=st.text(min_size=1, max_size=20).filter(lambda s: s != "detail"),
    extra_value=st.one_of(st.text(), st.integers(), st.booleans()),
)
def test_error_response_rejects_any_extra_field(extra_key: str, extra_value: object) -> None:
    with pytest.raises(pydantic.ValidationError):
        ErrorResponse.model_validate({"detail": "x", extra_key: extra_value})


@given(detail=st.text(min_size=0, max_size=1024))
def test_error_response_accepts_arbitrary_detail_string(detail: str) -> None:
    err = ErrorResponse(detail=detail)
    assert err.detail == detail


@given(extra_key=st.text(min_size=1, max_size=15))
def test_encrypt_request_rejects_extra_fields(extra_key: str) -> None:
    if extra_key in {"path", "password", "kdf", "dest", "force"}:
        return  # legitimate field
    with pytest.raises(pydantic.ValidationError):
        EncryptRequest.model_validate(
            {
                "path": "/tmp/foo.txt",  # noqa: S108  -- never opened, schema validation only
                "password": "Correct_Horse_Battery_Staple_42!",  # pragma: allowlist secret
                extra_key: "garbage",
            }
        )


@given(kdf=st.text(min_size=1, max_size=20).filter(lambda s: s not in {"pbkdf2", "argon2id"}))
def test_user_create_rejects_kdf_outside_literal(kdf: str) -> None:
    """``kdf`` is constrained by a regex; arbitrary strings must fail."""
    with pytest.raises(pydantic.ValidationError):
        UserCreateRequest.model_validate(
            {
                "username": "alice",
                "password": "Correct_Horse_Battery_Staple_42!",  # pragma: allowlist secret
                "kdf": kdf,
            }
        )


def test_sidecar_base_model_is_frozen_via_property() -> None:
    """Programmatic check that every subclass inherits frozen=True."""

    class Probe(SidecarBaseModel):
        name: str

    p = Probe(name="alpha")
    with pytest.raises(pydantic.ValidationError):
        p.name = "beta"  # type: ignore[misc]

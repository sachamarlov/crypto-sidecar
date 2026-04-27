"""Unit tests for the sidecar token-auth middleware (G-02)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.api.middleware import (
    AUTH_EXEMPT_PATHS,
    TOKEN_HEADER,
)
from guardiabox.ui.tauri.sidecar.app import create_app

if TYPE_CHECKING:
    from fastapi import FastAPI


_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"


def _build_app(tmp_path: Path) -> FastAPI:
    """Construct an app with the test token + a `/api/v1/_probe` route."""
    settings = Settings(data_dir=tmp_path)
    app = create_app(session_token=_TEST_TOKEN, settings=settings)

    @app.get("/api/v1/_probe")
    def probe() -> dict[str, bool]:
        return {"ok": True}

    return app


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_request_with_valid_token_passes_through(tmp_path: Path) -> None:
    app = _build_app(tmp_path)
    client = TestClient(app)

    response = client.get("/api/v1/_probe", headers={TOKEN_HEADER: _TEST_TOKEN})

    assert response.status_code == 200
    assert response.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Reject path
# ---------------------------------------------------------------------------


def test_missing_token_returns_401(tmp_path: Path) -> None:
    app = _build_app(tmp_path)
    client = TestClient(app)

    response = client.get("/api/v1/_probe")

    assert response.status_code == 401
    assert response.json() == {"detail": "missing or invalid token"}


def test_wrong_token_returns_401(tmp_path: Path) -> None:
    app = _build_app(tmp_path)
    client = TestClient(app)

    response = client.get(
        "/api/v1/_probe",
        headers={TOKEN_HEADER: "this-is-not-the-right-token-xxxx"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "missing or invalid token"}


def test_response_body_is_constant_between_missing_and_wrong_token(tmp_path: Path) -> None:
    """Anti-oracle: the two failure modes must be byte-identical."""
    app = _build_app(tmp_path)
    client = TestClient(app)

    missing = client.get("/api/v1/_probe")
    wrong = client.get(
        "/api/v1/_probe",
        headers={TOKEN_HEADER: "wrong-token-payload"},
    )

    assert missing.status_code == wrong.status_code == 401
    assert missing.content == wrong.content


def test_token_comparison_uses_hmac_compare_digest(tmp_path: Path) -> None:
    """ADR-0016 sec A: constant-time compare to defeat timing attacks."""
    app = _build_app(tmp_path)
    client = TestClient(app)

    with patch(
        "guardiabox.ui.tauri.sidecar.api.middleware.hmac.compare_digest",
        wraps=__import__("hmac").compare_digest,
    ) as spy:
        client.get("/api/v1/_probe", headers={TOKEN_HEADER: _TEST_TOKEN})

    assert spy.called, "hmac.compare_digest must be invoked on every protected request"


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted(AUTH_EXEMPT_PATHS))
def test_whitelisted_path_does_not_require_token(tmp_path: Path, path: str) -> None:
    app = _build_app(tmp_path)
    client = TestClient(app)

    response = client.get(path)

    # 200 for /healthz, /version, /openapi.json; 503 for /readyz when
    # the vault is not initialised. Both prove that the auth gate did
    # not fire (which would yield 401 regardless of route).
    assert response.status_code in {200, 503}
    if response.status_code == 401:  # pragma: no cover
        msg = "whitelisted path should never return 401"
        raise AssertionError(msg)


def test_whitelist_is_an_immutable_frozenset() -> None:
    """Make sure the whitelist cannot be mutated at runtime by a router."""
    assert isinstance(AUTH_EXEMPT_PATHS, frozenset)
    with pytest.raises(AttributeError):
        AUTH_EXEMPT_PATHS.add("/api/v1/inject")  # type: ignore[attr-defined]

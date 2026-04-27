"""Unit tests for the sidecar FastAPI factory + health endpoints (G-01)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from guardiabox import __version__
from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.app import create_app


def _settings_for(tmp_path: Path) -> Settings:
    """Build a :class:`Settings` rooted at ``tmp_path`` to isolate the vault."""
    return Settings(data_dir=tmp_path)


def test_create_app_stores_session_token_and_settings(tmp_path: Path) -> None:
    """The factory stashes the launch token and Settings in ``app.state``."""
    settings = _settings_for(tmp_path)
    app = create_app(session_token="probe-token-32bytes-urlsafe-aaaa", settings=settings)

    assert app.state.session_token == "probe-token-32bytes-urlsafe-aaaa"
    assert app.state.settings is settings


def test_create_app_rejects_empty_token(tmp_path: Path) -> None:
    """An empty token is a programming error -- fail loud at construction."""
    with pytest.raises(ValueError, match="non-empty"):
        create_app(session_token="", settings=_settings_for(tmp_path))


def test_create_app_disables_docs_and_redoc(tmp_path: Path) -> None:
    """ADR-0016 sec I -- no public API surface beyond the JSON schema.

    /docs and /redoc are not in the auth-exempt whitelist; if FastAPI
    still served them, we'd get 401 (middleware) instead of 404 (route
    absent). We therefore pass the token to bypass auth and assert the
    routes are genuinely missing -- a stronger contract than 401.
    """
    app = create_app(session_token="probe-token", settings=_settings_for(tmp_path))
    client = TestClient(app, headers={"x-guardiabox-token": "probe-token"})

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    # /openapi.json is whitelisted -- no auth header even needed.
    assert TestClient(app).get("/openapi.json").status_code == 200


def test_healthz_returns_200_without_token(tmp_path: Path) -> None:
    """Health is exempted from auth so the Tauri shell can probe pre-handshake."""
    app = create_app(session_token="probe-token", settings=_settings_for(tmp_path))
    client = TestClient(app)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readyz_503_when_vault_not_initialized(tmp_path: Path) -> None:
    """The vault admin config is absent -- the frontend must route to init."""
    app = create_app(session_token="probe-token", settings=_settings_for(tmp_path))
    client = TestClient(app)

    response = client.get("/readyz")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["vault_initialized"] is False
    assert "vault not initialised" in body["reason"]


def test_readyz_200_when_vault_initialized(tmp_path: Path) -> None:
    """A pre-existing ``vault.admin.json`` flips readyz to 200."""
    settings = _settings_for(tmp_path)
    # Mimic what `guardiabox init` writes; readyz only checks file
    # presence, not content validity.
    (tmp_path / "vault.admin.json").write_text("{}", encoding="utf-8")

    app = create_app(session_token="probe-token", settings=settings)
    client = TestClient(app)

    response = client.get("/readyz")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["vault_initialized"] is True
    assert body["reason"] is None


def test_version_returns_build_metadata(tmp_path: Path) -> None:
    """``/version`` exposes version + interpreter + platform for the About panel."""
    app = create_app(session_token="probe-token", settings=_settings_for(tmp_path))
    client = TestClient(app)

    response = client.get("/version")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == __version__
    assert body["python_version"]
    assert body["platform"]
    assert body["machine"]


def test_health_routes_are_registered(tmp_path: Path) -> None:
    """All three health routes are exposed under the root path."""
    app = create_app(session_token="probe-token", settings=_settings_for(tmp_path))
    paths = {route.path for route in app.routes}  # type: ignore[attr-defined]

    assert {"/healthz", "/readyz", "/version"}.issubset(paths)

"""Unit tests for the /api/v1/vault router (G-03)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from guardiabox.config import Settings
from guardiabox.security.vault_admin import (
    create_admin_config,
    write_admin_config,
)
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

# Strong test passwords (bypass S105 via tests/**/* per-file-ignore).
_ADMIN_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


def _seed_vault(tmp_path: Path, *, password: str = _ADMIN_PWD) -> None:
    """Write a valid ``vault.admin.json`` so unlock can succeed."""
    config = create_admin_config(password)
    write_admin_config(tmp_path / "vault.admin.json", config)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    return TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})


# ---------------------------------------------------------------------------
# /vault/unlock
# ---------------------------------------------------------------------------


def test_unlock_returns_session_id_for_valid_password(
    client: TestClient,
    tmp_path: Path,
) -> None:
    _seed_vault(tmp_path)

    response = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["session_id"], str)
    assert len(body["session_id"]) >= 32
    assert body["expires_in_seconds"] > 0


def test_unlock_rejects_wrong_password(client: TestClient, tmp_path: Path) -> None:
    _seed_vault(tmp_path)

    response = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": "Wrong_Password_42!"},  # pragma: allowlist secret
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unlock failed"}


def test_unlock_rejects_when_vault_not_initialized(client: TestClient) -> None:
    """Anti-oracle: missing vault and wrong password share the same 401."""
    response = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unlock failed"}


def test_unlock_anti_oracle_response_byte_identical(
    client: TestClient,
    tmp_path: Path,
) -> None:
    """Wrong password and missing vault must produce identical bodies."""
    # Trigger 1: vault absent.
    r_missing = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )

    # Trigger 2: vault present, wrong password.
    _seed_vault(tmp_path)
    r_wrong = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": "Different_Strong_Password_44!"},  # pragma: allowlist secret
    )

    assert r_missing.status_code == r_wrong.status_code == 401
    assert r_missing.content == r_wrong.content


def test_unlock_rejects_extra_fields_pydantic(client: TestClient, tmp_path: Path) -> None:
    """Schema enforces extra=forbid (ADR-0016 sec H)."""
    _seed_vault(tmp_path)

    response = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD, "ghost_field": 1},
    )

    assert response.status_code == 422


def test_unlock_requires_token(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    _seed_vault(tmp_path)
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    no_token = TestClient(app)  # no default header

    response = no_token.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "missing or invalid token"}


# ---------------------------------------------------------------------------
# /vault/lock
# ---------------------------------------------------------------------------


def test_lock_drops_an_active_session(client: TestClient, tmp_path: Path) -> None:
    _seed_vault(tmp_path)
    unlock_resp = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )
    session_id = unlock_resp.json()["session_id"]

    lock_resp = client.post(
        "/api/v1/vault/lock",
        json={"session_id": session_id},
    )

    assert lock_resp.status_code == 204
    # Status reflects that no session is active.
    status_resp = client.get("/api/v1/vault/status")
    assert status_resp.json()["active_sessions"] == 0


def test_lock_unknown_session_is_idempotent(client: TestClient) -> None:
    response = client.post(
        "/api/v1/vault/lock",
        json={"session_id": "ghost"},
    )
    assert response.status_code == 204


# ---------------------------------------------------------------------------
# /vault/status
# ---------------------------------------------------------------------------


def test_status_reports_no_session_when_idle(client: TestClient, tmp_path: Path) -> None:
    response = client.get("/api/v1/vault/status")

    assert response.status_code == 200
    body = response.json()
    assert body["active_sessions"] == 0
    assert body["vault_initialized"] is False

    _seed_vault(tmp_path)
    response2 = client.get("/api/v1/vault/status")
    assert response2.json()["vault_initialized"] is True


def test_status_reports_active_session_count(client: TestClient, tmp_path: Path) -> None:
    _seed_vault(tmp_path)
    client.post("/api/v1/vault/unlock", json={"admin_password": _ADMIN_PWD})

    response = client.get("/api/v1/vault/status")

    assert response.json()["active_sessions"] == 1

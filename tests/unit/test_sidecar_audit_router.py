"""Unit tests for /api/v1/audit router (G-07)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import pytest_asyncio

from guardiabox.config import Settings
from guardiabox.persistence.bootstrap import init_vault
from guardiabox.ui.tauri.sidecar.api.dependencies import SESSION_HEADER
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

_ADMIN_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_USER_PWD = "Different_Strong_Password_44!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


@pytest_asyncio.fixture
async def initialized_settings(tmp_path: Path) -> Settings:
    settings = Settings(data_dir=tmp_path)
    await init_vault(tmp_path, _ADMIN_PWD)
    return settings


@pytest.fixture
def authed_client(initialized_settings: Settings) -> TestClient:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    bootstrap = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})
    unlock = bootstrap.post("/api/v1/vault/unlock", json={"admin_password": _ADMIN_PWD})
    session_id = unlock.json()["session_id"]
    return TestClient(
        app,
        headers={TOKEN_HEADER: _TEST_TOKEN, SESSION_HEADER: session_id},
    )


# ---------------------------------------------------------------------------
# /audit list
# ---------------------------------------------------------------------------


def test_list_audit_returns_genesis_system_startup(authed_client: TestClient) -> None:
    """init_vault writes a SYSTEM_STARTUP row at sequence 1."""
    response = authed_client.get("/api/v1/audit")

    assert response.status_code == 200
    entries = response.json()["entries"]
    assert len(entries) >= 1
    # Order is most-recent-first; the genesis entry has sequence 1.
    actions = {e["action"] for e in entries}
    assert "system.startup" in actions


def test_list_audit_filter_by_action(authed_client: TestClient) -> None:
    # Trigger a user.create row.
    create_resp = authed_client.post(
        "/api/v1/users",
        json={"username": "alice", "password": _USER_PWD},
    )
    assert create_resp.status_code == 201

    response = authed_client.get("/api/v1/audit?action=user.create")

    assert response.status_code == 200
    entries = response.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["action"] == "user.create"
    assert entries[0]["target"] == "alice"


def test_list_audit_decrypts_target_and_actor_username(
    authed_client: TestClient,
) -> None:
    create_resp = authed_client.post(
        "/api/v1/users",
        json={"username": "bob", "password": _USER_PWD},
    )
    assert create_resp.status_code == 201

    response = authed_client.get("/api/v1/audit?action=user.create")
    entry = response.json()["entries"][0]

    # actor_user_id is the freshly-created user; actor_username
    # resolves through the User repo.
    assert entry["actor_user_id"] == create_resp.json()["user_id"]
    assert entry["actor_username"] == "bob"


def test_list_audit_limit_param_caps_results(authed_client: TestClient) -> None:
    """Limit upper bound is 1000; we just confirm it is honoured at 1."""
    # Generate two more rows.
    authed_client.post("/api/v1/users", json={"username": "u1", "password": _USER_PWD})
    authed_client.post("/api/v1/users", json={"username": "u2", "password": _USER_PWD})

    response = authed_client.get("/api/v1/audit?limit=1")

    assert response.status_code == 200
    assert len(response.json()["entries"]) == 1


def test_list_audit_rejects_limit_above_1000(authed_client: TestClient) -> None:
    response = authed_client.get("/api/v1/audit?limit=2000")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# /audit/verify
# ---------------------------------------------------------------------------


def test_verify_chain_returns_ok_on_clean_chain(authed_client: TestClient) -> None:
    response = authed_client.get("/api/v1/audit/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["first_bad_sequence"] is None
    assert body["entries_checked"] >= 1


def test_audit_route_requires_vault_session(initialized_settings: Settings) -> None:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    no_session = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})

    response = no_session.get("/api/v1/audit")
    assert response.status_code == 401

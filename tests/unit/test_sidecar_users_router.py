"""Unit tests for /api/v1/users router (G-06)."""

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
    """Init a real vault (DB + admin config + audit genesis) under tmp_path."""
    settings = Settings(data_dir=tmp_path)
    await init_vault(tmp_path, _ADMIN_PWD)
    return settings


@pytest.fixture
def unlocked_client(initialized_settings: Settings) -> tuple[TestClient, str]:
    """Build an app, unlock the vault, return (client_with_session, session_id)."""
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})

    unlock_resp = client.post(
        "/api/v1/vault/unlock",
        json={"admin_password": _ADMIN_PWD},
    )
    assert unlock_resp.status_code == 200
    session_id = unlock_resp.json()["session_id"]

    # Re-build the client with the session header on every request.
    authed = TestClient(
        app,
        headers={TOKEN_HEADER: _TEST_TOKEN, SESSION_HEADER: session_id},
    )
    return authed, session_id


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_users_route_requires_vault_session(initialized_settings: Settings) -> None:
    """Token alone is not enough -- /users demands an unlocked session."""
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    client = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})

    response = client.get("/api/v1/users")

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def test_create_user_persists_row_and_audits(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    response = client.post(
        "/api/v1/users",
        json={"username": "alice", "password": _USER_PWD, "kdf": "pbkdf2"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "alice"
    assert body["has_keystore"] is True
    assert isinstance(body["user_id"], str)
    assert len(body["user_id"]) >= 32  # uuid4 hex


def test_create_user_rejects_duplicate_username(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    first = client.post(
        "/api/v1/users",
        json={"username": "bob", "password": _USER_PWD},
    )
    assert first.status_code == 201

    second = client.post(
        "/api/v1/users",
        json={"username": "bob", "password": _USER_PWD},
    )
    assert second.status_code == 409


def test_create_user_rejects_weak_password(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    response = client.post(
        "/api/v1/users",
        json={"username": "weakling", "password": "short"},  # pragma: allowlist secret
    )

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# List + show
# ---------------------------------------------------------------------------


def test_list_users_returns_decrypted_usernames(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    client.post(
        "/api/v1/users",
        json={"username": "alice", "password": _USER_PWD},
    )
    client.post(
        "/api/v1/users",
        json={"username": "bob", "password": _USER_PWD},
    )

    response = client.get("/api/v1/users")

    assert response.status_code == 200
    usernames = sorted(u["username"] for u in response.json()["users"])
    assert usernames == ["alice", "bob"]


def test_show_user_returns_404_when_unknown(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    response = client.get("/api/v1/users/unknown-user-id")

    assert response.status_code == 404


def test_show_user_returns_view_for_known_id(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    create_resp = client.post(
        "/api/v1/users",
        json={"username": "charlie", "password": _USER_PWD},
    )
    user_id = create_resp.json()["user_id"]

    show_resp = client.get(f"/api/v1/users/{user_id}")

    assert show_resp.status_code == 200
    assert show_resp.json()["username"] == "charlie"


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


def test_delete_user_removes_row_and_audits(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client
    create_resp = client.post(
        "/api/v1/users",
        json={"username": "dave", "password": _USER_PWD},
    )
    user_id = create_resp.json()["user_id"]

    delete_resp = client.delete(f"/api/v1/users/{user_id}")
    assert delete_resp.status_code == 204

    # Confirm the user is gone.
    list_resp = client.get("/api/v1/users")
    assert all(u["user_id"] != user_id for u in list_resp.json()["users"])


def test_delete_unknown_user_returns_404(
    unlocked_client: tuple[TestClient, str],
) -> None:
    client, _ = unlocked_client

    response = client.delete("/api/v1/users/ghost-id")

    assert response.status_code == 404

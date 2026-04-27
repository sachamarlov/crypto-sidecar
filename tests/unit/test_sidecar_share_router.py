"""Unit tests for /api/v1/share + /api/v1/accept (G-05)."""

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
def client(initialized_settings: Settings) -> TestClient:
    app = create_app(session_token=_TEST_TOKEN, settings=initialized_settings)
    bootstrap = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})
    unlock = bootstrap.post("/api/v1/vault/unlock", json={"admin_password": _ADMIN_PWD})
    session_id = unlock.json()["session_id"]
    return TestClient(
        app,
        headers={TOKEN_HEADER: _TEST_TOKEN, SESSION_HEADER: session_id},
    )


def _create_user(client: TestClient, username: str) -> str:
    resp = client.post(
        "/api/v1/users",
        json={"username": username, "password": _USER_PWD, "kdf": "pbkdf2"},
    )
    assert resp.status_code == 201
    return resp.json()["user_id"]


def _encrypt_file(client: TestClient, path: Path, *, password: str) -> Path:
    resp = client.post(
        "/api/v1/encrypt",
        json={"path": str(path), "password": password, "kdf": "pbkdf2"},
    )
    assert resp.status_code == 200
    return Path(resp.json()["output_path"])


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_share_then_accept_round_trip(client: TestClient, tmp_path: Path) -> None:
    plaintext = b"end-to-end share via sidecar"
    src = tmp_path / "report.txt"
    src.write_bytes(plaintext)

    alice_id = _create_user(client, "alice")
    bob_id = _create_user(client, "bob")
    crypt_path = _encrypt_file(client, src, password=_USER_PWD)

    token_path = tmp_path / "share.gbox-share"
    out_path = tmp_path / "received.txt"

    share_resp = client.post(
        "/api/v1/share",
        json={
            "source_path": str(crypt_path),
            "sender_user_id": alice_id,
            "sender_password": _USER_PWD,
            "recipient_user_id": bob_id,
            "output_path": str(token_path),
            "expires_days": 0,
        },
    )
    assert share_resp.status_code == 200, share_resp.text
    assert token_path.is_file()

    accept_resp = client.post(
        "/api/v1/accept",
        json={
            "source_path": str(token_path),
            "recipient_user_id": bob_id,
            "recipient_password": _USER_PWD,
            "sender_user_id": alice_id,
            "output_path": str(out_path),
        },
    )
    assert accept_resp.status_code == 200, accept_resp.text
    assert out_path.read_bytes() == plaintext


# ---------------------------------------------------------------------------
# Anti-oracle on /accept
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_accept_tampered_token_returns_anti_oracle_422(
    client: TestClient,
    tmp_path: Path,
) -> None:
    src = tmp_path / "data.txt"
    src.write_bytes(b"payload to share")
    alice_id = _create_user(client, "alice")
    bob_id = _create_user(client, "bob")
    crypt_path = _encrypt_file(client, src, password=_USER_PWD)
    token_path = tmp_path / "share.gbox-share"
    client.post(
        "/api/v1/share",
        json={
            "source_path": str(crypt_path),
            "sender_user_id": alice_id,
            "sender_password": _USER_PWD,
            "recipient_user_id": bob_id,
            "output_path": str(token_path),
        },
    )

    # Flip 1 byte inside the signature suffix (last 512 bytes are the
    # RSA-PSS signature for a 4096-bit key).
    raw = bytearray(token_path.read_bytes())
    raw[-1] ^= 0x01
    token_path.write_bytes(bytes(raw))

    response = client.post(
        "/api/v1/accept",
        json={
            "source_path": str(token_path),
            "recipient_user_id": bob_id,
            "recipient_password": _USER_PWD,
            "sender_user_id": alice_id,
            "output_path": str(tmp_path / "out.txt"),
        },
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "share verification failed"}


# ---------------------------------------------------------------------------
# Auth + lookup errors
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_share_404_when_sender_unknown(client: TestClient, tmp_path: Path) -> None:
    src = tmp_path / "data.txt"
    src.write_bytes(b"x")
    bob_id = _create_user(client, "bob")
    crypt_path = _encrypt_file(client, src, password=_USER_PWD)

    response = client.post(
        "/api/v1/share",
        json={
            "source_path": str(crypt_path),
            "sender_user_id": "unknown-user-id",
            "sender_password": _USER_PWD,
            "recipient_user_id": bob_id,
            "output_path": str(tmp_path / "share.gbox-share"),
        },
    )
    assert response.status_code == 404


@pytest.mark.slow
def test_share_401_on_wrong_sender_password(client: TestClient, tmp_path: Path) -> None:
    src = tmp_path / "data.txt"
    src.write_bytes(b"x")
    alice_id = _create_user(client, "alice")
    bob_id = _create_user(client, "bob")
    crypt_path = _encrypt_file(client, src, password=_USER_PWD)

    response = client.post(
        "/api/v1/share",
        json={
            "source_path": str(crypt_path),
            "sender_user_id": alice_id,
            "sender_password": "Totally_Different_Password_99!",  # pragma: allowlist secret
            "recipient_user_id": bob_id,
            "output_path": str(tmp_path / "share.gbox-share"),
        },
    )
    assert response.status_code == 401

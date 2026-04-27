"""End-to-end integration test of the Phase G sidecar HTTP surface (G-17).

Drives the full lifecycle through the FastAPI app:
init -> unlock -> create users -> encrypt -> share -> accept ->
audit verify. Confirms every router co-operates and that the
audit chain remains intact after a non-trivial sequence of writes.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.api.dependencies import SESSION_HEADER
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

_ADMIN_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_USER_PWD = "Different_Strong_Password_44!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


@pytest.mark.integration
@pytest.mark.slow
def test_full_lifecycle_init_unlock_users_share_accept(tmp_path: Path) -> None:  # noqa: PLR0914  -- E2E lifecycle test legitimately chains 8 endpoints
    settings = Settings(data_dir=tmp_path)
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    client = TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})

    # 1. /api/v1/init -- create the vault.
    init_resp = client.post("/api/v1/init", json={"admin_password": _ADMIN_PWD})
    assert init_resp.status_code == 201

    # 2. /api/v1/vault/unlock -- open an admin session.
    unlock_resp = client.post("/api/v1/vault/unlock", json={"admin_password": _ADMIN_PWD})
    assert unlock_resp.status_code == 200
    session_id = unlock_resp.json()["session_id"]
    authed = TestClient(
        app,
        headers={TOKEN_HEADER: _TEST_TOKEN, SESSION_HEADER: session_id},
    )

    # 3. /api/v1/users x 2.
    alice = authed.post("/api/v1/users", json={"username": "alice", "password": _USER_PWD})
    bob = authed.post("/api/v1/users", json={"username": "bob", "password": _USER_PWD})
    assert alice.status_code == 201
    assert bob.status_code == 201
    alice_id = alice.json()["user_id"]
    bob_id = bob.json()["user_id"]

    # 4. /api/v1/encrypt as alice.
    plaintext = b"end-to-end full-stack lifecycle"
    src = tmp_path / "report.txt"
    src.write_bytes(plaintext)
    enc_resp = authed.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _USER_PWD, "kdf": "pbkdf2"},
    )
    assert enc_resp.status_code == 200
    crypt_path = enc_resp.json()["output_path"]

    # 5. /api/v1/share alice -> bob.
    token_path = tmp_path / "share.gbox-share"
    share_resp = authed.post(
        "/api/v1/share",
        json={
            "source_path": crypt_path,
            "sender_user_id": alice_id,
            "sender_password": _USER_PWD,
            "recipient_user_id": bob_id,
            "output_path": str(token_path),
        },
    )
    assert share_resp.status_code == 200, share_resp.text

    # 6. /api/v1/accept -- bob recovers the plaintext.
    out_path = tmp_path / "recovered.txt"
    accept_resp = authed.post(
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

    # 7. /api/v1/audit -- the chain has user.create x2 + file.share +
    #    file.share_accept + system.startup at minimum.
    audit_resp = authed.get("/api/v1/audit?limit=100")
    actions = {e["action"] for e in audit_resp.json()["entries"]}
    assert {"user.create", "file.share", "file.share_accept", "system.startup"} <= actions

    # 8. /api/v1/audit/verify -- the hash chain is intact end-to-end.
    verify_resp = authed.get("/api/v1/audit/verify")
    assert verify_resp.status_code == 200
    body = verify_resp.json()
    assert body["ok"] is True
    assert body["first_bad_sequence"] is None
    assert body["entries_checked"] >= 4

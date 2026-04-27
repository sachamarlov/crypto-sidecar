"""Unit tests for /inspect, /init, /doctor, /secure-delete (G-08)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

_ADMIN_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    return TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})


# ---------------------------------------------------------------------------
# /init
# ---------------------------------------------------------------------------


def test_init_creates_vault_returns_paths(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/init",
        json={"admin_password": _ADMIN_PWD, "kdf": "pbkdf2"},
    )

    assert response.status_code == 201
    body = response.json()
    assert Path(body["data_dir"]).resolve() == tmp_path.resolve()
    assert Path(body["db_path"]).is_file()
    assert Path(body["admin_config_path"]).is_file()


def test_init_refuses_double_init(client: TestClient) -> None:
    first = client.post("/api/v1/init", json={"admin_password": _ADMIN_PWD})
    assert first.status_code == 201

    second = client.post("/api/v1/init", json={"admin_password": _ADMIN_PWD})
    assert second.status_code == 409


def test_init_rejects_weak_password(client: TestClient) -> None:
    response = client.post(
        "/api/v1/init",
        json={"admin_password": "weak"},  # pragma: allowlist secret
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# /inspect
# ---------------------------------------------------------------------------


def test_inspect_returns_header_view(client: TestClient, tmp_path: Path) -> None:
    # Encrypt a file via /encrypt to generate a valid .crypt header.
    src = tmp_path / "report.txt"
    src.write_bytes(b"some content for inspect")
    enc = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _ADMIN_PWD},
    )
    assert enc.status_code == 200
    crypt_path = enc.json()["output_path"]

    response = client.post("/api/v1/inspect", json={"path": crypt_path})

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 1  # CONTAINER_VERSION
    assert body["kdf_id"] in {1, 2}
    assert len(body["salt_hex"]) == 32  # 16 bytes -> 32 hex chars
    assert len(body["base_nonce_hex"]) == 24  # 12 bytes
    assert body["header_size"] > 0
    assert body["ciphertext_size"] > 0


def test_inspect_404_on_missing(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/inspect",
        json={"path": str(tmp_path / "ghost.crypt")},
    )
    assert response.status_code == 404


def test_inspect_400_on_bogus_container(client: TestClient, tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.crypt"
    bogus.write_bytes(b"NOT GBOX")

    response = client.post("/api/v1/inspect", json={"path": str(bogus)})
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# /doctor
# ---------------------------------------------------------------------------


def test_doctor_reports_no_db_when_uninitialised(client: TestClient) -> None:
    response = client.get("/api/v1/doctor")

    assert response.status_code == 200
    body = response.json()
    assert body["db_exists"] is False
    assert body["admin_config_exists"] is False
    assert body["ssd_report"] is None
    assert body["audit_chain"] is None


def test_doctor_reports_initialized_after_init(client: TestClient) -> None:
    client.post("/api/v1/init", json={"admin_password": _ADMIN_PWD})
    response = client.get("/api/v1/doctor")

    body = response.json()
    assert body["db_exists"] is True
    assert body["admin_config_exists"] is True


def test_doctor_ssd_report_query_returns_verdict(client: TestClient) -> None:
    response = client.get("/api/v1/doctor?report_ssd=true")

    body = response.json()
    assert body["ssd_report"] is not None
    assert "is_ssd" in body["ssd_report"]
    assert isinstance(body["ssd_report"]["recommendation"], str)


# ---------------------------------------------------------------------------
# /secure-delete
# ---------------------------------------------------------------------------


def test_secure_delete_overwrites_and_unlinks(client: TestClient, tmp_path: Path) -> None:
    target = tmp_path / "victim.txt"
    target.write_bytes(b"sensitive content")

    response = client.post(
        "/api/v1/secure-delete",
        json={"path": str(target), "passes": 3, "confirm_ssd": True},
    )

    assert response.status_code == 200
    assert not target.exists()


def test_secure_delete_404_on_missing(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/secure-delete",
        json={"path": str(tmp_path / "ghost"), "confirm_ssd": True},
    )
    assert response.status_code == 404


def test_secure_delete_rejects_passes_above_35(client: TestClient, tmp_path: Path) -> None:
    target = tmp_path / "v.txt"
    target.write_bytes(b"x")

    response = client.post(
        "/api/v1/secure-delete",
        json={"path": str(target), "passes": 100, "confirm_ssd": True},
    )

    assert response.status_code == 422

"""Unit tests for /api/v1/encrypt + /api/v1/decrypt routers (G-04)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

# Strong test passwords (passes zxcvbn >= 3 + length >= 12).
_STRONG_PWD = "Correct_Horse_Battery_Staple_42!"  # pragma: allowlist secret
_OTHER_STRONG_PWD = "Different_Strong_Password_44!"  # pragma: allowlist secret
_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    return TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})


def _write_plain(tmp_path: Path, content: bytes = b"hello GuardiaBox sidecar") -> Path:
    src = tmp_path / "report.txt"
    src.write_bytes(content)
    return src


# ---------------------------------------------------------------------------
# /encrypt happy path
# ---------------------------------------------------------------------------


def test_encrypt_creates_crypt_file(client: TestClient, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)

    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD, "kdf": "pbkdf2"},
    )

    assert response.status_code == 200
    body = response.json()
    output = Path(body["output_path"])
    assert output.exists()
    assert output.suffix == ".crypt"
    assert body["plaintext_size"] == len(b"hello GuardiaBox sidecar")
    assert body["ciphertext_size"] > body["plaintext_size"]
    assert body["kdf_id"] in {1, 2}
    assert body["elapsed_ms"] >= 0


def test_encrypt_with_argon2id_kdf(client: TestClient, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)

    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD, "kdf": "argon2id"},
    )

    assert response.status_code == 200
    assert response.json()["kdf_id"] == 2  # Argon2idKdf id


# ---------------------------------------------------------------------------
# /encrypt rejection paths
# ---------------------------------------------------------------------------


def test_encrypt_404_when_source_missing(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(tmp_path / "ghost.txt"), "password": _STRONG_PWD},
    )
    assert response.status_code == 404


def test_encrypt_400_on_weak_password(client: TestClient, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)
    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": "short"},  # pragma: allowlist secret
    )
    assert response.status_code == 400


def test_encrypt_409_when_dest_exists_without_force(
    client: TestClient,
    tmp_path: Path,
) -> None:
    src = _write_plain(tmp_path)
    crypt = tmp_path / "report.txt.crypt"
    crypt.write_bytes(b"already there")

    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD, "force": False},
    )

    assert response.status_code == 409


def test_encrypt_force_overwrites_existing(client: TestClient, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)
    crypt = tmp_path / "report.txt.crypt"
    crypt.write_bytes(b"will be replaced")

    response = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD, "force": True},
    )
    assert response.status_code == 200
    # The destination was overwritten with a real .crypt header.
    assert crypt.read_bytes()[:4] == b"GBOX"


def test_encrypt_rejects_extra_fields(client: TestClient, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)
    response = client.post(
        "/api/v1/encrypt",
        json={
            "path": str(src),
            "password": _STRONG_PWD,
            "ghost_field": True,
        },
    )
    assert response.status_code == 422


def test_encrypt_requires_token(settings: Settings, tmp_path: Path) -> None:
    src = _write_plain(tmp_path)
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    no_token = TestClient(app)

    response = no_token.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# /decrypt happy path (round-trip)
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_round_trip(client: TestClient, tmp_path: Path) -> None:
    plaintext = b"the original payload bytes -- preserved end-to-end"
    src = _write_plain(tmp_path, plaintext)

    enc_resp = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD},
    )
    assert enc_resp.status_code == 200
    crypt_path = enc_resp.json()["output_path"]

    dec_resp = client.post(
        "/api/v1/decrypt",
        json={"path": crypt_path, "password": _STRONG_PWD},
    )
    assert dec_resp.status_code == 200
    out = Path(dec_resp.json()["output_path"])
    assert out.read_bytes() == plaintext


# ---------------------------------------------------------------------------
# /decrypt anti-oracle (the central security invariant)
# ---------------------------------------------------------------------------


def test_decrypt_wrong_password_returns_anti_oracle_422(
    client: TestClient,
    tmp_path: Path,
) -> None:
    src = _write_plain(tmp_path)
    enc_resp = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD},
    )
    crypt_path = enc_resp.json()["output_path"]

    response = client.post(
        "/api/v1/decrypt",
        json={"path": crypt_path, "password": _OTHER_STRONG_PWD},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "decryption failed"}


def test_decrypt_tampered_ciphertext_returns_anti_oracle_422(
    client: TestClient,
    tmp_path: Path,
) -> None:
    src = _write_plain(tmp_path)
    enc_resp = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD},
    )
    crypt_path = Path(enc_resp.json()["output_path"])
    # Flip the very last byte (final-chunk AEAD tag).
    raw = bytearray(crypt_path.read_bytes())
    raw[-1] ^= 0x01
    crypt_path.write_bytes(bytes(raw))

    response = client.post(
        "/api/v1/decrypt",
        json={"path": str(crypt_path), "password": _STRONG_PWD},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "decryption failed"}


def test_decrypt_anti_oracle_byte_identical(client: TestClient, tmp_path: Path) -> None:
    """Wrong password and tampered ciphertext must yield byte-identical responses."""
    # Encrypt one file, derive both failure scenarios from it.
    src = _write_plain(tmp_path)
    enc_resp = client.post(
        "/api/v1/encrypt",
        json={"path": str(src), "password": _STRONG_PWD},
    )
    pristine = Path(enc_resp.json()["output_path"])

    # Branch A: wrong password against the pristine ciphertext.
    r_wrong_pwd = client.post(
        "/api/v1/decrypt",
        json={"path": str(pristine), "password": _OTHER_STRONG_PWD},
    )

    # Branch B: right password against a tampered copy.
    tampered = tmp_path / "report.tampered.crypt"
    raw = bytearray(pristine.read_bytes())
    raw[-1] ^= 0x01
    tampered.write_bytes(bytes(raw))
    r_tampered = client.post(
        "/api/v1/decrypt",
        json={"path": str(tampered), "password": _STRONG_PWD},
    )

    assert r_wrong_pwd.status_code == r_tampered.status_code == 422
    assert r_wrong_pwd.content == r_tampered.content


def test_decrypt_404_when_source_missing(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/decrypt",
        json={"path": str(tmp_path / "ghost.crypt"), "password": _STRONG_PWD},
    )
    assert response.status_code == 404


def test_decrypt_400_on_invalid_container(client: TestClient, tmp_path: Path) -> None:
    """Pre-KDF failure: garbage bytes reject with 400 (public-metadata error)."""
    bogus = tmp_path / "bogus.crypt"
    bogus.write_bytes(b"NOT A CRYPT" + b"\x00" * 32)

    response = client.post(
        "/api/v1/decrypt",
        json={"path": str(bogus), "password": _STRONG_PWD},
    )

    assert response.status_code == 400

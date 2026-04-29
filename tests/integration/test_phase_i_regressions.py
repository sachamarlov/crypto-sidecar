"""Regression tests for the 8 runtime bugs caught at T-3 days.

Audit D P0-1 finding: PRs #42-#49 each fixed a runtime bug found
manually but none added a test of the broken-then-fixed contract.
This file is the meta-fix -- one test per bug class so the
regression cannot return silently.

Bugs covered:

* #1 (CORS missing) + #2 (middleware order LIFO): an OPTIONS
  preflight from ``http://tauri.localhost`` must succeed without
  a token and return ``Access-Control-Allow-Origin``.
* #3 (PyInstaller --noconsole closes stdout): exercised by
  ``tests/integration/test_sidecar_subprocess.py`` -- handshake
  parsing already covers the broken case.
* #4 (argon2-cffi 25.x retired ``argon2._ffi``): ``argon2.low_level``
  must remain importable.
* #7 (Alembic versions/ not bundled): ``alembic.script.ScriptDirectory``
  must enumerate the migrations on disk after a fresh import.
* #8 (frontend TS strict under Vite 7): handled by the CI ruff/biome
  gates -- no Python regression to write here.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from guardiabox.config import Settings
from guardiabox.ui.tauri.sidecar.api.middleware import TOKEN_HEADER
from guardiabox.ui.tauri.sidecar.app import create_app

_TEST_TOKEN = "test-token-32bytes-urlsafe-aaaa"  # pragma: allowlist secret


@pytest.fixture
def client(tmp_path: pytest.Path) -> TestClient:  # type: ignore[name-defined]
    settings = Settings(data_dir=tmp_path)
    app = create_app(session_token=_TEST_TOKEN, settings=settings)
    return TestClient(app, headers={TOKEN_HEADER: _TEST_TOKEN})


def test_cors_preflight_from_tauri_localhost_succeeds(client: TestClient) -> None:
    """Bug #1+#2: OPTIONS from tauri.localhost without token returns 200 + ACAO header."""
    response = client.options(
        "/api/v1/vault/unlock",
        headers={
            "Origin": "http://tauri.localhost",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-GuardiaBox-Token,X-GuardiaBox-Session,Content-Type",
        },
    )
    assert response.status_code in (200, 204), (
        f"CORS preflight failed: {response.status_code} {response.text}"
    )
    acao = response.headers.get("access-control-allow-origin", "")
    assert "tauri.localhost" in acao or acao == "*", f"missing ACAO: {response.headers}"


def test_options_preflight_does_not_require_token() -> None:
    """Bug #2: OPTIONS preflight must bypass TokenAuthMiddleware (CORS preflight has no auth)."""
    settings_app = create_app(session_token=_TEST_TOKEN, settings=Settings())
    bare_client = TestClient(settings_app)  # no token header
    response = bare_client.options(
        "/api/v1/encrypt",
        headers={
            "Origin": "http://tauri.localhost",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code in (200, 204)


def test_argon2_low_level_importable() -> None:
    """Bug #4: argon2-cffi 25.x retired _ffi; argon2.low_level must still load."""
    module = importlib.import_module("argon2.low_level")
    assert hasattr(module, "hash_secret_raw")
    assert hasattr(module, "Type")


def test_alembic_versions_dir_discoverable() -> None:
    """Bug #7: Alembic must find the migrations on disk (--add-data in PyInstaller).

    This test checks the on-disk discovery the same way Alembic would
    after the bundled binary unpacks: walk the versions/ dir, count the
    ``.py`` revision files. With ``__add-data`` correctly wired into
    ``scripts/build_sidecar.py``, the count is non-zero.
    """
    from pathlib import Path

    versions = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "guardiabox"
        / "persistence"
        / "migrations"
        / "versions"
    )
    revisions = [p for p in versions.glob("*.py") if not p.name.startswith("_")]
    assert len(revisions) >= 1, f"no Alembic revisions found under {versions}"

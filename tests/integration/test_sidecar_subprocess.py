"""Subprocess spawn integration tests for the sidecar binary (G-18).

These tests spawn the bundled PyInstaller binary as a child process,
parse the handshake line, hit ``/healthz`` with the launch token,
and SIGTERM the process. They are marked ``slow`` because each test
spawns a real Python process; the build script itself is exercised
by ``scripts/build_sidecar.py`` -- here we just verify runtime
behaviour given an existing artefact.

Tests skip cleanly if the binary is not present (e.g., on CI before
the matrix build step lands). To run locally::

    uv run python scripts/build_sidecar.py
    uv run pytest tests/integration/test_sidecar_subprocess.py -m slow
"""

from __future__ import annotations

import os
from pathlib import Path
import platform as platform_module
import signal
import subprocess  # nosec B404 -- argv is internal
import sys
import time

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TAURI_BINARIES = ROOT / "src" / "guardiabox" / "ui" / "tauri" / "src-tauri" / "binaries"


def _detect_target_triple() -> str:
    if sys.platform == "win32":
        return "x86_64-pc-windows-msvc"
    if sys.platform == "darwin":
        return (
            "aarch64-apple-darwin"
            if platform_module.machine() == "arm64"
            else "x86_64-apple-darwin"
        )
    return "x86_64-unknown-linux-gnu"


def _binary_path() -> Path:
    triple = _detect_target_triple()
    ext = ".exe" if sys.platform == "win32" else ""
    return TAURI_BINARIES / f"guardiabox-sidecar-{triple}{ext}"


def _binary_present() -> bool:
    return _binary_path().is_file()


pytestmark = pytest.mark.skipif(
    not _binary_present(),
    reason=(
        "PyInstaller-bundled sidecar binary not found. "
        "Run `uv run python scripts/build_sidecar.py` first."
    ),
)


@pytest.mark.integration
@pytest.mark.slow
def test_sidecar_binary_handshake_then_healthz_then_sigterm() -> None:
    proc = subprocess.Popen(  # nosec B603 -- argv internal
        [str(_binary_path())],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode("utf-8").strip()
        assert line.startswith("GUARDIABOX_SIDECAR="), f"unexpected handshake: {line!r}"

        rest = line.removeprefix("GUARDIABOX_SIDECAR=")
        port_str, token = rest.split(" ", 1)
        port = int(port_str)
        assert 1 <= port <= 65535
        assert len(token) >= 32

        # Give uvicorn a moment to bind.
        time.sleep(0.5)

        with httpx.Client(timeout=5.0) as client:
            response = client.get(
                f"http://127.0.0.1:{port}/healthz",
                headers={"X-GuardiaBox-Token": token},
            )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
    finally:
        if sys.platform == "win32":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
        try:
            return_code = proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            return_code = proc.wait(timeout=5.0)
        # On POSIX SIGTERM => exit code 0 from uvicorn graceful shutdown.
        # On Windows terminate() yields a non-zero code; we accept both.
        assert return_code in {0, 1, -signal.SIGTERM, signal.SIGTERM, 15} or os.name == "nt"


@pytest.mark.integration
@pytest.mark.slow
def test_sidecar_binary_rejects_request_without_token() -> None:
    proc = subprocess.Popen(  # nosec B603 -- argv internal
        [str(_binary_path())],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().decode("utf-8").strip()
        rest = line.removeprefix("GUARDIABOX_SIDECAR=")
        port = int(rest.split(" ", 1)[0])

        time.sleep(0.5)

        with httpx.Client(timeout=5.0) as client:
            # /healthz is whitelisted, but /api/v1/users is not.
            response = client.get(f"http://127.0.0.1:{port}/api/v1/users")
        assert response.status_code == 401
    finally:
        if sys.platform == "win32":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10.0)

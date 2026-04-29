"""Full lifecycle smoke test on the bundled PyInstaller sidecar binary.

Audit D P0-2 closure: the previous smoke-test in ``build_sidecar.py``
only hit ``/healthz``. That covered bug #3 (PyInstaller --noconsole
stdout) but not bug #4 (argon2-cffi 25.x), bug #7 (Alembic versions
not bundled), nor any path that exercises the actual crypto.

This script spawns the bundled binary, parses the handshake, drives
a full vault lifecycle (init -> unlock -> create user -> encrypt ->
decrypt -> anti-oracle wrong-password -> CORS preflight) and SIGTERMs
the process. Exits 0 on success, non-zero with diagnostic on failure.

Wiring in ``release.yml`` after the ``sidecar`` job, before
``nfr-verification``, catches 5 of the 8 runtime bugs in CI before
the binary ships to users.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 -- subprocess invoked with fixed argv
import sys
import tempfile
import time
from pathlib import Path

import httpx

ADMIN_PWD = "Smoke_Test_Admin_42!"  # pragma: allowlist secret
USER_PWD = "Smoke_Test_User_44!"  # pragma: allowlist secret


def main(argv: list[str]) -> int:
    """Run a full lifecycle smoke against the bundled sidecar at ``argv[1]``."""
    if len(argv) < 2:
        sys.stderr.write("usage: smoke_bundled_binary.py <path-to-sidecar-binary>\n")
        return 2
    binary = Path(argv[1])
    if not binary.is_file():
        sys.stderr.write(f"binary not found: {binary}\n")
        return 2

    data_dir = Path(tempfile.mkdtemp(prefix="gbox_smoke_"))
    proc = subprocess.Popen(  # noqa: S603 -- argv is hardcoded
        [str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "GUARDIABOX_DATA_DIR": str(data_dir)},
    )
    try:
        if proc.stdout is None:
            sys.stderr.write("subprocess stdout was not captured\n")
            return 1
        line = proc.stdout.readline().decode("utf-8").strip()
        prefix = "GUARDIABOX_SIDECAR="
        if not line.startswith(prefix):
            sys.stderr.write(f"bad handshake: {line!r}\n")
            return 1
        port_str, token = line.removeprefix(prefix).split(" ", 1)
        port = int(port_str)
        time.sleep(0.5)

        with httpx.Client(timeout=15.0, headers={"X-GuardiaBox-Token": token}) as client:
            base = f"http://127.0.0.1:{port}"

            health = client.get(f"{base}/healthz")
            assert health.status_code == 200, f"healthz: {health.status_code}"

            init = client.post(f"{base}/api/v1/init", json={"admin_password": ADMIN_PWD})
            assert init.status_code in (200, 201), f"init: {init.status_code} {init.text}"

            unlock = client.post(
                f"{base}/api/v1/vault/unlock",
                json={"admin_password": ADMIN_PWD},
            )
            assert unlock.status_code == 200, f"unlock: {unlock.status_code} {unlock.text}"
            client.headers["X-GuardiaBox-Session"] = unlock.json()["session_id"]

            user_create = client.post(
                f"{base}/api/v1/users",
                json={"username": "smoker", "password": USER_PWD, "kdf": "pbkdf2"},
            )
            assert user_create.status_code in (200, 201), (
                f"users.create: {user_create.status_code} {user_create.text}"
            )

            with tempfile.NamedTemporaryFile(  # noqa: SIM117 -- nested CMs ok here
                delete=False, suffix=".txt", dir=data_dir,
            ) as fh:
                fh.write(b"smoke test payload")
                src = fh.name

            encrypt = client.post(
                f"{base}/api/v1/encrypt",
                json={"path": src, "password": USER_PWD, "kdf": "pbkdf2"},
            )
            assert encrypt.status_code == 200, (
                f"encrypt: {encrypt.status_code} {encrypt.text}"
            )
            crypt_path = encrypt.json()["output_path"]

            decrypt = client.post(
                f"{base}/api/v1/decrypt",
                json={"path": crypt_path, "password": USER_PWD},
            )
            assert decrypt.status_code == 200, (
                f"decrypt: {decrypt.status_code} {decrypt.text}"
            )

            wrong = client.post(
                f"{base}/api/v1/decrypt",
                json={"path": crypt_path, "password": "Wrong_Smoke_Pwd_999!"},
            )
            assert wrong.status_code == 422, f"anti-oracle: {wrong.status_code}"
            body = wrong.json()
            assert body == {"detail": "decryption failed"}, f"detail leak: {body}"

            preflight = client.options(
                f"{base}/api/v1/vault/unlock",
                headers={
                    "Origin": "http://tauri.localhost",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-GuardiaBox-Token",
                },
            )
            assert preflight.status_code in (200, 204), (
                f"cors preflight: {preflight.status_code}"
            )

        sys.stderr.write("[smoke] ALL CHECKS PASSED\n")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

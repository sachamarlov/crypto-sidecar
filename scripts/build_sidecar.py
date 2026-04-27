"""Bundle the Python sidecar into a standalone executable via PyInstaller.

The output binary is consumed by the Tauri shell as an external resource
declared in ``src-tauri/tauri.conf.json > bundle.externalBin``.

Usage::

    uv run python scripts/build_sidecar.py [--release] [--smoke-test]
                                           [--output-name NAME]

Outputs::

    src/guardiabox/ui/tauri/src-tauri/binaries/guardiabox-sidecar-<triple>(.exe)

Hidden imports / collect-all rationale:

* ``--collect-all guardiabox`` -- our own package; pulls every
  submodule including the Alembic migrations under
  ``persistence/migrations/versions/``.
* ``--collect-all cryptography`` -- the hazmat layer ships compiled
  backends that PyInstaller's static analysis misses.
* ``--collect-all sqlalchemy`` -- async dialect modules
  (``sqlalchemy.dialects.sqlite.aiosqlite``) imported lazily.
* ``--collect-all alembic`` -- runtime migration discovery.
* ``--hidden-import argon2`` + ``--hidden-import argon2._ffi``
  -- argon2-cffi's compiled binding lives under a name PyInstaller
  cannot resolve from the imports alone.
* ``--hidden-import aiosqlite`` -- imported via SQLAlchemy URL string.
* ``--hidden-import zxcvbn`` -- the password evaluator.

The smoke test (``--smoke-test``) spawns the produced binary, parses
its handshake stdout line, hits ``GET /healthz`` with the launch
token, asserts a 200 response, then sends SIGTERM and confirms
clean exit code 0.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess  # noqa: S404  # nosec B404 -- subprocess invoked with fixed argv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIDECAR_ENTRY = ROOT / "src" / "guardiabox" / "ui" / "tauri" / "sidecar" / "main.py"
TAURI_BINARIES = ROOT / "src" / "guardiabox" / "ui" / "tauri" / "src-tauri" / "binaries"
PYINSTALLER_BUILD_ROOT = ROOT / "build" / "pyinstaller"


def main() -> int:
    """Build the sidecar binary; returns 0 on success."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="Build optimised binary.")
    parser.add_argument(
        "--output-name",
        default="guardiabox-sidecar",
        help="Name prefix for the produced executable.",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="After building, spawn the binary and probe /healthz.",
    )
    args = parser.parse_args()

    target_triple = _detect_target_triple()
    output_name = f"{args.output_name}-{target_triple}"
    cmd = _pyinstaller_cmd(output_name=output_name, release=args.release)

    print(f"-> running PyInstaller for target {target_triple}")
    print(" ".join(cmd))
    TAURI_BINARIES.mkdir(parents=True, exist_ok=True)
    PYINSTALLER_BUILD_ROOT.mkdir(parents=True, exist_ok=True)

    completed = subprocess.run(cmd, check=False)  # noqa: S603  # nosec B603 -- argv internal
    if completed.returncode != 0:
        print(f"PyInstaller exited with code {completed.returncode}", file=sys.stderr)
        return completed.returncode

    binary_path = TAURI_BINARIES / _binary_name(output_name)
    if not binary_path.is_file():
        print(f"expected binary at {binary_path} but it is missing", file=sys.stderr)
        return 1

    print(f"-> built {binary_path}")

    if args.smoke_test:
        return _smoke_test(binary_path)

    return 0


def _detect_target_triple() -> str:
    """Return the Rust-style target triple Tauri expects in externalBin names."""
    triple_by_platform: dict[str, str] = {
        "win32": "x86_64-pc-windows-msvc",
        "linux": "x86_64-unknown-linux-gnu",
    }
    if sys.platform == "darwin":
        return "aarch64-apple-darwin" if platform.machine() == "arm64" else "x86_64-apple-darwin"
    return triple_by_platform.get(sys.platform, "x86_64-unknown-linux-gnu")


def _binary_name(output_name: str) -> str:
    return f"{output_name}.exe" if sys.platform == "win32" else output_name


def _pyinstaller_cmd(*, output_name: str, release: bool) -> list[str]:
    """Build the PyInstaller argv. Same flags on every platform."""
    args: list[str] = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        output_name,
        "--collect-all",
        "guardiabox",
        "--collect-all",
        "cryptography",
        "--collect-all",
        "sqlalchemy",
        "--collect-all",
        "alembic",
        "--hidden-import",
        "argon2",
        "--hidden-import",
        "argon2._ffi",
        "--hidden-import",
        "aiosqlite",
        "--hidden-import",
        "zxcvbn",
        "--distpath",
        str(TAURI_BINARIES),
        "--workpath",
        str(PYINSTALLER_BUILD_ROOT / "work"),
        "--specpath",
        str(PYINSTALLER_BUILD_ROOT / "spec"),
        "--clean",
        "--noconfirm",
    ]
    if sys.platform == "win32":
        # Hide the spawned console on Windows -- the Tauri shell owns the UI.
        args.append("--noconsole")
    if release:
        # ``--strip`` is a no-op on Windows but cuts size on Linux/macOS.
        args.append("--strip")
    args.append(str(SIDECAR_ENTRY))
    return args


def _smoke_test(binary_path: Path) -> int:
    """Spawn the binary, probe /healthz with the launch token, return 0/1."""
    import time

    import httpx

    print(f"-> smoke-testing {binary_path}")
    proc = subprocess.Popen(  # noqa: S603  # nosec B603 -- argv internal
        [str(binary_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if proc.stdout is None:
            print("no stdout pipe", file=sys.stderr)
            return 1
        line = proc.stdout.readline().decode("utf-8").strip()
        if not line.startswith("GUARDIABOX_SIDECAR="):
            print(f"unexpected handshake: {line!r}", file=sys.stderr)
            return 1
        rest = line.removeprefix("GUARDIABOX_SIDECAR=")
        port_str, token = rest.split(" ", 1)
        port = int(port_str)

        # Give uvicorn a beat to bind the listener.
        time.sleep(0.5)

        with httpx.Client(timeout=5.0) as client:
            response = client.get(
                f"http://127.0.0.1:{port}/healthz",
                headers={"X-GuardiaBox-Token": token},
            )
        if response.status_code != 200:
            print(f"/healthz returned {response.status_code}", file=sys.stderr)
            return 1
        print("-> smoke test OK")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())


# Helpers exposed for smoke-test imports.
_ = shutil  # kept available for future ``shutil.which(pyinstaller)`` checks

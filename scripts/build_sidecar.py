"""Bundle the Python sidecar into a standalone executable via PyInstaller.

The output binary is consumed by the Tauri shell as an external resource
declared in ``src-tauri/tauri.conf.json > bundle.externalBin``.

Usage::

    uv run python scripts/build_sidecar.py [--release]

Outputs::

    src/guardiabox/ui/tauri/src-tauri/binaries/guardiabox-sidecar(.exe)

Implementation deliberately deferred — the real build pipeline calls
PyInstaller with the right ``--add-data`` flags, signs the binary on Windows
(``signtool``), and copies it under the Tauri resources tree before
``cargo tauri build`` runs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIDECAR_ENTRY = ROOT / "src" / "guardiabox" / "ui" / "tauri" / "sidecar" / "main.py"
TAURI_BINARIES = ROOT / "src" / "guardiabox" / "ui" / "tauri" / "src-tauri" / "binaries"


def main() -> int:
    """Entry point — currently a stub printing the planned command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="Build optimised binary.")
    parser.add_argument(
        "--output-name",
        default="guardiabox-sidecar",
        help="Name of the produced executable (without extension).",
    )
    args = parser.parse_args()

    target_triple = _detect_target_triple()
    output_name = f"{args.output_name}-{target_triple}"

    sys.stdout.write(
        "PyInstaller invocation (stub):\n"
        f"  pyinstaller --onefile --noconsole --name {output_name} \\\n"
        f"    --distpath {TAURI_BINARIES} \\\n"
        f"    --workpath {ROOT / 'build' / 'pyinstaller'} \\\n"
        f"    --specpath {ROOT / 'build' / 'pyinstaller'} \\\n"
        f"    {SIDECAR_ENTRY}\n"
    )
    sys.stdout.write("\nReal implementation tracked in docs/specs/000-tauri-sidecar/plan.md.\n")
    return 0


def _detect_target_triple() -> str:
    """Return the Rust-style target triple Tauri expects in externalBin names."""
    if sys.platform == "win32":
        return "x86_64-pc-windows-msvc"
    if sys.platform == "darwin":
        import platform

        return "aarch64-apple-darwin" if platform.machine() == "arm64" else "x86_64-apple-darwin"
    return "x86_64-unknown-linux-gnu"


if __name__ == "__main__":
    raise SystemExit(main())

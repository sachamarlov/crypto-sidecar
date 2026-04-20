"""Tauri sidecar entry point.

Bootstraps the FastAPI app, binds it to ``127.0.0.1`` on a free port, prints
the bound port + a fresh session token to stdout (consumed by the Tauri shell
to authenticate subsequent requests), and serves until terminated.

Security guarantees:

* Bind address is **always** ``127.0.0.1`` — never ``0.0.0.0``.
* Each launch generates a fresh 32-byte session token; requests without it are
  rejected with HTTP 401.
* No CORS allowed by default; the Tauri shell injects the token into a
  custom header it controls.

Implementation deliberately deferred — see
``docs/specs/000-tauri-sidecar/plan.md``.
"""

from __future__ import annotations

import secrets
import sys


def main() -> int:
    """Sidecar entry point. Returns a Unix-style exit code."""
    session_token = secrets.token_urlsafe(32)
    # The actual uvicorn.run() invocation is added in the spec implementation.
    sys.stdout.write(f"GUARDIABOX_SIDECAR_TOKEN={session_token}\n")
    sys.stdout.flush()
    raise NotImplementedError("See docs/specs/000-tauri-sidecar/plan.md")


if __name__ == "__main__":
    raise SystemExit(main())

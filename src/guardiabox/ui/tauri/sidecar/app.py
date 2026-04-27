"""FastAPI application factory for the GuardiaBox sidecar.

Separating the factory from the entry point (``main.py``) lets tests
mount the app under :class:`fastapi.testclient.TestClient` without
spawning a real uvicorn server. The entry point handles the per-launch
session token, free-port discovery, and signal-driven shutdown; this
module knows only about the HTTP shape.

Auth model (cf. ADR-0016):

* Every request to ``/api/v1/*`` must carry ``X-GuardiaBox-Token``
  matching the launch token (verified by the middleware in G-02).
* ``/healthz``, ``/readyz``, ``/version`` are explicitly exempted so
  the Rust shell can probe the sidecar before unlocking the vault.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from guardiabox import __version__
from guardiabox.config import Settings, get_settings
from guardiabox.logging import get_logger
from guardiabox.ui.tauri.sidecar.api.v1.health import build_health_router

__all__ = ["create_app"]

_log = get_logger("guardiabox.sidecar.app")


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan hook: log startup + leave room for SessionStore wiring.

    The session-store zero-fill on shutdown (ADR-0016 §B) lands in G-03;
    today this hook is intentionally minimal so each Phase G commit
    extends a working state instead of replacing one.
    """
    _log.info("sidecar.startup", version=__version__)
    try:
        yield
    finally:
        _log.info("sidecar.shutdown")


def create_app(
    *,
    session_token: str,
    settings: Settings | None = None,
) -> FastAPI:
    """Construct a fresh FastAPI application bound to ``session_token``.

    Args:
        session_token: 32-byte URL-safe token generated at process
            launch by ``main.py``. Stored in ``app.state.session_token``;
            the auth middleware (G-02) reads it from there to validate
            inbound requests in constant time.
        settings: Optional Settings override. Defaults to a fresh
            :func:`guardiabox.config.get_settings` call so tests can
            inject a temp ``data_dir``.

    Returns:
        A wired :class:`fastapi.FastAPI` instance ready to be served by
        uvicorn or mounted under :class:`fastapi.testclient.TestClient`.
    """
    if not session_token:
        msg = "session_token must be a non-empty string"
        raise ValueError(msg)

    resolved_settings = settings if settings is not None else get_settings()

    app = FastAPI(
        title="GuardiaBox Sidecar",
        version=__version__,
        description=(
            "Loopback-only HTTP API consumed by the Tauri shell. "
            "Authenticated via per-launch session token. See ADR-0016."
        ),
        lifespan=_lifespan,
        # CORS deliberately disabled (ADR-0016 §I): the only legitimate
        # caller is the Tauri shell on the same origin via the loopback
        # URL it discovered through the handshake.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.session_token = session_token
    app.state.settings = resolved_settings

    # Health endpoints (G-09) are exempt from auth; they ship in G-01
    # because the sidecar boot smoke test needs a route to hit before
    # the auth middleware lands in G-02.
    app.include_router(build_health_router(), tags=["health"])
    return app

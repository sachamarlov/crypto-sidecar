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
from guardiabox.ui.tauri.sidecar.api.middleware import TokenAuthMiddleware
from guardiabox.ui.tauri.sidecar.api.v1.decrypt import build_decrypt_router
from guardiabox.ui.tauri.sidecar.api.v1.encrypt import build_encrypt_router
from guardiabox.ui.tauri.sidecar.api.v1.health import build_health_router
from guardiabox.ui.tauri.sidecar.api.v1.vault import build_vault_router
from guardiabox.ui.tauri.sidecar.state import SessionStore

__all__ = ["create_app"]

_log = get_logger("guardiabox.sidecar.app")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan hook: startup log + SessionStore zero-fill on shutdown.

    On graceful shutdown we tear down every active vault session so
    the buffers holding admin keys and per-user vault keys are
    zero-filled before the process image leaves memory. Python's
    immutable ``bytes`` copies still outlive zero-fill, but the
    mutable bytearrays we own do not (cf. THREAT_MODEL section 4.5).
    """
    _log.info("sidecar.startup", version=__version__)
    try:
        yield
    finally:
        store: SessionStore | None = getattr(app.state, "session_store", None)
        reaped = store.close_all() if store is not None else 0
        _log.info("sidecar.shutdown", sessions_reaped=reaped)


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
    # SessionStore TTL = auto_lock_minutes (cf. ADR-0016 sec B).
    # Sliding expiry on access; zero-fill on close / lifespan shutdown.
    app.state.session_store = SessionStore(
        ttl_seconds=resolved_settings.auto_lock_minutes * 60,
    )

    # Auth middleware (ADR-0016 sec A): every /api/v1/* request must
    # carry X-GuardiaBox-Token. /healthz, /readyz, /version, and
    # /openapi.json are whitelisted -- see AUTH_EXEMPT_PATHS.
    app.add_middleware(TokenAuthMiddleware)

    # Health endpoints (G-09) are exempt from auth; they ship in G-01
    # because the sidecar boot smoke test needs a route to hit before
    # the auth middleware lands in G-02.
    app.include_router(build_health_router(), tags=["health"])
    # Vault unlock / lock / status (G-03). Auth-protected by the
    # token middleware; the body of /unlock carries the admin
    # password as a Pydantic SecretStr.
    app.include_router(build_vault_router())
    # Encrypt / decrypt routers (G-04). File-mode only for now; the
    # ``vault_user`` audit hook lands with G-06 (users router).
    app.include_router(build_encrypt_router())
    app.include_router(build_decrypt_router())
    return app

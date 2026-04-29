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
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from guardiabox import __version__
from guardiabox.config import Settings, get_settings
from guardiabox.logging import get_logger
from guardiabox.ui.tauri.sidecar.api.middleware import TokenAuthMiddleware
from guardiabox.ui.tauri.sidecar.api.rate_limit import (
    limiter,
    rate_limit_exceeded_handler,
)
from guardiabox.ui.tauri.sidecar.api.stream_hub import StreamHub
from guardiabox.ui.tauri.sidecar.api.v1.audit import build_audit_router
from guardiabox.ui.tauri.sidecar.api.v1.decrypt import build_decrypt_router
from guardiabox.ui.tauri.sidecar.api.v1.doctor import build_doctor_router
from guardiabox.ui.tauri.sidecar.api.v1.encrypt import build_encrypt_router
from guardiabox.ui.tauri.sidecar.api.v1.health import build_health_router
from guardiabox.ui.tauri.sidecar.api.v1.init import build_init_router
from guardiabox.ui.tauri.sidecar.api.v1.inspect import build_inspect_router
from guardiabox.ui.tauri.sidecar.api.v1.secure_delete import build_secure_delete_router
from guardiabox.ui.tauri.sidecar.api.v1.share import build_share_router
from guardiabox.ui.tauri.sidecar.api.v1.users import build_users_router
from guardiabox.ui.tauri.sidecar.api.v1.vault import build_vault_router
from guardiabox.ui.tauri.sidecar.api.ws import build_ws_router
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
    # Rate limiter (ADR-0016 sec D): per-IP buckets via slowapi.
    # Decorators on individual routes will reference ``app.state.limiter``.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    # Stream hub (G-10): in-memory pub/sub for WebSocket progress
    # events. Routers publish opportunistically when their request
    # carries an ``operation_id`` query param.
    app.state.stream_hub = StreamHub()

    # Auth middleware (ADR-0016 sec A): every /api/v1/* request must
    # carry X-GuardiaBox-Token. /healthz, /readyz, /version, and
    # /openapi.json are whitelisted -- see AUTH_EXEMPT_PATHS.
    app.add_middleware(TokenAuthMiddleware)

    # CORS middleware (must be added AFTER TokenAuth so it runs
    # FIRST -- FastAPI middleware order is LIFO). The Tauri 2 WebView
    # serves React from `http(s)://tauri.localhost` while the sidecar
    # listens on `http://127.0.0.1:<random>`: cross-origin, so the
    # browser issues a CORS preflight (OPTIONS) on every non-simple
    # fetch. The preflight carries no auth headers (browsers strip
    # them); without this middleware running first, TokenAuth would
    # reject the OPTIONS and the real request never gets sent.
    #
    # Token auth remains the real security gate: CORS only decides
    # which *origins* may issue the preflight; the token decides
    # which *requests* are honoured. Bind-address stays 127.0.0.1-only
    # (security test unaffected). ADR-0016 sec I amended.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://tauri.localhost",
            "https://tauri.localhost",
            "tauri://localhost",
            "http://localhost:1420",  # Vite dev server
        ],
        allow_credentials=False,  # token rides in a custom header, not cookies
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "X-GuardiaBox-Token",
            "X-GuardiaBox-Session",
        ],
    )

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
    # Users CRUD (G-06). Requires both the launch token AND a vault
    # session (X-GuardiaBox-Session header).
    app.include_router(build_users_router())
    # Audit history + verify chain (G-07).
    app.include_router(build_audit_router())
    # Inspect / init / doctor / secure-delete (G-08).
    app.include_router(build_inspect_router())
    app.include_router(build_init_router())
    app.include_router(build_doctor_router())
    app.include_router(build_secure_delete_router())
    # Share / accept (G-05). Hybrid RSA-OAEP wrap + RSA-PSS sign;
    # anti-oracle preserved on accept failures (422 constant body).
    app.include_router(build_share_router())
    # WebSocket /api/v1/stream (G-10). Auth via query string
    # (browsers cannot set headers on WS); token compare is
    # constant-time, session validated against the SessionStore.
    app.include_router(build_ws_router())
    return app

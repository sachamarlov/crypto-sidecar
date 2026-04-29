r"""Vault unlock / lock / status endpoints (ADR-0016 sec B).

The router is mounted under ``/api/v1/vault`` and is auth-protected
by :class:`TokenAuthMiddleware` (G-02). The unlock endpoint derives
the admin key from the supplied password, opens a session in the
in-process :class:`SessionStore`, and returns the session id that
the frontend will forward on every subsequent request via the
``X-GuardiaBox-Session`` header (consumed by G-04+ routers).

Anti-oracle:
* A wrong admin password and an absent ``vault.admin.json`` both
  surface as HTTP 401 with the constant body
  ``{"detail": "unlock failed"}``. The frontend cannot tell the
  difference -- which it should not, because the discriminator
  reveals whether a vault even exists at this data_dir.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import GuardiaBoxError
from guardiabox.logging import get_logger
from guardiabox.persistence.bootstrap import vault_paths
from guardiabox.security.vault_admin import (
    VaultAdminConfigInvalidError,
    VaultAdminConfigMissingError,
    read_admin_config,
    verify_admin_password,
)
from guardiabox.ui.tauri.sidecar.api.dependencies import require_session
from guardiabox.ui.tauri.sidecar.api.rate_limit import BUCKET_AUTH_UNLOCK, limiter
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel
from guardiabox.ui.tauri.sidecar.state import SessionStore, VaultSession

__all__ = [
    "build_vault_router",
]


_UNLOCK_FAILED_DETAIL = "unlock failed"

_log = get_logger("guardiabox.sidecar.vault")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UnlockRequest(SidecarBaseModel):
    admin_password: SecretStr


class UnlockResponse(SidecarBaseModel):
    session_id: str
    expires_in_seconds: int


class StatusResponse(SidecarBaseModel):
    active_sessions: int
    vault_initialized: bool


# ---------------------------------------------------------------------------
# Dependency injection helpers
# ---------------------------------------------------------------------------


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _store(request: Request) -> SessionStore:
    store: SessionStore = request.app.state.session_store
    return store


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_vault_router() -> APIRouter:
    """Return the ``/api/v1/vault`` router."""
    router = APIRouter(prefix="/api/v1/vault", tags=["vault"])

    @router.post(
        "/unlock",
        response_model=UnlockResponse,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit(BUCKET_AUTH_UNLOCK)
    def unlock(
        request: Request,
        body: UnlockRequest,
        settings: Annotated[Settings, Depends(_settings)],
        store: Annotated[SessionStore, Depends(_store)],
    ) -> UnlockResponse:
        # Audit A P1-3 / C P0-1: rate-limit decorator was declared in
        # rate_limit.py but never applied -- brute-force /vault/unlock
        # was effectively unbounded (4 attempts/sec post-PBKDF2 at the
        # CPU floor). 5/min per source IP closes the ADR-0016 sec D
        # gate that the threat model relies on. slowapi requires the
        # `request: Request` first parameter to extract the client IP
        # via get_remote_address.
        del request  # used by slowapi via inspection
        paths = vault_paths(settings.data_dir)
        admin_key: bytes | None = None
        try:
            config = read_admin_config(paths.admin_config)
            # ``verify_admin_password`` derives the key AND validates
            # it against the verification_blob persisted at init.
            # Wrong password -> DecryptionError -> uniform 401.
            admin_key = verify_admin_password(config, body.admin_password.get_secret_value())
        except (VaultAdminConfigMissingError, VaultAdminConfigInvalidError):
            # Vault not initialised OR config malformed: indistinguishable
            # from "wrong password" at this layer (anti-oracle).
            _log.info("vault.unlock.rejected", reason="config-missing-or-invalid")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_UNLOCK_FAILED_DETAIL,
            ) from None
        except GuardiaBoxError:
            _log.info("vault.unlock.rejected", reason="verification-failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_UNLOCK_FAILED_DETAIL,
            ) from None

        # ``derive_admin_key`` returns immutable bytes; SessionStore
        # copies into a bytearray so we can zero-fill on close. Drop
        # our own reference promptly -- the GC may reclaim it before
        # the session expires, which still doesn't satisfy hard
        # zero-fill (cf. THREAT_MODEL 4.5) but is the best Python lets
        # us do here.
        try:
            session = store.open_admin_session(admin_key)
        finally:
            del admin_key

        return UnlockResponse(
            session_id=session.session_id,
            expires_in_seconds=int(session.expires_at - _now_via(store)),
        )

    @router.post("/lock", status_code=status.HTTP_204_NO_CONTENT)
    def lock(
        session: Annotated[VaultSession, Depends(require_session)],
        store: Annotated[SessionStore, Depends(_store)],
    ) -> None:
        # Audit A P0-3: previously read session_id from the body, no
        # require_session dep -- any attacker holding the launch token
        # could force-close any session id they could guess (DoS
        # primitive). require_session dep validates the X-GuardiaBox-
        # Session header against the SessionStore, returning 401 on
        # missing/expired. The session id never travels in a body.
        store.close(session.session_id)

    @router.get("/status", response_model=StatusResponse)
    def vault_status(
        settings: Annotated[Settings, Depends(_settings)],
        store: Annotated[SessionStore, Depends(_store)],
    ) -> StatusResponse:
        paths = vault_paths(settings.data_dir)
        return StatusResponse(
            active_sessions=len(store),
            vault_initialized=paths.admin_config.is_file(),
        )

    return router


def _now_via(store: SessionStore) -> float:
    """Read the store's monotonic clock so tests with frozen time stay coherent."""
    # SessionStore exposes its clock through ``_now`` for tests; using
    # it here keeps the ``expires_in_seconds`` reporting synchronised
    # with the actual store TTL, especially under monkeypatch.
    return store._now()  # noqa: SLF001 -- intentional access to the store's clock

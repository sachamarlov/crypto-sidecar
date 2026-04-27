"""Health endpoints exempted from token auth (ADR-0016 §A whitelist).

Three routes:

* ``GET /healthz`` -- the process is alive and the event loop drains.
  Used by the Tauri shell to confirm the spawn succeeded before
  attempting any authenticated call.
* ``GET /readyz`` -- the *vault* is initialised
  (``vault.admin.json`` exists under ``Settings.data_dir``). Returns
  503 when not, so the frontend can route the user to the init flow
  rather than a generic error.
* ``GET /version`` -- build metadata for the About panel and CI smoke
  tests.

These three routes intentionally accept no input and surface no
secret material. They predate the auth middleware so the shell can
probe the sidecar without yet holding the session token.
"""

from __future__ import annotations

import platform as platform_module
import sys
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from guardiabox import __version__
from guardiabox.config import Settings
from guardiabox.persistence.bootstrap import vault_paths

__all__ = ["build_health_router"]


class HealthResponse(BaseModel):
    """``GET /healthz`` body."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: str = Field(default="ok", description="Liveness marker.")


class ReadyResponse(BaseModel):
    """``GET /readyz`` body."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    ready: bool
    vault_initialized: bool
    reason: str | None = None


class VersionResponse(BaseModel):
    """``GET /version`` body."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    version: str
    python_version: str
    platform: str
    machine: str


def _settings_from_request(request: Request) -> Settings:
    """Pull the :class:`Settings` instance attached at app construction."""
    settings: Settings = request.app.state.settings
    return settings


def build_health_router() -> APIRouter:
    """Return a fresh router exposing the three liveness/readiness routes."""
    router = APIRouter()

    @router.get("/healthz", response_model=HealthResponse)
    def healthz() -> HealthResponse:
        return HealthResponse(status="ok")

    @router.get("/readyz")
    def readyz(
        response: Response,
        settings: Annotated[Settings, Depends(_settings_from_request)],
    ) -> ReadyResponse:
        paths = vault_paths(settings.data_dir)
        if paths.admin_config.is_file():
            return ReadyResponse(ready=True, vault_initialized=True)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadyResponse(
            ready=False,
            vault_initialized=False,
            reason="vault not initialised; run `guardiabox init` first.",
        )

    @router.get("/version", response_model=VersionResponse)
    def version() -> VersionResponse:
        return VersionResponse(
            version=__version__,
            python_version=sys.version.split()[0],
            platform=platform_module.system(),
            machine=platform_module.machine(),
        )

    return router

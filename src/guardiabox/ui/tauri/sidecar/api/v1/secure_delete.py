"""POST /api/v1/secure-delete -- DoD multi-pass overwrite (G-08).

Wraps :func:`core.secure_delete.secure_delete` with method
``overwrite-dod``. The crypto-erase method requires a vault session
plus a vault_user lookup (cf. spec 004 Phase B2); that variant is
roadmapped as a follow-up router that reuses the SessionStore.

For the MVP soutenance scope, file-mode overwrite-dod via HTTP is
the load-bearing surface -- the CLI keeps crypto-erase available
for power users.

Auth: launch token only (overwrite-dod has no DB dependency).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field

from guardiabox.config import Settings
from guardiabox.core.exceptions import PathTraversalError, SymlinkEscapeError
from guardiabox.core.secure_delete import (
    SecureDeleteMethod,
    secure_delete as run_secure_delete,
)
from guardiabox.fileio.platform import is_ssd
from guardiabox.fileio.safe_path import resolve_within
from guardiabox.ui.tauri.sidecar.api.dependencies import settings_dep
from guardiabox.ui.tauri.sidecar.api.rate_limit import BUCKET_WRITE, limiter
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel

__all__ = ["build_secure_delete_router"]


class SecureDeleteRequest(SidecarBaseModel):
    path: str = Field(description="Absolute filesystem path of the file to wipe.")
    passes: int = Field(default=3, ge=1, le=35)
    confirm_ssd: bool = Field(
        default=False,
        description=(
            "Acknowledge that overwrite is best-effort on SSD media. Required "
            "when the platform probe reports SSD."
        ),
    )


class SecureDeleteResponse(SidecarBaseModel):
    path: str
    method: str
    passes: int
    is_ssd: bool | None


def build_secure_delete_router() -> APIRouter:
    """Return the ``/api/v1/secure-delete`` router."""
    router = APIRouter(prefix="/api/v1", tags=["secure-delete"])

    @router.post(
        "/secure-delete",
        response_model=SecureDeleteResponse,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit(BUCKET_WRITE)
    def secure_delete(
        request: Request,
        body: SecureDeleteRequest,
        settings: Annotated[Settings, Depends(settings_dep)],
    ) -> SecureDeleteResponse:
        del request  # consumed by slowapi via signature inspection
        # Audit A P0-1: previously the router accepted any absolute
        # path with no resolve_within guard, so an attacker holding the
        # launch token could DoD-erase /etc/passwd or any file the
        # sidecar process could write to. resolve_within constrains
        # the operation to the vault data_dir; the symlink/reparse
        # checks reject Windows junctions + POSIX symlinks alike.
        try:
            target = resolve_within(Path(body.path), settings.data_dir)
        except (PathTraversalError, SymlinkEscapeError) as exc:
            raise HTTPException(status_code=400, detail="path validation failed") from exc
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"file not found: {target}")

        ssd_verdict = is_ssd(target)
        if ssd_verdict is True and not body.confirm_ssd:
            raise HTTPException(
                status_code=409,
                detail=(
                    "SSD detected: overwrite is best-effort due to wear-levelling. "
                    "Re-submit with confirm_ssd=true or prefer crypto-erase via "
                    "the CLI."
                ),
            )

        run_secure_delete(
            target,
            method=SecureDeleteMethod.OVERWRITE_DOD,
            passes=body.passes,
        )

        return SecureDeleteResponse(
            path=str(target),
            method=SecureDeleteMethod.OVERWRITE_DOD.value,
            passes=body.passes,
            is_ssd=ssd_verdict,
        )

    return router

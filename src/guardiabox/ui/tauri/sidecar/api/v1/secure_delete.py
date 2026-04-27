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

from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from guardiabox.core.secure_delete import (
    SecureDeleteMethod,
    secure_delete as run_secure_delete,
)
from guardiabox.fileio.platform import is_ssd
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
    def secure_delete(body: SecureDeleteRequest) -> SecureDeleteResponse:
        target = Path(body.path)
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

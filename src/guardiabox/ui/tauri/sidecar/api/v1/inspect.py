"""POST /api/v1/inspect -- read-only ``.crypt`` header view (G-08).

Returns the container metadata that ``inspect_container`` produces:
version, kdf id and parameters, salt, base nonce, header / ciphertext
sizes. No password required, no plaintext touched -- safe to run on
an untrusted file.

Auth: launch token only (no vault session needed, since nothing is
read or written through the persistence layer).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from guardiabox.core.exceptions import (
    CorruptedContainerError,
    InvalidContainerError,
    UnknownKdfError,
    UnsupportedVersionError,
    WeakKdfParametersError,
)
from guardiabox.core.operations import inspect_container
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel

__all__ = ["build_inspect_router"]


class InspectRequest(SidecarBaseModel):
    path: str = Field(description="Absolute filesystem path of the .crypt file.")


class InspectResponse(SidecarBaseModel):
    path: str
    version: int
    kdf_id: int
    kdf_name: str
    kdf_params_summary: str
    salt_hex: str
    base_nonce_hex: str
    header_size: int
    ciphertext_size: int


def build_inspect_router() -> APIRouter:
    """Return the ``/api/v1/inspect`` router."""
    router = APIRouter(prefix="/api/v1", tags=["inspect"])

    @router.post(
        "/inspect",
        response_model=InspectResponse,
        status_code=status.HTTP_200_OK,
    )
    def inspect(body: InspectRequest) -> InspectResponse:
        source = Path(body.path)
        if not source.is_file():
            raise HTTPException(status_code=404, detail=f"file not found: {source}")
        try:
            view = inspect_container(source)
        except (
            InvalidContainerError,
            UnsupportedVersionError,
            UnknownKdfError,
            CorruptedContainerError,
            WeakKdfParametersError,
        ) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return InspectResponse(
            path=str(view.path),
            version=view.version,
            kdf_id=view.kdf_id,
            kdf_name=view.kdf_name,
            kdf_params_summary=view.kdf_params_summary,
            salt_hex=view.salt_hex,
            base_nonce_hex=view.base_nonce_hex,
            header_size=view.header_size,
            ciphertext_size=view.ciphertext_size,
        )

    return router

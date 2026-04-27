"""POST /api/v1/init -- bootstrap a fresh vault (G-08).

Calls :func:`persistence.bootstrap.init_vault` to create
``data_dir``, write ``vault.admin.json`` (schema v2 with verification
blob), run the Alembic migrations, and append the genesis
``system.startup`` audit row.

Auth: launch token only. The endpoint is the chicken-and-egg pre-
condition for every session-gated route -- there is no session to
require before init. Refuses to overwrite an existing vault (409).
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import WeakPasswordError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.persistence.bootstrap import init_vault
from guardiabox.security.vault_admin import VaultAdminConfigAlreadyExistsError
from guardiabox.ui.tauri.sidecar.api.dependencies import settings_dep
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel

__all__ = ["build_init_router"]


class InitRequest(SidecarBaseModel):
    admin_password: SecretStr
    kdf: Literal["pbkdf2", "argon2id"] = "pbkdf2"


class InitResponse(SidecarBaseModel):
    data_dir: str
    db_path: str
    admin_config_path: str


def build_init_router() -> APIRouter:
    """Return the ``/api/v1/init`` router."""
    router = APIRouter(prefix="/api/v1", tags=["init"])

    @router.post(
        "/init",
        response_model=InitResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def initialise(
        body: InitRequest,
        settings: Annotated[Settings, Depends(settings_dep)],
    ) -> InitResponse:
        kdf_impl: Pbkdf2Kdf | Argon2idKdf = Argon2idKdf() if body.kdf == "argon2id" else Pbkdf2Kdf()
        try:
            paths = await init_vault(
                settings.data_dir,
                body.admin_password.get_secret_value(),
                kdf=kdf_impl,
            )
        except WeakPasswordError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except VaultAdminConfigAlreadyExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        return InitResponse(
            data_dir=str(paths.data_dir),
            db_path=str(paths.db),
            admin_config_path=str(paths.admin_config),
        )

    return router

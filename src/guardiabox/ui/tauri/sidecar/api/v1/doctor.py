"""GET /api/v1/doctor -- diagnostic view (G-08).

Mirrors the ``guardiabox doctor`` CLI: vault paths, SQLCipher
availability, optional SSD report, optional audit chain verify.

The audit verify branch needs the admin key -- callers must hold an
active vault session for ``?verify_audit=true`` to succeed. Without
the session header the field is omitted.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from guardiabox.config import Settings
from guardiabox.fileio.platform import is_ssd
from guardiabox.persistence.bootstrap import vault_paths
from guardiabox.persistence.database import sqlcipher_available
from guardiabox.security import audit as audit_module
from guardiabox.ui.tauri.sidecar.api.dependencies import (
    SESSION_HEADER,
    open_db_session,
    settings_dep,
    store_dep,
)
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel
from guardiabox.ui.tauri.sidecar.state import SessionStore

__all__ = ["build_doctor_router"]


class SsdReport(SidecarBaseModel):
    is_ssd: bool | None
    recommendation: str


class AuditVerifyView(SidecarBaseModel):
    ok: bool
    first_bad_sequence: int | None
    entries_checked: int


class DoctorResponse(SidecarBaseModel):
    data_dir: str
    db_exists: bool
    admin_config_exists: bool
    sqlcipher_available: bool
    ssd_report: SsdReport | None
    audit_chain: AuditVerifyView | None


def _ssd_recommendation(verdict: bool | None) -> str:
    if verdict is True:
        return (
            "SSD detected: secure-delete --method overwrite is best-effort due to "
            "wear-levelling. Prefer --method crypto-erase when the file lives in a "
            "vault user."
        )
    if verdict is False:
        return "HDD detected: DoD multi-pass overwrite is reliable here."
    return "Storage type unknown: assume SSD semantics (overwrite is best-effort)."


def build_doctor_router() -> APIRouter:
    """Return the ``/api/v1/doctor`` router."""
    router = APIRouter(prefix="/api/v1", tags=["doctor"])

    @router.get("/doctor", response_model=DoctorResponse)
    async def doctor(
        request: Request,
        settings: Annotated[Settings, Depends(settings_dep)],
        store: Annotated[SessionStore, Depends(store_dep)],
        verify_audit: Annotated[bool, Query()] = False,
        report_ssd: Annotated[bool, Query()] = False,
    ) -> DoctorResponse:
        paths = vault_paths(settings.data_dir)
        ssd_view: SsdReport | None = None
        if report_ssd:
            verdict = is_ssd(paths.data_dir)
            ssd_view = SsdReport(
                is_ssd=verdict,
                recommendation=_ssd_recommendation(verdict),
            )

        audit_view: AuditVerifyView | None = None
        if verify_audit:
            session_id = request.headers.get(SESSION_HEADER)
            session = store.get(session_id) if session_id is not None else None
            if session is not None:
                async with open_db_session(settings) as db:
                    result = await audit_module.verify(db, bytes(session.admin_key))
                audit_view = AuditVerifyView(
                    ok=result.ok,
                    first_bad_sequence=result.first_bad_sequence,
                    entries_checked=result.entries_checked,
                )

        return DoctorResponse(
            data_dir=str(paths.data_dir),
            db_exists=paths.db.is_file(),
            admin_config_exists=paths.admin_config.is_file(),
            sqlcipher_available=sqlcipher_available(),
            ssd_report=ssd_view,
            audit_chain=audit_view,
        )

    return router

"""GET /api/v1/audit + /api/v1/audit/verify (G-07).

Decrypted views over the hash-chained audit log + integrity probe.

Auth: launch token (G-02) + active vault session (G-03) -- the
admin key is needed to decrypt ``target_enc`` and ``metadata_enc``.

Verify is a defence-in-depth surface: the SQL trigger already
prevents UPDATE / DELETE on ``audit_log``, but
:func:`security.audit.verify` walks every row and recomputes the
chain hash, surfacing the first sequence that does not match the
expected ``prev_hash`` -- catches state diverged from outside
the sidecar (a manual SQL rewrite on disk).
"""

from __future__ import annotations

from datetime import datetime
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from guardiabox.config import Settings
from guardiabox.persistence.repositories import AuditRepository, UserRepository
from guardiabox.security import audit as audit_module
from guardiabox.ui.tauri.sidecar.api.dependencies import (
    open_db_session,
    require_session,
    settings_dep,
)
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel
from guardiabox.ui.tauri.sidecar.state import VaultSession

__all__ = ["build_audit_router"]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AuditEntryView(SidecarBaseModel):
    """Decrypted view of one audit row."""

    sequence: int
    timestamp: datetime
    actor_user_id: str | None
    actor_username: str | None
    action: str
    target: str | None
    metadata: dict[str, str] | None


class AuditListResponse(SidecarBaseModel):
    entries: list[AuditEntryView]


class AuditVerifyResponse(SidecarBaseModel):
    ok: bool
    first_bad_sequence: int | None
    entries_checked: int


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_audit_router() -> APIRouter:
    """Return the ``/api/v1/audit`` router."""
    router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

    @router.get("", response_model=AuditListResponse)
    async def list_audit(
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
        actor_user_id: Annotated[str | None, Query(description="Filter by actor.")] = None,
        action: Annotated[str | None, Query(description="Filter by action.")] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> AuditListResponse:
        async with open_db_session(settings) as db:
            audit_repo = AuditRepository(db, bytes(session.admin_key))
            user_repo = UserRepository(db, bytes(session.admin_key))

            rows = await audit_repo.list_filtered(
                actor_user_id=actor_user_id,
                action=action,
                limit=limit,
            )
            users = await user_repo.list_all()
            user_map = {u.id: user_repo.decrypt_username(u) for u in users}

            entries: list[AuditEntryView] = []
            for row in rows:
                target = audit_repo.decrypt_target(row) if row.target_enc else None
                metadata_bytes = audit_repo.decrypt_metadata(row) if row.metadata_enc else None
                metadata: dict[str, str] | None = None
                if metadata_bytes is not None:
                    metadata = json.loads(metadata_bytes.decode("utf-8"))
                entries.append(
                    AuditEntryView(
                        sequence=row.sequence,
                        timestamp=row.timestamp,
                        actor_user_id=row.actor_user_id,
                        actor_username=user_map.get(row.actor_user_id)
                        if row.actor_user_id
                        else None,
                        action=row.action,
                        target=target,
                        metadata=metadata,
                    )
                )
        return AuditListResponse(entries=entries)

    @router.get("/verify", response_model=AuditVerifyResponse)
    async def verify_chain(
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> AuditVerifyResponse:
        async with open_db_session(settings) as db:
            result = await audit_module.verify(db, bytes(session.admin_key))
        return AuditVerifyResponse(
            ok=result.ok,
            first_bad_sequence=result.first_bad_sequence,
            entries_checked=result.entries_checked,
        )

    return router

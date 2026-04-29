"""POST /api/v1/share + /api/v1/accept (G-05).

The hybrid RSA share flow over HTTP. The sender / recipient identity
plus passwords come in the body; the sidecar loads each user's
keystore from the DB, unlocks the RSA private with the supplied
password, and delegates to :func:`core.operations.share_file` /
:func:`core.operations.accept_share`.

Anti-oracle (ADR-0015 + ADR-0016 sec C):
* :class:`IntegrityError` on accept (signature, recipient,
  content-hash, unwrap, AEAD) collapses to HTTP 422 with the
  constant body ``{"detail": "share verification failed"}``.
* :class:`ShareExpiredError` is raised AFTER the signature has
  verified, so it is allowed to surface a distinct 422 detail
  (``share expired``) -- the attacker has already proven they can
  forge a valid signature, which is impossible against the sender's
  public key.

Sender RSA-private unlock failure surfaces as 401, distinct from
the recipient-side anti-oracle path; this is a per-user keystore
unlock that already has its own 5-attempts/min rate limit envelope
(slowapi, G-11).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field, SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import (
    DecryptionError,
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    IntegrityError,
    MessageTooLargeError,
    ShareExpiredError,
)
from guardiabox.core.operations import accept_share, share_file
from guardiabox.core.rsa import load_private_key_der, load_public_key_pem
from guardiabox.logging import get_logger
from guardiabox.persistence.repositories import UserRepository
from guardiabox.security import keystore as keystore_module
from guardiabox.security.audit import AuditAction, append as audit_append
from guardiabox.ui.tauri.sidecar.api.dependencies import (
    open_db_session,
    require_session,
    settings_dep,
)
from guardiabox.ui.tauri.sidecar.api.rate_limit import BUCKET_WRITE, limiter
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel
from guardiabox.ui.tauri.sidecar.state import VaultSession

__all__ = ["build_share_router"]

_log = get_logger("guardiabox.sidecar.share")

_ACCEPT_INTEGRITY_DETAIL = "share verification failed"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ShareRequest(SidecarBaseModel):
    source_path: str = Field(description="Absolute path to the .crypt to share.")
    sender_user_id: str
    sender_password: SecretStr
    recipient_user_id: str
    output_path: str = Field(description="Where to write the .gbox-share token.")
    expires_days: int = Field(default=0, ge=0, le=3650)
    force: bool = False


class ShareResponse(SidecarBaseModel):
    output_path: str
    sender_user_id: str
    recipient_user_id: str


class AcceptRequest(SidecarBaseModel):
    source_path: str = Field(description="Absolute path to the .gbox-share token.")
    recipient_user_id: str
    recipient_password: SecretStr
    sender_user_id: str
    output_path: str = Field(description="Where to write the recovered plaintext.")
    force: bool = False


class AcceptResponse(SidecarBaseModel):
    output_path: str
    plaintext_size: int


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def _keystore_from_user(user: object) -> keystore_module.Keystore:
    """Build a :class:`Keystore` view from a SQLAlchemy ``User`` row."""
    return keystore_module.Keystore(
        salt=user.salt,  # type: ignore[attr-defined]
        kdf_id=user.kdf_id,  # type: ignore[attr-defined]
        kdf_params=user.kdf_params,  # type: ignore[attr-defined]
        wrapped_vault_key=user.wrapped_vault_key,  # type: ignore[attr-defined]
        wrapped_rsa_private=user.wrapped_rsa_private,  # type: ignore[attr-defined]
        rsa_public_pem=user.rsa_public_pem,  # type: ignore[attr-defined]
    )


def build_share_router() -> APIRouter:  # noqa: PLR0915 -- two routers + DB + audit + RSA unlock co-locate intentionally
    """Return the ``/api/v1/share`` + ``/api/v1/accept`` router."""
    router = APIRouter(prefix="/api/v1", tags=["share"])

    @router.post("/share", response_model=ShareResponse, status_code=status.HTTP_200_OK)
    @limiter.limit(BUCKET_WRITE)
    async def share(
        request: Request,
        body: ShareRequest,
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> ShareResponse:
        del request  # consumed by slowapi via signature inspection
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            users = await repo.list_all()
            sender = next((u for u in users if u.id == body.sender_user_id), None)
            recipient = next((u for u in users if u.id == body.recipient_user_id), None)
            if sender is None:
                raise HTTPException(status_code=404, detail="sender user not found")
            if recipient is None:
                raise HTTPException(status_code=404, detail="recipient user not found")

            # Unlock sender's RSA private via the supplied password.
            try:
                sender_keystore = _keystore_from_user(sender)
                rsa_private_der = keystore_module.unlock_rsa_private(
                    sender_keystore, body.sender_password.get_secret_value()
                )
            except DecryptionError as exc:
                raise HTTPException(
                    status_code=401,
                    detail="sender password rejected",
                ) from exc

            sender_private = load_private_key_der(rsa_private_der)
            recipient_public = load_public_key_pem(recipient.rsa_public_pem)

            try:
                output = share_file(
                    source=Path(body.source_path),
                    sender_password=body.sender_password.get_secret_value(),
                    sender_user_id=uuid.UUID(body.sender_user_id),
                    sender_private_key=sender_private,
                    recipient_user_id=uuid.UUID(body.recipient_user_id),
                    recipient_public_key=recipient_public,
                    output=Path(body.output_path),
                    expires_at=_to_epoch(body.expires_days),
                    force=body.force,
                )
            except (DestinationCollidesWithSourceError, DestinationAlreadyExistsError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            except MessageTooLargeError as exc:
                raise HTTPException(status_code=413, detail=str(exc)) from exc
            except DecryptionError as exc:
                # The .crypt source could not be decrypted by the
                # sender password -- 401 (auth error) rather than 422
                # because the failure is on the sender's own data.
                raise HTTPException(status_code=401, detail="source decryption failed") from exc

            await audit_append(
                db,
                bytes(session.admin_key),
                actor_user_id=sender.id,
                action=AuditAction.FILE_SHARE,
                target=str(output.name),
                metadata={"recipient_user_id": recipient.id},
            )

        _log.info(
            "sidecar.share.created",
            sender=body.sender_user_id,
            recipient=body.recipient_user_id,
        )
        return ShareResponse(
            output_path=str(output),
            sender_user_id=body.sender_user_id,
            recipient_user_id=body.recipient_user_id,
        )

    @router.post("/accept", response_model=AcceptResponse, status_code=status.HTTP_200_OK)
    @limiter.limit(BUCKET_WRITE)
    async def accept(
        request: Request,
        body: AcceptRequest,
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> AcceptResponse:
        del request  # consumed by slowapi via signature inspection
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            users = await repo.list_all()
            recipient = next((u for u in users if u.id == body.recipient_user_id), None)
            sender = next((u for u in users if u.id == body.sender_user_id), None)
            if recipient is None:
                raise HTTPException(status_code=404, detail="recipient user not found")
            if sender is None:
                raise HTTPException(status_code=404, detail="sender user not found")

            try:
                recipient_keystore = _keystore_from_user(recipient)
                rsa_private_der = keystore_module.unlock_rsa_private(
                    recipient_keystore,
                    body.recipient_password.get_secret_value(),
                )
            except DecryptionError as exc:
                raise HTTPException(
                    status_code=401,
                    detail="recipient password rejected",
                ) from exc

            recipient_private = load_private_key_der(rsa_private_der)
            sender_public = load_public_key_pem(sender.rsa_public_pem)

            try:
                output = accept_share(
                    source=Path(body.source_path),
                    recipient_private_key=recipient_private,
                    sender_public_key=sender_public,
                    expected_recipient_user_id=uuid.UUID(body.recipient_user_id),
                    output=Path(body.output_path),
                    force=body.force,
                )
            except IntegrityError as exc:
                # Anti-oracle: every authenticity-related failure is
                # the same 422 body. NEVER log the cause string.
                _log.info("sidecar.accept.anti_oracle_failure")
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=_ACCEPT_INTEGRITY_DETAIL,
                ) from exc
            except ShareExpiredError as exc:
                # Raised AFTER signature verify, so OK to differentiate.
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="share expired",
                ) from exc
            except (DestinationCollidesWithSourceError, DestinationAlreadyExistsError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

            await audit_append(
                db,
                bytes(session.admin_key),
                actor_user_id=recipient.id,
                action=AuditAction.FILE_SHARE_ACCEPT,
                target=str(output.name),
                metadata={"sender_user_id": sender.id},
            )

        plaintext_size = output.stat().st_size
        _log.info(
            "sidecar.accept.ok",
            recipient=body.recipient_user_id,
            sender=body.sender_user_id,
            plaintext_size=plaintext_size,
        )
        return AcceptResponse(output_path=str(output), plaintext_size=plaintext_size)

    return router


def _to_epoch(days: int) -> int:
    """Return Unix epoch seconds ``days`` from now (0 == never)."""
    if days <= 0:
        return 0
    import time

    return int(time.time()) + days * 86_400

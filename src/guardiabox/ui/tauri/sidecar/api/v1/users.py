"""POST/GET/DELETE /api/v1/users -- multi-user CRUD over the vault.

Lands G-06 of Phase G. Every endpoint requires:
* the launch token (``X-GuardiaBox-Token``, validated by the
  middleware in G-02), and
* an active vault session (``X-GuardiaBox-Session``, validated by
  :func:`require_session` in G-03).

The session's admin key gates every encrypted column read / write;
the audit hook for ``user.create`` and ``user.delete`` runs inside
the same DB transaction so a successful insert is always paired
with a chained audit row.
"""

from __future__ import annotations

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field, SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import WeakPasswordError
from guardiabox.logging import get_logger
from guardiabox.persistence.repositories import UserRepository
from guardiabox.security import keystore
from guardiabox.security.audit import AuditAction, append as audit_append
from guardiabox.ui.tauri.sidecar.api.dependencies import (
    open_db_session,
    require_session,
    settings_dep,
)
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel
from guardiabox.ui.tauri.sidecar.state import VaultSession

__all__ = ["build_users_router"]

_log = get_logger("guardiabox.sidecar.users")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UserView(SidecarBaseModel):
    """Decrypted view of a vault user."""

    user_id: str
    username: str
    has_keystore: bool


class UsersList(SidecarBaseModel):
    users: list[UserView]


class UserCreateRequest(SidecarBaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    kdf: str = Field(default="pbkdf2", pattern="^(pbkdf2|argon2id)$")


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_users_router() -> APIRouter:
    """Return the ``/api/v1/users`` router."""
    router = APIRouter(prefix="/api/v1/users", tags=["users"])

    @router.get("", response_model=UsersList)
    async def list_users(
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> UsersList:
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            rows = await repo.list_all()
            views = [
                UserView(
                    user_id=row.id,
                    username=repo.decrypt_username(row),
                    has_keystore=bool(row.wrapped_vault_key),
                )
                for row in rows
            ]
        return UsersList(users=views)

    @router.get("/{user_id}", response_model=UserView)
    async def show_user(
        user_id: str,
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> UserView:
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            rows = await repo.list_all()
            for row in rows:
                if row.id == user_id:
                    return UserView(
                        user_id=row.id,
                        username=repo.decrypt_username(row),
                        has_keystore=bool(row.wrapped_vault_key),
                    )
        raise HTTPException(status_code=404, detail="user not found")

    @router.post("", response_model=UserView, status_code=status.HTTP_201_CREATED)
    async def create_user(
        body: UserCreateRequest,
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> UserView:
        # Strength assertion happens inside keystore.create too, but
        # surface a friendly 400 if it fails before we spend KDF time.
        try:
            new_keystore = keystore.create(body.password.get_secret_value())
        except WeakPasswordError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        user_id = str(uuid.uuid4())
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            existing = await repo.get_by_username(body.username)
            if existing is not None:
                raise HTTPException(status_code=409, detail="username already taken")
            user = await repo.create(
                user_id=user_id,
                username=body.username,
                salt=new_keystore.salt,
                kdf_id=new_keystore.kdf_id,
                kdf_params=new_keystore.kdf_params,
                wrapped_vault_key=new_keystore.wrapped_vault_key,
                wrapped_rsa_private=new_keystore.wrapped_rsa_private,
                rsa_public_pem=new_keystore.rsa_public_pem,
            )
            await audit_append(
                db,
                bytes(session.admin_key),
                actor_user_id=user.id,
                action=AuditAction.USER_CREATE,
                target=body.username,
            )
        _log.info("sidecar.users.created", user_id=user.id)
        return UserView(
            user_id=user.id,
            username=body.username,
            has_keystore=True,
        )

    @router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_user(
        user_id: str,
        settings: Annotated[Settings, Depends(settings_dep)],
        session: Annotated[VaultSession, Depends(require_session)],
    ) -> None:
        async with open_db_session(settings) as db:
            repo = UserRepository(db, bytes(session.admin_key))
            rows = await repo.list_all()
            target = next((r for r in rows if r.id == user_id), None)
            if target is None:
                raise HTTPException(status_code=404, detail="user not found")
            username = repo.decrypt_username(target)
            await repo.delete(user_id)
            # Audit row uses actor_user_id=None because the row we
            # just deleted is no longer there to reference; the
            # ``target`` field carries the username for forensics.
            await audit_append(
                db,
                bytes(session.admin_key),
                actor_user_id=None,
                action=AuditAction.USER_DELETE,
                target=username,
            )
        _log.info("sidecar.users.deleted", user_id=user_id)

    return router

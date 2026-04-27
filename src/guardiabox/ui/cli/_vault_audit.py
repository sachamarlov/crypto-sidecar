"""Optional audit-log hook for vault-aware CLI commands.

The standalone ``encrypt`` / ``decrypt`` flows know nothing about
the multi-user database. When the user passes ``--vault-user <name>``
the CLI calls into this module after a successful operation so the
``.crypt`` file is recorded in ``vault_items`` and the action lands
in the audit log.

Design contract:

* Opt-in only. If ``vault_user`` is ``None`` the helpers are no-ops --
  legacy single-user flows keep working without any vault on disk.
* Failure-safe. The audit hook never fails the encryption itself: if
  the vault is missing or the admin password is wrong, we surface
  the error to the user but the ``.crypt`` file already on disk is
  left intact. The CLI exits non-zero so the user can re-run the
  audit step manually.
* Plaintext target. The audit row stores the ``.crypt`` filename
  (encrypted at the column level) and the full path is hashed in
  the HMAC index for equality lookups.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from guardiabox.core.exceptions import VaultUserNotFoundError
from guardiabox.persistence.repositories import (
    UserRepository,
    VaultItemRepository,
)
from guardiabox.security.audit import AuditAction, append
from guardiabox.ui.cli._session import open_vault_session

__all__ = [
    "VaultUserNotFoundError",
    "record_decrypt_event",
    "record_encrypt_event",
]


async def _record_file_event(
    *,
    data_dir: Path | None,
    password_stdin: bool,
    vault_username: str,
    action: AuditAction,
    target_path: Path,
    plaintext_size: int,
    container_path: Path | None,
    ciphertext_sha256: bytes | None,
    ciphertext_size: int | None,
    kdf_id: int | None,
) -> None:
    """Open a session and append the audit + (encrypt-only) VaultItem row.

    ``ciphertext_size`` is read by the caller (sync code) so this
    coroutine does not need to touch ``Path.stat`` -- ``ASYNC240``
    flags blocking filesystem calls inside async functions.
    """
    async with open_vault_session(data_dir, password_stdin=password_stdin) as (
        vault,
        session,
        _engine,
    ):
        user_repo = UserRepository(session, vault.admin_key)
        user = await user_repo.get_by_username(vault_username)
        if user is None:
            raise VaultUserNotFoundError(
                f"vault user '{vault_username}' is not registered. "
                "Run `guardiabox user create' first."
            )

        if (
            action is AuditAction.FILE_ENCRYPT
            and container_path is not None
            and ciphertext_sha256 is not None
            and ciphertext_size is not None
            and kdf_id is not None
        ):
            items = VaultItemRepository(session, vault.admin_key)
            from uuid import uuid4

            existing = await items.find_by_filename(
                owner_user_id=user.id, filename=container_path.name
            )
            if existing is None:
                await items.create(
                    item_id=uuid4().hex,
                    owner_user_id=user.id,
                    filename=container_path.name,
                    original_path=str(target_path),
                    container_path=str(container_path),
                    ciphertext_sha256=ciphertext_sha256,
                    ciphertext_size=ciphertext_size,
                    kdf_id=kdf_id,
                )

        await append(
            session,
            vault.admin_key,
            actor_user_id=user.id,
            action=action,
            target=str(target_path),
            metadata={"size": str(plaintext_size)},
        )


def record_encrypt_event(
    *,
    data_dir: Path | None,
    password_stdin: bool,
    vault_username: str,
    plaintext_path: Path,
    container_path: Path,
    ciphertext_sha256: bytes,
    kdf_id: int,
) -> None:
    """Synchronous wrapper for the encrypt-success audit + VaultItem write."""
    plaintext_size = plaintext_path.stat().st_size if plaintext_path.is_file() else 0
    ciphertext_size = container_path.stat().st_size if container_path.is_file() else 0
    asyncio.run(
        _record_file_event(
            data_dir=data_dir,
            password_stdin=password_stdin,
            vault_username=vault_username,
            action=AuditAction.FILE_ENCRYPT,
            target_path=plaintext_path,
            plaintext_size=plaintext_size,
            container_path=container_path,
            ciphertext_sha256=ciphertext_sha256,
            ciphertext_size=ciphertext_size,
            kdf_id=kdf_id,
        )
    )


def record_decrypt_event(
    *,
    data_dir: Path | None,
    password_stdin: bool,
    vault_username: str,
    container_path: Path,
    plaintext_path: Path | None,
) -> None:
    """Synchronous wrapper for the decrypt-success audit append."""
    plaintext_size = (
        plaintext_path.stat().st_size if plaintext_path and plaintext_path.is_file() else 0
    )
    asyncio.run(
        _record_file_event(
            data_dir=data_dir,
            password_stdin=password_stdin,
            vault_username=vault_username,
            action=AuditAction.FILE_DECRYPT,
            target_path=container_path,
            plaintext_size=plaintext_size,
            container_path=None,
            ciphertext_sha256=None,
            ciphertext_size=None,
            kdf_id=None,
        )
    )

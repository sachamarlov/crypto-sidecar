"""Append-only audit log with hash-chained integrity.

Every security-relevant action (encrypt, decrypt, share, delete, login,
failure, ...) appends an entry whose ``prev_hash`` field references the
previous entry's hash. Tampering with any entry invalidates the chain from
that point onward — verification is then a single linear scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AuditAction(StrEnum):
    """Types of actions tracked in the audit log."""

    USER_CREATE = "user.create"
    USER_UNLOCK = "user.unlock"
    USER_UNLOCK_FAILED = "user.unlock_failed"
    USER_LOCK = "user.lock"
    FILE_ENCRYPT = "file.encrypt"
    FILE_DECRYPT = "file.decrypt"
    FILE_DECRYPT_FAILED = "file.decrypt_failed"
    FILE_SHARE = "file.share"
    FILE_SHARE_ACCEPT = "file.share_accept"
    FILE_SECURE_DELETE = "file.secure_delete"
    KDF_MIGRATE = "kdf.migrate"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """An immutable, hash-chained record."""

    sequence: int
    timestamp: datetime
    actor_user_id: str
    action: AuditAction
    target: str | None
    metadata: dict[str, str]
    prev_hash: bytes
    entry_hash: bytes

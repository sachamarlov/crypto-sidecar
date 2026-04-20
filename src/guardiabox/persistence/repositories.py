"""Repository pattern — typed access to the persistence layer.

Each repository encapsulates the queries against a single aggregate. The UI /
service layers depend on the :class:`typing.Protocol` contracts here, never on
SQLAlchemy directly. This isolates the rest of the codebase from any future
storage swap (e.g. moving the audit log to an append-only KV store).
"""

from __future__ import annotations

from typing import Protocol

from guardiabox.persistence.models import User


class UserRepository(Protocol):
    """Persistence contract for :class:`User`."""

    async def get_by_username(self, username: str) -> User | None: ...
    async def list_all(self) -> list[User]: ...
    async def create(self, user: User) -> None: ...
    async def update(self, user: User) -> None: ...
    async def delete(self, user_id: str) -> None: ...

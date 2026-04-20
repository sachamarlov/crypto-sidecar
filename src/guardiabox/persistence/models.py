"""SQLAlchemy 2.0 declarative models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all GuardiaBox models."""


class User(Base):
    """A locally registered vault user."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    salt: Mapped[bytes] = mapped_column(LargeBinary(16))
    wrapped_vault_key: Mapped[bytes] = mapped_column(LargeBinary(48))
    wrapped_rsa_private: Mapped[bytes] = mapped_column(LargeBinary)
    rsa_public_pem: Mapped[bytes] = mapped_column(LargeBinary)
    kdf_id: Mapped[int] = mapped_column()
    kdf_params: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column()
    last_unlock_at: Mapped[datetime | None] = mapped_column(default=None)
    failed_unlock_count: Mapped[int] = mapped_column(default=0)

"""Centralised configuration.

Backed by :mod:`pydantic_settings`. All values can be overridden via environment
variables prefixed with ``GUARDIABOX_`` or via a ``.env`` file in the project
root (gitignored by default).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CryptoSettings(BaseSettings):
    """Cryptographic parameters (defaults match OWASP 2026 recommendations)."""

    # Audit A P1-8: align floors with core.constants.{ARGON2_MIN_MEMORY_KIB,
    # ARGON2_MIN_TIME_COST}. Previously memory_cost ge=19_456 (~19 MiB) and
    # time_cost ge=2 misled env-var consumers; the runtime KDF rejected
    # anything below 64 MiB / t=3.
    pbkdf2_iterations: int = Field(default=600_000, ge=600_000)
    argon2id_memory_cost_kib: int = Field(default=65_536, ge=65_536)  # 64 MiB
    argon2id_time_cost: int = Field(default=3, ge=3)
    argon2id_parallelism: int = Field(default=1, ge=1)
    rsa_key_bits: Literal[3072, 4096] = 4096
    aes_nonce_bytes: Literal[12] = 12
    salt_bytes: Literal[16, 32] = 16
    container_chunk_bytes: int = Field(default=64 * 1024, ge=4096)


class SidecarSettings(BaseSettings):
    """Tauri sidecar HTTP server configuration."""

    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: int = Field(default=0, ge=0, le=65_535)  # 0 = pick free port
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


class Settings(BaseSettings):
    """Top-level GuardiaBox settings loaded from env + .env."""

    model_config = SettingsConfigDict(
        env_prefix="GUARDIABOX_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="forbid",
        case_sensitive=False,
    )

    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".guardiabox",
        description="Directory holding the SQLCipher DB and per-user keystores.",
    )
    auto_lock_minutes: int = Field(default=15, ge=1, le=240)
    crypto: CryptoSettings = Field(default_factory=CryptoSettings)
    sidecar: SidecarSettings = Field(default_factory=SidecarSettings)


def get_settings() -> Settings:
    """Return a fresh :class:`Settings` instance.

    Wrap with :func:`functools.lru_cache` at the call site if a singleton is
    desired; we deliberately avoid a module-level cache here to keep tests
    parametrisable.
    """
    return Settings()

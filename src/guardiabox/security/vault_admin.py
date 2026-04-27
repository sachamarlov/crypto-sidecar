"""Vault administrator key derivation.

The vault admin key is the single 32-byte AES-256 key used at the
repository boundary to encrypt / HMAC every sensitive DB column
(``username_enc``, ``filename_enc``, ``audit_log.target_enc``, ...).
It is derived from a vault administrator password via a KDF whose
salt + parameters live in a small JSON file alongside the SQLite DB.

File layout (inside ``Settings.data_dir``, typically ``~/.guardiabox/``)::

    vault.admin.json  — public config (salt, kdf_id, kdf_params hex)
    vault.db          — SQLCipher / SQLite file

The JSON file is **not** a secret: the salt and KDF parameters are
public inputs to the derivation. A reader still needs the password
to recompute the key.

Why separate from :mod:`guardiabox.security.keystore`?

The per-user keystore wraps two secrets (vault key, RSA private) under
a master key. The vault admin is simpler: no wrapped material, just
``KDF(password, salt, params) -> 32-byte key``. Sharing the keystore
module would either bloat its surface or force us to wrap a dummy
blob. A dedicated module keeps the contract narrow and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import secrets
from typing import Any, Final

from guardiabox.core.constants import AES_KEY_BYTES, SALT_BYTES
from guardiabox.core.exceptions import GuardiaBoxError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.security.password import assert_strong

__all__ = [
    "ADMIN_CONFIG_FILENAME",
    "VaultAdminConfig",
    "VaultAdminConfigAlreadyExistsError",
    "VaultAdminConfigMissingError",
    "create_admin_config",
    "derive_admin_key",
    "read_admin_config",
    "write_admin_config",
]

#: Filename used inside the data dir. Plain JSON, no secret content.
ADMIN_CONFIG_FILENAME: Final[str] = "vault.admin.json"


class VaultAdminConfigMissingError(GuardiaBoxError):
    """The admin config file does not exist — run ``guardiabox init``."""


class VaultAdminConfigAlreadyExistsError(GuardiaBoxError):
    """Attempted to re-initialise an existing admin config."""


class VaultAdminConfigInvalidError(GuardiaBoxError, ValueError):
    """The admin config file exists but cannot be parsed / validated.

    Inherits :class:`ValueError` so existing ``pytest.raises(ValueError)``
    in tests still catches it; ``GuardiaBoxError`` lets the CLI
    ``exit_for`` mapping route it through the domain-error branch.
    """


@dataclass(frozen=True, slots=True)
class VaultAdminConfig:
    """Public parameters needed to re-derive the vault admin key.

    Field values are stable for the lifetime of the vault — rotating
    them is equivalent to re-keying every encrypted column and is
    tracked separately (post-MVP).
    """

    salt: bytes
    kdf_id: int
    kdf_params: bytes

    # -- Serialisation ------------------------------------------------------

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "salt": self.salt.hex(),
            "kdf_id": self.kdf_id,
            "kdf_params": self.kdf_params.hex(),
            "schema_version": 1,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, blob: str) -> VaultAdminConfig:
        raw = json.loads(blob)
        if not isinstance(raw, dict):
            raise VaultAdminConfigInvalidError(
                f"admin config must be a JSON object, got {type(raw).__name__}"
            )
        if raw.get("schema_version") != 1:
            raise VaultAdminConfigInvalidError(
                f"admin config schema_version {raw.get('schema_version')!r} not supported"
            )
        salt_hex = raw.get("salt")
        kdf_id = raw.get("kdf_id")
        kdf_params_hex = raw.get("kdf_params")
        if not isinstance(salt_hex, str) or not isinstance(kdf_params_hex, str):
            raise VaultAdminConfigInvalidError(
                "admin config fields 'salt' and 'kdf_params' must be hex strings"
            )
        if not isinstance(kdf_id, int):
            raise VaultAdminConfigInvalidError("admin config field 'kdf_id' must be an integer")
        salt = bytes.fromhex(salt_hex)
        if len(salt) != SALT_BYTES:
            raise VaultAdminConfigInvalidError(
                f"admin config salt must be {SALT_BYTES} bytes, got {len(salt)}"
            )
        return cls(salt=salt, kdf_id=kdf_id, kdf_params=bytes.fromhex(kdf_params_hex))


# ---------------------------------------------------------------------------
# Create / read / write
# ---------------------------------------------------------------------------


def create_admin_config(
    password: str,
    *,
    kdf: Pbkdf2Kdf | Argon2idKdf | None = None,
) -> VaultAdminConfig:
    """Validate ``password`` and return a fresh config with random salt.

    The returned object must be persisted with :func:`write_admin_config`
    before the caller discards it — there is no recovery from a lost
    salt + KDF params.
    """
    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else Pbkdf2Kdf()
    return VaultAdminConfig(
        salt=secrets.token_bytes(SALT_BYTES),
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
    )


def derive_admin_key(config: VaultAdminConfig, password: str) -> bytes:
    """Return the 32-byte AES-256 vault admin key.

    NFC-normalisation and UTF-8 encoding match the encrypt/decrypt
    password path so visually-identical codepoint sequences derive
    the same key.
    """
    import unicodedata

    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    kdf = kdf_for_id(config.kdf_id, config.kdf_params)
    return kdf.derive(password_bytes, config.salt, AES_KEY_BYTES)


def write_admin_config(path: Path, config: VaultAdminConfig) -> None:
    """Persist ``config`` at ``path``. Refuses to overwrite an existing file.

    On POSIX we chmod 0600 after the write so only the owning user can
    read it. On Windows, ACL semantics differ and the chmod is a
    no-op; the user's home directory ACL already gates access.
    """
    if path.exists():
        raise VaultAdminConfigAlreadyExistsError(
            f"admin config already exists at {path}; remove it to re-initialise"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config.to_json(), encoding="utf-8")
    _restrict_permissions(path)


def read_admin_config(path: Path) -> VaultAdminConfig:
    """Load and validate the admin config at ``path``."""
    if not path.is_file():
        raise VaultAdminConfigMissingError(
            f"admin config not found at {path}. Run `guardiabox init` to create one."
        )
    return VaultAdminConfig.from_json(path.read_text(encoding="utf-8"))


def _restrict_permissions(path: Path) -> None:
    """Chmod 0600 on POSIX; no-op on Windows."""
    import os

    if os.name == "posix":
        path.chmod(0o600)

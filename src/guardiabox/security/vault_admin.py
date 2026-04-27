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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardiabox.core.constants import AES_GCM_NONCE_BYTES, AES_KEY_BYTES, SALT_BYTES
from guardiabox.core.exceptions import DecryptionError, GuardiaBoxError
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf, kdf_for_id
from guardiabox.security.password import assert_strong

__all__ = [
    "ADMIN_CONFIG_FILENAME",
    "VERIFICATION_AAD",
    "VERIFICATION_PAYLOAD",
    "VaultAdminConfig",
    "VaultAdminConfigAlreadyExistsError",
    "VaultAdminConfigInvalidError",
    "VaultAdminConfigMissingError",
    "create_admin_config",
    "derive_admin_key",
    "read_admin_config",
    "verify_admin_password",
    "write_admin_config",
]

#: AAD context for the verification blob -- binds the ciphertext to
#: this specific use, so a swap with another AES-GCM blob fails.
VERIFICATION_AAD: Final[bytes] = b"guardiabox/vault_admin/verification/v1"

#: Plaintext sealed under the admin key when the vault is initialised.
#: A successful decrypt of the verification_blob proves the supplied
#: password derives the right admin key (defeats the silent
#: "wrong-password = different-key" footgun).
VERIFICATION_PAYLOAD: Final[bytes] = b"GUARDIABOX_VAULT_OK"

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

    ``verification_blob`` is an AES-GCM ciphertext (12-byte nonce ||
    ciphertext || 16-byte tag) of :data:`VERIFICATION_PAYLOAD` sealed
    under the admin key, with :data:`VERIFICATION_AAD` as associated
    data. A successful decrypt proves the supplied password derives
    the right key -- without it, a wrong password silently produces a
    *different* but still-32-byte key that only fails when used to
    decrypt a real database column. This eliminates that footgun and
    lets the unlock endpoint return a 401 immediately.
    """

    salt: bytes
    kdf_id: int
    kdf_params: bytes
    verification_blob: bytes

    # -- Serialisation ------------------------------------------------------

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "salt": self.salt.hex(),
            "kdf_id": self.kdf_id,
            "kdf_params": self.kdf_params.hex(),
            "verification_blob": self.verification_blob.hex(),
            "schema_version": 2,
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, blob: str) -> VaultAdminConfig:
        raw = json.loads(blob)
        if not isinstance(raw, dict):
            raise VaultAdminConfigInvalidError(
                f"admin config must be a JSON object, got {type(raw).__name__}"
            )
        if raw.get("schema_version") != 2:
            raise VaultAdminConfigInvalidError(
                f"admin config schema_version {raw.get('schema_version')!r} not supported "
                "(expected 2; pre-1.0 schema_version=1 vaults must be re-initialised)"
            )
        salt_hex = raw.get("salt")
        kdf_id = raw.get("kdf_id")
        kdf_params_hex = raw.get("kdf_params")
        verification_hex = raw.get("verification_blob")
        if (
            not isinstance(salt_hex, str)
            or not isinstance(kdf_params_hex, str)
            or not isinstance(verification_hex, str)
        ):
            raise VaultAdminConfigInvalidError(
                "admin config fields 'salt', 'kdf_params', 'verification_blob' must be hex strings"
            )
        if not isinstance(kdf_id, int):
            raise VaultAdminConfigInvalidError("admin config field 'kdf_id' must be an integer")
        salt = bytes.fromhex(salt_hex)
        if len(salt) != SALT_BYTES:
            raise VaultAdminConfigInvalidError(
                f"admin config salt must be {SALT_BYTES} bytes, got {len(salt)}"
            )
        return cls(
            salt=salt,
            kdf_id=kdf_id,
            kdf_params=bytes.fromhex(kdf_params_hex),
            verification_blob=bytes.fromhex(verification_hex),
        )


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

    Side-effect: derives the admin key in-process to seal the
    ``verification_blob``. The temporary key is zero-filled before
    return; the persisted blob carries no secret material in cleartext.
    """
    import unicodedata

    assert_strong(password)
    kdf_impl: Pbkdf2Kdf | Argon2idKdf = kdf if kdf is not None else Pbkdf2Kdf()
    salt = secrets.token_bytes(SALT_BYTES)

    # Derive the admin key once to seal the verification payload, then
    # zero-fill the buffer. The persisted blob is reproducible only by
    # the user who knows the password.
    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    transient = bytearray(kdf_impl.derive(password_bytes, salt, AES_KEY_BYTES))
    try:
        nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
        ciphertext = AESGCM(bytes(transient)).encrypt(nonce, VERIFICATION_PAYLOAD, VERIFICATION_AAD)
        verification_blob = nonce + ciphertext
    finally:
        for i in range(len(transient)):
            transient[i] = 0

    return VaultAdminConfig(
        salt=salt,
        kdf_id=kdf_impl.kdf_id,
        kdf_params=kdf_impl.encode_params(),
        verification_blob=verification_blob,
    )


def derive_admin_key(config: VaultAdminConfig, password: str) -> bytes:
    """Return the 32-byte AES-256 vault admin key.

    NFC-normalisation and UTF-8 encoding match the encrypt/decrypt
    password path so visually-identical codepoint sequences derive
    the same key.

    Note: this function does **not** validate the password. Use
    :func:`verify_admin_password` when the caller needs to reject a
    wrong password before opening a vault session.
    """
    import unicodedata

    password_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    kdf = kdf_for_id(config.kdf_id, config.kdf_params)
    return kdf.derive(password_bytes, config.salt, AES_KEY_BYTES)


def verify_admin_password(config: VaultAdminConfig, password: str) -> bytes:
    """Derive the admin key and prove ``password`` is correct.

    Decrypts ``config.verification_blob`` with the derived key. If the
    AES-GCM tag matches, the password is the right one and the key is
    returned to the caller. If the tag does not match, the function
    raises :class:`DecryptionError` so the caller can route the
    failure to a uniform 401 / "unlock failed" response (anti-oracle).

    Args:
        config: The :class:`VaultAdminConfig` loaded from disk.
        password: The candidate admin password.

    Returns:
        The 32-byte admin key (immutable bytes). Caller is expected
        to copy into a bytearray + zero-fill when done.

    Raises:
        DecryptionError: ``password`` does not match the one that
            sealed ``config.verification_blob``.
    """
    candidate_key = derive_admin_key(config, password)
    nonce = config.verification_blob[:AES_GCM_NONCE_BYTES]
    ciphertext = config.verification_blob[AES_GCM_NONCE_BYTES:]
    try:
        AESGCM(candidate_key).decrypt(nonce, ciphertext, VERIFICATION_AAD)
    except InvalidTag as exc:
        raise DecryptionError("admin password verification failed") from exc
    return candidate_key


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

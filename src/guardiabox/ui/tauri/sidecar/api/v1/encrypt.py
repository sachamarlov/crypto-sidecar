"""POST /api/v1/encrypt -- delegates to :func:`core.operations.encrypt_file`.

The router is auth-protected by :class:`TokenAuthMiddleware` (G-02).
For Phase G-04 it ships the *standalone* encrypt path (no vault user
attached, no audit row appended); the ``vault_user`` opt-in flow
lands with G-06 once the user / keystore router is wired.

Error mapping:

* :class:`WeakPasswordError` -> 400 weak-password.
* :class:`PathTraversalError` / :class:`SymlinkEscapeError` -> 400.
* :class:`FileNotFoundError` -> 404.
* :class:`DestinationCollidesWithSourceError` -> 409.
* :class:`DestinationAlreadyExistsError` -> 409.
* Unexpected exceptions bubble up to FastAPI's 500 handler.
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field, SecretStr

from guardiabox.config import Settings
from guardiabox.core.exceptions import (
    DestinationAlreadyExistsError,
    DestinationCollidesWithSourceError,
    PathTraversalError,
    SymlinkEscapeError,
    WeakPasswordError,
)
from guardiabox.core.kdf import Argon2idKdf, Pbkdf2Kdf
from guardiabox.core.operations import encrypt_file
from guardiabox.logging import get_logger
from guardiabox.ui.tauri.sidecar.api.rate_limit import BUCKET_WRITE, limiter
from guardiabox.ui.tauri.sidecar.api.schemas import SidecarBaseModel

__all__ = ["build_encrypt_router"]

_log = get_logger("guardiabox.sidecar.encrypt")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EncryptRequest(SidecarBaseModel):
    """Body of ``POST /api/v1/encrypt``."""

    path: str = Field(description="Absolute filesystem path of the source file.")
    password: SecretStr
    kdf: Literal["pbkdf2", "argon2id"] = "pbkdf2"
    dest: str | None = Field(
        default=None,
        description="Optional output path; defaults to <source>.crypt alongside the source.",
    )
    force: bool = False


class EncryptResponse(SidecarBaseModel):
    """Body of a successful ``POST /api/v1/encrypt``."""

    output_path: str
    plaintext_size: int
    ciphertext_size: int
    kdf_id: int
    elapsed_ms: int


# ---------------------------------------------------------------------------
# Dependency injection
# ---------------------------------------------------------------------------


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_encrypt_router() -> APIRouter:
    """Return the ``/api/v1/encrypt`` router."""
    router = APIRouter(prefix="/api/v1", tags=["encrypt"])

    @router.post(
        "/encrypt",
        response_model=EncryptResponse,
        status_code=status.HTTP_200_OK,
    )
    @limiter.limit(BUCKET_WRITE)
    def encrypt(
        request: Request,
        body: EncryptRequest,
        settings: Annotated[Settings, Depends(_settings)],
    ) -> EncryptResponse:
        del request  # consumed by slowapi via signature inspection
        # Audit C P1-2: previously root=source.parent which made
        # resolve_within(source, source.parent) trivially-passing --
        # the router accepted any absolute path including system
        # files. Now constrain to a sane allow-list: vault data_dir
        # plus the user's home dir (Documents / Downloads / Desktop
        # are the only realistic encrypt targets a desktop user
        # picks via the Tauri dialog).
        source = Path(body.path)
        dest_path = Path(body.dest) if body.dest is not None else None
        kdf_impl: Pbkdf2Kdf | Argon2idKdf = Argon2idKdf() if body.kdf == "argon2id" else Pbkdf2Kdf()
        allowed_root = _resolve_allowed_root(source, settings)
        if allowed_root is None:
            raise HTTPException(
                status_code=400,
                detail="path validation failed",
            )

        if not source.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"source file not found: {source}",
            )

        start = time.monotonic()
        try:
            output = encrypt_file(
                source,
                body.password.get_secret_value(),
                root=allowed_root,
                kdf=kdf_impl,
                dest=dest_path,
                force=body.force,
            )
        except WeakPasswordError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (PathTraversalError, SymlinkEscapeError) as exc:
            raise HTTPException(status_code=400, detail="path validation failed") from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DestinationCollidesWithSourceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except DestinationAlreadyExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        elapsed_ms = int((time.monotonic() - start) * 1000)
        plaintext_size = source.stat().st_size
        ciphertext_size = output.stat().st_size
        _log.info(
            "sidecar.encrypt.ok",
            kdf=body.kdf,
            plaintext_size=plaintext_size,
            ciphertext_size=ciphertext_size,
            elapsed_ms=elapsed_ms,
        )
        return EncryptResponse(
            output_path=str(output),
            plaintext_size=plaintext_size,
            ciphertext_size=ciphertext_size,
            kdf_id=kdf_impl.kdf_id,
            elapsed_ms=elapsed_ms,
        )

    return router


def _resolve_allowed_root(source: Path, settings: Settings) -> Path | None:
    """Return the broadest allowed ancestor of ``source`` or None.

    Audit C P1-2 mitigation: the router caller is the Tauri WebView
    in the trust model, so an XSS in the renderer must not be able
    to encrypt arbitrary system files (Windows registry hives,
    /etc/shadow, browser cookie stores, etc.). Acceptable roots:

    * ``settings.data_dir`` -- the vault itself.
    * ``Path.home()`` -- user's home directory (covers Documents,
      Downloads, Desktop, OneDrive shells, etc.).

    Both roots are fully resolved so symlinks cannot point outside.
    The function returns the first root the source resolves under;
    None when neither matches, so the caller can return 400.
    """
    try:
        resolved_source = source.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    candidates = [settings.data_dir.resolve(), Path.home().resolve()]
    for root in candidates:
        try:
            resolved_source.relative_to(root)
        except ValueError:
            continue
        else:
            return root
    return None

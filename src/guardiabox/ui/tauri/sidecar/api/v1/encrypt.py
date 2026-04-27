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
    def encrypt(
        body: EncryptRequest,
        _settings_dep: Annotated[Settings, Depends(_settings)],
    ) -> EncryptResponse:
        # Resolve and validate paths. Mirror the TUI policy of using the
        # source's parent as the resolve_within root; the safe_path
        # guard still rejects symlink escapes and reparse points.
        source = Path(body.path)
        dest_path = Path(body.dest) if body.dest is not None else None
        kdf_impl: Pbkdf2Kdf | Argon2idKdf = Argon2idKdf() if body.kdf == "argon2id" else Pbkdf2Kdf()

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
                root=source.parent,
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

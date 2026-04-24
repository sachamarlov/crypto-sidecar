"""OS-specific filesystem probes.

Currently exposes :func:`is_ssd`, which the secure-delete CLI uses to
decide whether a DoD-style overwrite is likely to be effective (HDD) or
not (SSD, where wear-levelling defeats overwrite per NIST SP 800-88r2).

The function returns ``None`` on any failure to probe — callers MUST
treat ``None`` as "unknown" and make a conservative choice (for
secure-delete, NIST recommends assuming SSD and reaching for
crypto-erase when the media type is unclear).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import plistlib
import re
import shutil
import subprocess  # nosec B404  # noqa: S404 — called only with shutil.which-resolved paths
import sys

__all__ = ["is_ssd"]


def is_ssd(path: Path) -> bool | None:
    """Return ``True`` if ``path``'s backing storage is solid-state.

    Returns ``False`` for rotational (HDD/tape) media and ``None`` when
    the probe cannot decide — including when the platform is unknown,
    the OS call fails, or the path is on a remote / virtual filesystem.
    """
    resolved = path.resolve(strict=False)
    # Assigning ``sys.platform`` to a local variable prevents mypy from
    # narrowing to the single literal of the build host — every branch
    # below is then reachable in the type checker's view, which is what
    # we want for multi-OS code.
    platform = sys.platform
    if platform == "win32":
        return _is_ssd_windows(resolved)
    if platform == "linux":
        return _is_ssd_linux(resolved)
    if platform == "darwin":
        return _is_ssd_macos(resolved)
    return None


# ---------------------------------------------------------------------------
# Windows — IOCTL_STORAGE_QUERY_PROPERTY + StorageDeviceSeekPenaltyProperty
# <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-device_seek_penalty_descriptor>
# ---------------------------------------------------------------------------

_IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
_STORAGE_DEVICE_SEEK_PENALTY_PROPERTY = 7
_PROPERTY_STANDARD_QUERY = 0

_GENERIC_READ = 0x80000000  # unused but documents intent
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _StoragePropertyQuery(ctypes.Structure):
    _fields_ = (
        ("PropertyId", wintypes.DWORD),
        ("QueryType", wintypes.DWORD),
        ("AdditionalParameters", ctypes.c_ubyte * 1),
    )


class _DeviceSeekPenaltyDescriptor(ctypes.Structure):
    _fields_ = (
        ("Version", wintypes.DWORD),
        ("Size", wintypes.DWORD),
        ("IncursSeekPenalty", wintypes.BOOLEAN),
    )


def _is_ssd_windows(path: Path) -> bool | None:  # pragma: no cover — Windows-only
    drive = path.drive
    if not drive:
        return None
    device = rf"\\.\{drive}"
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(
        device,
        0,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        0,
        None,
    )
    if handle in {0, _INVALID_HANDLE_VALUE, None}:
        return None
    try:
        query = _StoragePropertyQuery(
            PropertyId=_STORAGE_DEVICE_SEEK_PENALTY_PROPERTY,
            QueryType=_PROPERTY_STANDARD_QUERY,
        )
        desc = _DeviceSeekPenaltyDescriptor()
        returned = wintypes.DWORD()
        kernel32.DeviceIoControl.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        ok = kernel32.DeviceIoControl(
            handle,
            _IOCTL_STORAGE_QUERY_PROPERTY,
            ctypes.byref(query),
            ctypes.sizeof(query),
            ctypes.byref(desc),
            ctypes.sizeof(desc),
            ctypes.byref(returned),
            None,
        )
        if not ok:
            return None
        return not bool(desc.IncursSeekPenalty)
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# Linux — /sys/block/<dev>/queue/rotational
# ---------------------------------------------------------------------------


def _is_ssd_linux(path: Path) -> bool | None:  # pragma: no cover — Linux-only
    # Find the mount point backing `path`, then follow to the block device.
    try:
        import os

        stat = path.stat()
        # ``os.major`` / ``os.minor`` are POSIX-only; ``getattr`` avoids a
        # static attribute lookup that mypy on Windows would flag while
        # still being a trivial call on every POSIX host.
        major = getattr(os, "major")(stat.st_dev)  # noqa: B009 — runtime POSIX lookup
        minor = getattr(os, "minor")(stat.st_dev)  # noqa: B009 — runtime POSIX lookup
    except OSError:
        return None
    sys_path = Path(f"/sys/dev/block/{major}:{minor}")
    if not sys_path.exists():
        return None
    # Walk up until we find a queue/rotational file (handles partitions).
    current = sys_path.resolve()
    for _ in range(6):  # avoid unbounded walks on weird layouts
        rotational = current / "queue" / "rotational"
        if rotational.is_file():
            return rotational.read_text().strip() == "0"
        if current.parent == current:
            return None
        current = current.parent
    return None


# ---------------------------------------------------------------------------
# macOS — diskutil info -plist <path>
# ---------------------------------------------------------------------------


def _is_ssd_macos(path: Path) -> bool | None:  # pragma: no cover — macOS-only  # noqa: PLR0911
    diskutil = shutil.which("diskutil")
    if diskutil is None:
        return None
    try:
        proc = subprocess.run(  # nosec B603  # noqa: S603 — diskutil path resolved via shutil.which
            [diskutil, "info", "-plist", str(path)],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        info = plistlib.loads(proc.stdout)
    except plistlib.InvalidFileException:
        return None
    solid = info.get("SolidState")
    if isinstance(solid, bool):
        return solid
    # Fall back to the more roundabout "MediaType" string if SolidState is missing.
    media_type = info.get("MediaType")
    if isinstance(media_type, str) and re.search(r"ssd|flash", media_type, re.IGNORECASE):
        return True
    return None

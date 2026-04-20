"""Generate placeholder icons for the Tauri build using only the standard library.

Tauri's bundler requires ``icons/{32x32.png, 128x128.png, 128x128@2x.png,
icon.ico, icon.icns}`` to exist. Until a real icon set is provided, this
script writes valid but neutral solid-colour placeholders so that
``cargo tauri build`` does not fail at packaging time.

Usage::

    uv run python scripts/generate_placeholder_icons.py

Outputs::

    src/guardiabox/ui/tauri/src-tauri/icons/
        32x32.png
        128x128.png
        128x128@2x.png       (256x256)
        icon.ico             (multi-resolution: 16, 32, 48, 64, 128, 256)
        icon.icns            (single resolution, sufficient for dev builds)
        Square30x30Logo.png  (Windows Store)
        Square44x44Logo.png  (Windows Store)
        Square71x71Logo.png  (Windows Store)
        Square89x89Logo.png  (Windows Store)
        Square107x107Logo.png
        Square142x142Logo.png
        Square150x150Logo.png
        Square284x284Logo.png
        Square310x310Logo.png
        StoreLogo.png

The placeholder colour matches the dark UI accent (``oklch(0.7 0.18 260)``
≈ RGB ``#7c8cf0``).
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ICONS_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "guardiabox"
    / "ui"
    / "tauri"
    / "src-tauri"
    / "icons"
)

ACCENT_RGBA = (124, 140, 240, 255)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    """Frame ``data`` as a single PNG chunk under ``tag`` (length + CRC)."""
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def make_png(width: int, height: int, rgba: tuple[int, int, int, int] = ACCENT_RGBA) -> bytes:
    """Return raw bytes of a PNG of the given dimensions filled with one colour."""
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    raw = b""
    pixel = bytes(rgba)
    for _ in range(height):
        raw += b"\x00" + pixel * width  # filter byte 0 (None) + scanline
    idat = zlib.compress(raw, level=9)
    return (
        signature
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def make_ico(sizes: tuple[int, ...] = (16, 32, 48, 64, 128, 256)) -> bytes:
    """Return raw bytes of a multi-resolution ICO containing PNG entries."""
    images = [make_png(s, s) for s in sizes]
    n = len(images)
    header = struct.pack("<HHH", 0, 1, n)  # reserved=0, type=ICO, count=n
    directory = b""
    offset = 6 + n * 16
    for size, image in zip(sizes, images, strict=True):
        w = 0 if size == 256 else size
        h = 0 if size == 256 else size
        directory += struct.pack(
            "<BBBBHHII",
            w, h, 0, 0,  # width, height, palette, reserved
            1, 32,        # planes, bits per pixel
            len(image), offset,
        )
        offset += len(image)
    return header + directory + b"".join(images)


def make_icns(size: int = 512) -> bytes:
    """Return a minimal Apple ICNS file wrapping a single PNG icon."""
    png = make_png(size, size)
    icns_type = b"ic09"  # 512x512
    icon_chunk = icns_type + struct.pack(">I", 8 + len(png)) + png
    return b"icns" + struct.pack(">I", 8 + len(icon_chunk)) + icon_chunk


def main() -> int:
    """Write all required Tauri icon placeholders to the icons directory."""
    ICONS_DIR.mkdir(parents=True, exist_ok=True)

    sizes_png: dict[str, int] = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "Square30x30Logo.png": 30,
        "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71,
        "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107,
        "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150,
        "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310,
        "StoreLogo.png": 50,
    }

    written: list[str] = []
    for filename, size in sizes_png.items():
        path = ICONS_DIR / filename
        path.write_bytes(make_png(size, size))
        written.append(filename)

    (ICONS_DIR / "icon.ico").write_bytes(make_ico())
    written.append("icon.ico")

    (ICONS_DIR / "icon.icns").write_bytes(make_icns())
    written.append("icon.icns")

    sys.stdout.write(f"Generated placeholder icons in {ICONS_DIR}:\n")
    for name in written:
        sys.stdout.write(f"  - {name}\n")
    sys.stdout.write(
        "\nReplace with real artwork via `pnpm tauri icon path/to/source.png` "
        "when available.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

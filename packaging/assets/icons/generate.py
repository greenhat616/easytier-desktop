#!/usr/bin/env python3
"""Reproducibly rasterize and package the EasyTier Desktop Triad icon set.

Uses pinned resvg (0.46.0) for deterministic CPU SVG rasterization and Python 3's
standard library only for ICO / ICNS / hicolor assembly.

Usage:
    cargo install --locked resvg --version 0.46.0
    python packaging/assets/icons/generate.py
    python packaging/assets/icons/generate.py --check
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

PINNED_RESVG_VERSION = "0.46.0"

# Sizes 16, 24 and 32 MUST render from the pixel-tuned small SVGs rather than
# downscaling app.svg.
APP_PNG_SPECS: list[tuple[int, str]] = [
    (16, "app-16.svg"),
    (20, "app.svg"),
    (24, "app-24.svg"),
    (32, "app-32.svg"),
    (40, "app.svg"),
    (48, "app.svg"),
    (64, "app.svg"),
    (128, "app.svg"),
    (256, "app.svg"),
]

ICO_SIZES: list[int] = [16, 20, 24, 32, 40, 48, 64, 128, 256]
HICOLOR_SIZES: list[int] = [16, 24, 32, 48, 64, 128, 256]

# Standard Apple ICNS PNG chunk types (macOS 10.7+ including Retina @2x slots).
ICNS_SPECS: list[tuple[bytes, int]] = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic09", 512),
    (b"ic10", 1024),
    (b"ic11", 32),   # 16x16@2x
    (b"ic12", 64),   # 32x32@2x
    (b"ic13", 256),  # 128x128@2x
    (b"ic14", 512),  # 256x256@2x
]

TRAY_THEMES: tuple[str, ...] = ("light", "dark")
TRAY_SIZES: tuple[int, ...] = (16, 24)
TRAY_STATES: tuple[str, ...] = ("connected", "connecting", "disconnected")


def find_resvg(explicit: str | None) -> str:
    candidate = explicit or os.environ.get("RESVG") or "resvg"
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    if Path(candidate).is_file():
        return candidate
    raise SystemExit(
        f"resvg not found (tried {candidate!r}). Install the pinned version with:\n"
        f"  cargo install --locked resvg --version {PINNED_RESVG_VERSION}"
    )


def verify_resvg_version(resvg_bin: str, allow_any: bool) -> None:
    proc = subprocess.run(
        [resvg_bin, "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    version = proc.stdout.strip().split()[-1]
    if not allow_any and version != PINNED_RESVG_VERSION:
        raise SystemExit(
            f"Expected resvg {PINNED_RESVG_VERSION}, found {version!r} at {resvg_bin}.\n"
            f"Install the pinned version with:\n"
            f"  cargo install --locked resvg --version {PINNED_RESVG_VERSION}\n"
            f"(or pass --allow-any-resvg to override)."
        )


def render_svg(resvg_bin: str, src: Path, dst: Path, size: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            resvg_bin,
            "--width",
            str(size),
            "--height",
            str(size),
            str(src),
            str(dst),
        ],
        check=True,
    )


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def decode_png_rgba(png_bytes: bytes) -> tuple[int, int, bytes]:
    """Minimal stdlib decoder for 8-bit non-interlaced RGBA/RGB/GA/G PNGs."""
    if png_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("invalid PNG signature")
    pos = 8
    width = height = bit_depth = color_type = interlace = None
    idat_parts: list[bytes] = []
    while pos < len(png_bytes):
        length = struct.unpack(">I", png_bytes[pos : pos + 4])[0]
        ctype = png_bytes[pos + 4 : pos + 8]
        data = png_bytes[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if ctype == b"IHDR":
            width, height, bit_depth, color_type, comp, flt, interlace = struct.unpack(
                ">IIBBBBB", data
            )
            if comp != 0 or flt != 0 or interlace != 0:
                raise ValueError(f"unsupported PNG flags: comp={comp} flt={flt} interlace={interlace}")
            if bit_depth != 8:
                raise ValueError(f"unsupported PNG bit depth: {bit_depth}")
        elif ctype == b"IDAT":
            idat_parts.append(data)
        elif ctype == b"IEND":
            break

    if width is None or height is None or color_type is None:
        raise ValueError("missing IHDR chunk")

    bpp_map = {0: 1, 2: 3, 4: 2, 6: 4}
    if color_type not in bpp_map:
        raise ValueError(f"unsupported PNG color type: {color_type}")
    bpp = bpp_map[color_type]

    raw = zlib.decompress(b"".join(idat_parts))
    stride = width * bpp
    expected = height * (1 + stride)
    if len(raw) != expected:
        raise ValueError(f"unexpected decompressed PNG size: {len(raw)} != {expected}")

    prev = bytearray(stride)
    out = bytearray(width * height * 4)
    in_off = 0
    out_off = 0

    for _ in range(height):
        flt = raw[in_off]
        in_off += 1
        row = bytearray(raw[in_off : in_off + stride])
        in_off += stride

        if flt == 0:
            pass
        elif flt == 1:
            for i in range(bpp, stride):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif flt == 2:
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif flt == 3:
            for i in range(stride):
                left = row[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif flt == 4:
            for i in range(stride):
                left = row[i - bpp] if i >= bpp else 0
                up = prev[i]
                up_left = prev[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + _paeth(left, up, up_left)) & 0xFF
        else:
            raise ValueError(f"unsupported PNG filter type: {flt}")

        if color_type == 6:
            out[out_off : out_off + stride] = row
            out_off += stride
        elif color_type == 2:
            for x in range(width):
                r, g, b = row[x * 3 : x * 3 + 3]
                out[out_off : out_off + 4] = bytes((r, g, b, 255))
                out_off += 4
        elif color_type == 4:
            for x in range(width):
                v, a = row[x * 2 : x * 2 + 2]
                out[out_off : out_off + 4] = bytes((v, v, v, a))
                out_off += 4
        elif color_type == 0:
            for x in range(width):
                v = row[x]
                out[out_off : out_off + 4] = bytes((v, v, v, 255))
                out_off += 4

        prev = row

    return width, height, bytes(out)


def encode_ico_dib(png_bytes: bytes) -> bytes:
    """Encode an RGBA PNG into a 32-bit BGRA Windows ICO DIB + 1-bit AND mask."""
    width, height, rgba = decode_png_rgba(png_bytes)
    xor_stride = width * 4
    and_stride = ((width + 31) // 32) * 4

    xor_buf = bytearray(xor_stride * height)
    and_buf = bytearray(and_stride * height)

    # ICO DIB scanlines are stored bottom-up.
    for y in range(height):
        src_y = height - 1 - y
        src_row = src_y * xor_stride
        dst_row = y * xor_stride
        and_row = y * and_stride
        for x in range(width):
            r = rgba[src_row + x * 4]
            g = rgba[src_row + x * 4 + 1]
            b = rgba[src_row + x * 4 + 2]
            a = rgba[src_row + x * 4 + 3]
            xor_buf[dst_row + x * 4] = b
            xor_buf[dst_row + x * 4 + 1] = g
            xor_buf[dst_row + x * 4 + 2] = r
            xor_buf[dst_row + x * 4 + 3] = a
            if a == 0:
                and_buf[and_row + (x >> 3)] |= 0x80 >> (x & 7)

    header = struct.pack(
        "<IiiHHIIiiII",
        40,              # biSize
        width,           # biWidth
        height * 2,      # biHeight (XOR + AND)
        1,               # biPlanes
        32,              # biBitCount
        0,               # biCompression (BI_RGB)
        len(xor_buf) + len(and_buf),  # biSizeImage
        0,               # biXPelsPerMeter
        0,               # biYPelsPerMeter
        0,               # biClrUsed
        0,               # biClrImportant
    )
    return header + bytes(xor_buf) + bytes(and_buf)


def build_ico(png_by_size: dict[int, bytes]) -> bytes:
    """Build a multi-size Windows .ico (32bpp DIB for <256px, PNG for 256px)."""
    entries: list[tuple[int, bytes]] = []
    for size in ICO_SIZES:
        png = png_by_size[size]
        payload = png if size >= 256 else encode_ico_dib(png)
        entries.append((size, payload))

    header = struct.pack("<HHH", 0, 1, len(entries))
    directory = bytearray()
    offset = 6 + 16 * len(entries)
    for size, payload in entries:
        dim = 0 if size >= 256 else size
        directory += struct.pack(
            "<BBBBHHII",
            dim,          # bWidth
            dim,          # bHeight
            0,            # bColorCount
            0,            # bReserved
            1,            # wPlanes
            32,           # wBitCount
            len(payload), # dwBytesInRes
            offset,       # dwImageOffset
        )
        offset += len(payload)

    return header + bytes(directory) + b"".join(payload for _, payload in entries)


def build_icns(png_by_size: dict[int, bytes]) -> bytes:
    """Build an Apple .icns container from macOS squircle PNG frames."""
    chunks = bytearray()
    for ostype, size in ICNS_SPECS:
        payload = png_by_size[size]
        chunks += ostype + struct.pack(">I", 8 + len(payload)) + payload
    total = 8 + len(chunks)
    return b"icns" + struct.pack(">I", total) + bytes(chunks)


def generate_into(src_dir: Path, out_dir: Path, resvg_bin: str) -> list[Path]:
    written: list[Path] = []

    def write_bytes(rel: str, data: bytes) -> None:
        target = out_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written.append(Path(rel))

    # 1. App PNGs (16/24/32 from pixel-tuned SVGs, rest from app.svg).
    app_pngs: dict[int, bytes] = {}
    for size, svg_name in APP_PNG_SPECS:
        rel = f"png/app-{size}.png"
        dst = out_dir / rel
        render_svg(resvg_bin, src_dir / svg_name, dst, size)
        app_pngs[size] = dst.read_bytes()
        written.append(Path(rel))

    # 2. Tray PNGs (1:1 from pixel-aligned tray SVGs).
    for theme in TRAY_THEMES:
        for size in TRAY_SIZES:
            for state in TRAY_STATES:
                stem = f"tray/{theme}-{size}-{state}"
                dst = out_dir / f"{stem}.png"
                render_svg(resvg_bin, src_dir / f"{stem}.svg", dst, size)
                written.append(Path(f"{stem}.png"))

    # 3. Windows multi-size app.ico.
    write_bytes("app.ico", build_ico(app_pngs))

    # 4. Linux hicolor theme PNGs + scalable SVG.
    for size in HICOLOR_SIZES:
        write_bytes(
            f"hicolor/{size}x{size}/apps/easytier-desktop.png",
            app_pngs[size],
        )
    write_bytes(
        "hicolor/scalable/apps/easytier-desktop.svg",
        (src_dir / "app.svg").read_bytes(),
    )

    # 5. macOS app.icns from app-macos.svg.
    with tempfile.TemporaryDirectory(prefix="etd-icns-") as tmp:
        tmp_path = Path(tmp)
        macos_pngs: dict[int, bytes] = {}
        for size in sorted({s for _, s in ICNS_SPECS}):
            png_path = tmp_path / f"macos-{size}.png"
            render_svg(resvg_bin, src_dir / "app-macos.svg", png_path, size)
            macos_pngs[size] = png_path.read_bytes()
        write_bytes("app.icns", build_icns(macos_pngs))

    return sorted(written)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--resvg",
        help=f"Path to resvg binary (defaults to $RESVG or 'resvg' on PATH; pinned to {PINNED_RESVG_VERSION}).",
    )
    parser.add_argument(
        "--allow-any-resvg",
        action="store_true",
        help="Skip the exact resvg version check.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that all committed generated files match fresh output byte-for-byte.",
    )
    args = parser.parse_args()

    icons_dir = Path(__file__).resolve().parent
    resvg_bin = find_resvg(args.resvg)
    verify_resvg_version(resvg_bin, args.allow_any_resvg)

    if args.check:
        with tempfile.TemporaryDirectory(prefix="etd-icons-check-") as tmp:
            tmp_dir = Path(tmp)
            generated = generate_into(icons_dir, tmp_dir, resvg_bin)
            mismatches: list[str] = []
            for rel in generated:
                actual_path = icons_dir / rel
                expected = (tmp_dir / rel).read_bytes()
                if not actual_path.is_file():
                    mismatches.append(f"missing: {rel.as_posix()}")
                elif actual_path.read_bytes() != expected:
                    mismatches.append(f"differs: {rel.as_posix()}")
            if mismatches:
                print("Generated icon assets are out of date:", file=sys.stderr)
                for m in mismatches:
                    print(f"  {m}", file=sys.stderr)
                return 1
            print(f"All {len(generated)} generated icon files match resvg {PINNED_RESVG_VERSION}.")
            return 0

    generated = generate_into(icons_dir, icons_dir, resvg_bin)
    print(f"Generated {len(generated)} icon files using resvg {PINNED_RESVG_VERSION}:")
    for rel in generated:
        print(f"  {rel.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

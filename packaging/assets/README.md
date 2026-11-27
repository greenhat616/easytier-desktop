# Application and Tray Icon Assets

This directory holds the final **Triad** icon set for EasyTier Desktop (SVG sources plus committed raster and container outputs).

## Directory layout (`packaging/assets/icons/`)

| Path | Description |
| --- | --- |
| `make.py` | Original parametric generator that produced the Triad SVG sources (kept for provenance). |
| `generate.py` | Reproducible rasterization and packaging script (Python 3 stdlib + pinned `resvg 0.46.0`). |
| `app.svg` | Full-colour Windows/Linux Triad app icon SVG (`256x256` viewBox). |
| `app-macos.svg` | Full-colour macOS squircle-tile Triad app icon SVG (`256x256` viewBox). |
| `app-16.svg`, `app-24.svg`, `app-32.svg` | Pixel-tuned small-size app icon SVGs designed for 16, 24, and 32 px (not downscaled from `app.svg`). |
| `png/app-{16,20,24,32,40,48,64,128,256}.png` | Pre-rendered app icon PNGs. Sizes `16`, `24`, and `32` are rendered directly from `app-16.svg`, `app-24.svg`, and `app-32.svg`; all other sizes come from `app.svg`. |
| `app.ico` | Multi-size Windows icon containing `16, 20, 24, 32, 40, 48, 64, 128, 256` px (`32 bpp` BGRA DIB for `< 256`, PNG for `256`). |
| `tray/{light,dark}-{16,24}-{connected,connecting,disconnected}.svg` | Pixel-aligned monochrome tray glyph SVGs (`#1B1B1B` ink for light taskbars, `#FFFFFF` ink for dark taskbars). |
| `tray/{light,dark}-{16,24}-{connected,connecting,disconnected}.png` | Pre-rendered `16x16` and `24x24` RGBA PNGs embedded into `etd-ui`. |
| `hicolor/{16x16,24x24,32x32,48x48,64x64,128x128,256x256}/apps/easytier-desktop.png` | Linux freedesktop hicolor theme PNG icons. |
| `hicolor/scalable/apps/easytier-desktop.svg` | Linux freedesktop hicolor scalable SVG (`app.svg`). |
| `app.icns` | Apple ICNS bundle generated from `app-macos.svg` (`icp4`/`icp5`/`icp6`/`ic07`/`ic08`/`ic09`/`ic10`/`ic11`/`ic12`/`ic13`/`ic14`, 16–1024 px including `@2x` slots) for future macOS packaging. |

## Where each size and file is used

| Consumer | Asset / Size | Notes |
| --- | --- | --- |
| Windows `etd-ui.exe` resource (`crates/etd-ui/app.rc`, `build.rs`) | `app.ico` (ordinal `1`) | Embedded via `embed-resource`. Drives Windows Explorer, Start Menu shortcuts, taskbar, and Alt+Tab. |
| Windows MSI installer (`ARPPRODUCTICON`) | `packaging/assets/icons/app.ico` | Start Menu shortcut inherits `etd-ui.exe`'s icon automatically; `app.ico` provides the Add/Remove Programs product icon. |
| GPUI window icon — Windows | `app.ico` (ordinal `1`) | GPUI loads resource `1` into `WNDCLASSW.hIcon`; `theme::bind_window` also sends `WM_SETICON` for `ICON_SMALL` (`SM_CXSMICON`: 16/24 px) and `ICON_BIG` (`SM_CXICON`: 32/48 px) so titlebars use the pixel-tuned small frames. |
| GPUI window icon — Linux | `png/app-64.png` + `app_id = "easytier-desktop"` | `app-64.png` is set as X11 `_NET_WM_ICON` in `WindowOptions.icon`; `app_id` matches the installed `hicolor/*/apps/easytier-desktop.{png,svg}` desktop entry on Wayland and X11. |
| GPUI window icon — macOS | `app.icns` | Used by the `.app` bundle's `CFBundleIconFile` once macOS packaging is enabled. |
| System tray — Connected (`TrayIndicator::Connected`) | `tray/<theme>-<16\|24>-connected.png` | Three filled nodes linked by solid triangle struts. |
| System tray — Connecting / Attention (`TrayIndicator::Attention`) | `tray/<theme>-<16\|24>-connecting.png` | Three filled nodes with short broken struts. |
| System tray — Disconnected / Idle / Error (`TrayIndicator::Idle`, `Error`) | `tray/<theme>-<16\|24>-disconnected.png` | Three hollow rings. |
| Tray theme & DPI selection | `light` vs `dark`, `16` vs `24` | Windows reads HKCU `SystemUsesLightTheme` (independent of app theme) and `SM_CXSMICON` (`>= 20` px → `24`, else `16`), refreshing live via `AppearanceWatch`. Linux follows window appearance and scale factor (`>= 1.25x` → `24`). macOS passes the monochrome dark glyph with `set_icon_templated` so AppKit adapts automatically to light/dark menu bars. |

## Reproducible regeneration

All generated binaries are committed so normal `cargo build` and packaging never require `resvg` at build time. To regenerate every derived PNG, `.ico`, `hicolor/`, and `.icns` deterministically using the pinned `resvg 0.46.0` renderer:

```sh
cargo install --locked resvg --version 0.46.0
python packaging/assets/icons/generate.py
```

To verify that all committed outputs match fresh regeneration byte-for-byte without modifying the working tree:

```sh
python packaging/assets/icons/generate.py --check
```

`generate.py` checks `resvg --version` against `0.46.0` (override with `RESVG=/path/to/resvg` or `--resvg <path>`). Do not regenerate the SVG sources unless intentionally changing the design; `make.py` is kept only as provenance for the committed SVGs.

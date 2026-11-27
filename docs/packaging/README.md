# Packaging

## Application Icons

The Triad application and tray icon assets live under `packaging/assets/icons/` (documented in [`packaging/assets/README.md`](../../packaging/assets/README.md)):

- **Windows:** `packaging/assets/icons/app.ico` (multi-size 16–256 px) is embedded into `etd-ui.exe` as resource ID `1` (giving Start Menu shortcuts and taskbar pins the Triad icon automatically) and serves as the MSI Add/Remove Programs (`ARPPRODUCTICON`) icon.
- **Linux:** `packaging/assets/icons/hicolor/` provides the freedesktop hicolor PNG sizes (`16x16`–`256x256`) and scalable SVG under `easytier-desktop.{png,svg}`, matching the window `app_id` (`easytier-desktop`).
- **macOS:** `packaging/assets/icons/app.icns` provides the squircle `.icns` bundle icon for future `.app` packaging.

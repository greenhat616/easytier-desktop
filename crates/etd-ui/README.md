# etd-ui

The desktop UI of EasyTier Desktop (UI side; binary `etd-ui` plus a library). It is built
on GPUI through `gpui-kit` 0.11 (features `component`, `assets`, `x11`, `gpui-fast`) with
a native tray from `tray-icon` + `muda`. All views bind to `etd_app::StateStore` and send
`etd_app::UserCommand`s through `etd_app::AppBridge`; the UI never talks to the host
itself and never starts a kernel. Visual design is in progress: this README describes
what exists today.

## Running

```sh
cargo run -p etd-ui
```

The binary looks for `etd-host` next to its own executable (to start a user host or to
run the service installer) and for an installed service host at the platform's
protected install directory. Start-up wiring in `src/main.rs`:

1. `build_local_services()`: real gRPC client factory (`GrpcHostClient` over
   `LocalConnector`), `LocalHostLauncher` wrapped in `ElevatedAwareLauncher`, and
   `TomlProfileStore` at its default path.
2. `AppRuntime::start` puts tokio on its background thread (see
   [`../etd-app/README.md`](../etd-app/README.md)).
3. GPUI runs with `QuitMode::Explicit` and `FluentAssets`; `theme::init` installs the
   Fluent theme; `UiController::start` opens the first window and installs the tray.
   Every exit runs `etd_app::ExitGate` (with `LeaseRelease::StopInstances`) before
   `cx.quit()`.

## Public surface

| Item | Purpose |
| --- | --- |
| `UiController`, `ExitHook` | Main-thread coordinator: bridge, `WindowTray`, `TrayDriver`, exit gate, window generations, service installation. |
| `MainView` | Root view: sidebar (Instances, Reclaim, appearance menu) and section content. |
| `UiModel`, `Section`, `DetailTab`, `InstallStatus` | GPUI entity wrapping the latest `StateStore` plus view-only selection. |
| `NetworkEditorState`, `SecretMode` | Network configuration editor. |
| `NativeTrayBackend` | `etd_app::TrayBackend` over `tray-icon` + `muda`. |
| `build_local_services`, `LocalGrpcClientFactory`, `ElevatedAwareLauncher` | Composition root. |
| `ServiceInstaller`, `PlatformServiceInstaller` | Runs `etd-host install --allow-user <SID or UID>` when the user accepts the offer. |
| `assets::FluentAssets`, `theme::{init, install_palette}` | Icons and theme. |

`lib.rs` and `Cargo.toml` are part of the `freeze-v1` interface set.

### Logs and panics

`src/logging.rs` sends `tracing` output (filter from `RUST_LOG`, default `info`) to
`etd-ui.log` in the per-user local data directory, which never roams:

| Platform | Folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\EasyTierDesk\data\logs` |
| macOS | `~/Library/Application Support/EasyTierDesk/logs` |
| Linux | `$XDG_DATA_HOME/easytierdesk/logs` (default `~/.local/share/easytierdesk/logs`) |

A file is rotated before a write would take it past 1 MiB; the current file and four
older ones (`etd-ui.log.1`, newest, to `.4`) are kept, so the folder stays under about
5 MiB. A panic hook writes the panic message, the thread name and a captured backtrace
to the same file synchronously, then runs the default hook. A debug build also logs to
stdout; a release build (no console on Windows) logs to stdout only if the folder cannot
be opened. No network secret reaches these events: the store strips it from every spec,
and the host redacts its own errors. Panic messages are written as they are. There is
no "Open log folder" entry in the UI yet.

## Dependencies and boundaries

- **Used by:** nothing in the workspace (top of the UI side).
- **Depends on:** `etd-app`, `etd-client`, `etd-contract`, `etd-ipc`, `etd-sysfx-os`
  (elevation check, installed host directory, Windows appearance and DWM calls);
  `directories` for the log folder;
  `etd-testkit` as a dev-dependency only.
- **Must not depend on:** `etd-core-easytier` or any `easytier*` crate anywhere in its
  closure (rule 1), nor directly on system binding crates such as `windows*`, `nix` or
  `libc` (rule 2); OS calls go through `etd-sysfx-os`. See
  [`../../xtask/README.md`](../../xtask/README.md).

## Key modules

| Module | Responsibility |
| --- | --- |
| `main.rs` | Binary entry point, wiring described above. |
| `logging` (binary) | Rotated log file and panic hook (above). |
| `composition` | Production services; elevation-aware launcher (an elevated UI refuses to start a user host and offers the service instead); platform service installer. |
| `controller` | `UiController`: applies `WindowAction`s, pumps tray events, runs the exit gate. When GPUI quits without our exit command (logoff or shutdown; on macOS also Quit from the Dock), its quit hook runs the gate with `ExitReason::SessionEnd`, blocking under the gate's deadlines because the process ends right after. |
| `model` | `UiModel`; detail tabs Nodes / Routes / Traffic are gated on host capabilities. |
| `editor` | Network editor. Suggested listeners come from `etd_app::SUGGESTED_LISTENERS` (port 11010 set, no `faketcp`). |
| `views/mod.rs` | `MainView`, sidebar, section switch. |
| `views/banners.rs` | Header and banners: host reconnecting, "cut, unconfirmed" with retry, not installed (offer install), elevated user-host refusal, upgrade required, unverified host, keep-window notice, operations bar. |
| `views/instances.rs` | Instance list and detail panel (Overview plus capability-gated pages). |
| `views/reclaim.rs` | Reclaim report with per-item candidate decisions (Delete / Keep), conflict release, quarantine retries. |
| `views/ui.rs` | Small `#[inline(never)]` element builders and the appearance menu. |
| `theme` / `preferences` | Fluent theme and the persisted theme choice (below). |
| `assets` | `FluentAssets` (embedded Fluent UI icons composed with `gpui-kit`) and `app_icons` (embedded Triad tray and X11 window PNGs). |
| `tray` | `NativeTrayBackend`, rendering the Triad tray icon per state (`connected`, `connecting`, `disconnected`), taskbar theme (`light`/`dark`), and DPI (`16`/`24`). |

The `#[inline(never)]` helpers returning `AnyElement` are deliberate: unoptimised debug
builds otherwise overflow the 1 MiB main-thread stack on Windows.

### Fluent theme

`assets/fluent-theme.json` is a `gpui-kit` theme set with two profiles, "EasyTier Fluent
Light" and "EasyTier Fluent Dark", embedded at compile time. `src/theme.rs` installs both
and reapplies the matching one whenever the mode or the system style changes. The user
picks Follow system / Light / Dark in the sidebar's appearance menu; the change applies
live. `src/preferences.rs` stores that choice as `ui-preferences.json` (for example
`{"theme": "follow-system"}`) beside `profiles.toml`, written atomically. It contains no
host or network data; an unreadable file falls back to Follow system.

### Icons

- **UI icons:** `assets/fluent/` holds a subset of Microsoft's Fluent System Icons (24 px
  regular SVGs, unmodified, MIT). [`assets/fluent/NOTICE.md`](assets/fluent/NOTICE.md)
  lists each file with its upstream path and commit; the license text is in
  [`assets/fluent/LICENSE.txt`](assets/fluent/LICENSE.txt). Keep both in sync when adding
  an icon, and add the file to the table in `src/assets.rs`.
- **Application & tray icons:** the Triad icon set lives in
  [`packaging/assets/icons/`](../../packaging/assets/README.md). On Windows, `build.rs`
  and `app.rc` embed `packaging/assets/icons/app.ico` as icon resource `1` (used by
  Explorer, shortcuts, GPUI, and `WM_SETICON`); on Linux, `WindowOptions` sets
  `app_id = "easytier-desktop"` and embeds `app-64.png` for X11 `_NET_WM_ICON`; the system
  tray loads the pre-rendered Triad tray PNGs and switches `light`/`dark` and `16`/`24`
  live with taskbar theme and DPI.

## Platform notes

- **Windows:** the theme follows the system accent colour when it gives readable text
  (contrast-checked), prefers Segoe UI Variable when installed, sets per-window DWM dark
  mode, and uses a Mica backdrop only when the system supports it, direct composition is
  not disabled (`GPUI_DISABLE_DIRECT_COMPOSITION`) and DWM accepts it; otherwise the
  window is opaque. The tray backend probes the icon after install so a desktop without
  a taskbar reports "no tray" and the window stays open. The service installer elevates
  through a UAC prompt; all child processes use `CREATE_NO_WINDOW`.
- **macOS:** the theme choice sets the application's native appearance; the installer
  asks for administrator rights through `osascript`.
- **Linux:** the tray uses `tray-icon`'s `ksni` (StatusNotifierItem) backend; without a
  tray the window cannot hide. The installer runs through `pkexec`.

## Testing

```sh
cargo nextest run -p etd-ui
```

`tests/view_binding.rs` is the single integration test file. It runs the real `MainView`
and `UiController` in GPUI's headless `TestAppContext`, with a fake tray, fake installer
and fakes from `etd-testkit`, and covers: live theme switching, instance conditions
(waiting, gave up, cut unconfirmed), capability-gated pages, that the editor never stores
a secret, reclaim per-item confirmation, the reconnecting banner, the not-installed and
elevated-refusal flows, trayless fallback and exit gate order, the session-end exit,
hide to tray and restore,
the icon asset source, and rendering every view on a 768 KiB stack (the Windows
stack-overflow guard). Unit tests in `src/theme.rs`, `src/preferences.rs`,
`src/assets.rs` and `src/tray.rs` cover accent contrast, Mica fallback, font choice,
preference round trips and indicator icons; those in `src/logging.rs` (binary target)
cover size rotation, the kept count, appending to an existing file, the panic record and
the local (non-roaming) folder. Nothing here is privileged.

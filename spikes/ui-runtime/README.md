# Spike S3: UI Runtime Coexistence (`ui-runtime-spike`)

Standalone prototype (outside the root Cargo workspace) verifying coexistence of:

- `gpui-kit 0.11.0` (`gpui-pre 0.3.14` + `gpui-component 0.11.0` + `gpui-kit-assets 0.11.0`)
- `tray-icon 0.26.1` + `muda 0.21.2`
- Background-thread `tokio 1.54.1` runtime + `tonic 0.14.9` client against an in-process fake `tonic` server
- Bounded `async-channel 2.5.0` bridge between GPUI's foreground executor and the background Tokio thread
- Repeated hide-to-tray / restore window cycles under `QuitMode::Explicit`
- Deterministic exit order: `stop_subscription` -> `stop_tokio` -> `quit_gpui`

## Run

From `spikes/ui-runtime`:

```powershell
# Automated acceptance check (50 hide-to-tray / restore cycles + ordered exit < 5s)
cargo run -- --cycles 50

# Hold initial window + tray visible for 10s (useful to inspect/screenshot the taskbar icon), then run cycles
cargo run -- --cycles 50 --hold-ms 10000

# Interactive mode (click window X to hide to tray, left-click tray to restore, right-click for menu)
cargo run -- --interactive
```

## Architecture Notes for A1 (`etd-app`) and U1 (`etd-ui`)

1. **Keep GPUI alive with 0 windows**: Always configure `gpui_kit::application().with_quit_mode(QuitMode::Explicit)`. On Windows, `WindowsPlatform::hide()` and `App::activate()` are no-ops and `Window` has no hide method; hide-to-tray closes the native window (`window.remove_window()` / titlebar close) while retaining `Entity` state + `TrayAdapter`, and restore opens a fresh window bound to the same state entity.
2. **Tray on GPUI main thread**: On Windows `tray-icon` creates a hidden Win32 `HWND` (`!Send`) whose `tray_proc` is pumped natively by GPUI's `GetMessageW` loop. Construct and drop `TrayAdapter` on the GPUI main thread.
3. **`OnceCell`/`OnceLock` handler trap in `tray-icon 0.26.1` & `muda 0.21.2`**: Both crates store their event handler in a write-once global (`OnceCell`/`OnceLock`). Install a single process-wide forwarder backed by a `Mutex<Option<Dispatch>>` and never block inside `tray_proc` (use `async_channel::Sender::try_send`).
4. **Detecting tray availability on Windows**: `TrayIconBuilder::build()` returns `Ok` even when `Shell_TrayWnd` is absent (waiting for `TaskbarCreated`). Probe with `set_tooltip` (`NIM_MODIFY`) or `rect()` (`Shell_NotifyIconGetRect`) to report `TrayState::Unavailable` accurately instead of assuming the icon is visible.
5. **Ordered exit outside GPUI's 200ms `SHUTDOWN_TIMEOUT`**: Run `stop_subscription` -> `stop_tokio` (joining the Tokio thread on `cx.background_executor()`, never blocking the UI thread) -> `tray.shutdown()` (`NIM_DELETE` + `DestroyWindow`) -> `cx.quit()`.

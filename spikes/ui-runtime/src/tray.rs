use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use async_channel::{Receiver, Sender};
use muda::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{
    Icon, MouseButton, MouseButtonState, Rect, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

struct TrayDispatch {
    action_tx: Sender<TrayAction>,
    show_id: MenuId,
    hide_id: MenuId,
    ping_id: MenuId,
    quit_id: MenuId,
}

static TRAY_DISPATCH: OnceLock<Mutex<Option<TrayDispatch>>> = OnceLock::new();
static HANDLERS_INSTALLED: OnceLock<()> = OnceLock::new();

fn dispatch_slot() -> &'static Mutex<Option<TrayDispatch>> {
    TRAY_DISPATCH.get_or_init(|| Mutex::new(None))
}

fn ensure_global_handlers_installed() {
    // Both `tray-icon 0.26.1` (`OnceCell`) and `muda 0.21.2` (`OnceLock`) only accept
    // `set_event_handler` once per process; indirection through `TRAY_DISPATCH` allows
    // clean teardown and re-creation without silently losing events.
    HANDLERS_INSTALLED.get_or_init(|| {
        TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| {
            let should_toggle = matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            );
            if should_toggle
                && let Ok(guard) = dispatch_slot().lock()
                && let Some(dispatch) = guard.as_ref()
            {
                let _ = dispatch.action_tx.try_send(TrayAction::ToggleWindow);
            }
        }));

        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            if let Ok(guard) = dispatch_slot().lock()
                && let Some(dispatch) = guard.as_ref()
            {
                let action = if event.id == dispatch.show_id {
                    Some(TrayAction::ShowWindow)
                } else if event.id == dispatch.hide_id {
                    Some(TrayAction::HideWindow)
                } else if event.id == dispatch.ping_id {
                    Some(TrayAction::PingServer)
                } else if event.id == dispatch.quit_id {
                    Some(TrayAction::Quit)
                } else {
                    None
                };
                if let Some(action) = action {
                    let _ = dispatch.action_tx.try_send(action);
                }
            }
        }));
    });
}

/// High-level actions emitted by the OS tray icon & context menu into GPUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    ToggleWindow,
    ShowWindow,
    HideWindow,
    PingServer,
    Quit,
}

const TRAY_ID: &str = "easytier-s3-spike";
#[cfg(target_os = "linux")]
const TRAY_TITLE: &str = "EasyTier S3 Spike";

/// Main-thread tray adapter combining `tray-icon 0.26.1` and `muda 0.21.2`.
///
/// U1 reuse note: `TrayIcon` is `!Send` on Windows (`Rc<RefCell<...>>`) and creates a hidden
/// Win32 `HWND` on the calling thread; on macOS it creates an `NSStatusItem` on the main thread;
/// on Linux (`ksni`) it publishes a `StatusNotifierItem` over session D-Bus without requiring GTK.
/// Always construct and drop it on GPUI's main thread inside `application().run(...)`.
pub struct TrayAdapter {
    tray: TrayIcon,
    // Keep menu items alive if dynamic label/enabled updates are needed later.
    _show_item: MenuItem,
    _hide_item: MenuItem,
    _ping_item: MenuItem,
    _quit_item: MenuItem,
    action_rx: Receiver<TrayAction>,
}

impl TrayAdapter {
    pub fn new(tooltip: &str) -> Result<Self> {
        let (action_tx, action_rx) = async_channel::bounded::<TrayAction>(64);

        let show_item = MenuItem::with_id(MenuId::new("show"), "Show / Restore Window", true, None);
        let hide_item = MenuItem::with_id(MenuId::new("hide"), "Hide to Tray", true, None);
        let ping_item = MenuItem::with_id(MenuId::new("ping"), "Ping Fake Server", true, None);
        let quit_item = MenuItem::with_id(MenuId::new("quit"), "Quit", true, None);

        let menu = Menu::new();
        menu.append(&show_item).context("append show menu item")?;
        menu.append(&hide_item).context("append hide menu item")?;
        menu.append(&ping_item).context("append ping menu item")?;
        menu.append(&PredefinedMenuItem::separator())
            .context("append separator")?;
        menu.append(&quit_item).context("append quit menu item")?;

        ensure_global_handlers_installed();
        *dispatch_slot().lock().expect("tray dispatch lock") = Some(TrayDispatch {
            action_tx,
            show_id: show_item.id().clone(),
            hide_id: hide_item.id().clone(),
            ping_id: ping_item.id().clone(),
            quit_id: quit_item.id().clone(),
        });

        let icon = build_spike_icon().context("failed to build RGBA tray icon")?;
        let builder = TrayIconBuilder::new()
            .with_id(TRAY_ID)
            .with_tooltip(tooltip)
            .with_icon(icon)
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true);
        #[cfg(target_os = "linux")]
        let builder = builder.with_title(TRAY_TITLE);

        let tray = builder
            .build()
            .context("failed to register system tray icon")?;

        Ok(Self {
            tray,
            _show_item: show_item,
            _hide_item: hide_item,
            _ping_item: ping_item,
            _quit_item: quit_item,
            action_rx,
        })
    }

    pub fn actions(&self) -> Receiver<TrayAction> {
        self.action_rx.clone()
    }

    pub fn tray_id(&self) -> &str {
        &self.tray.id().0
    }

    pub fn rect(&self) -> Option<Rect> {
        self.tray.rect()
    }

    /// Returns `Some(true)` on macOS when `NSStatusItem` is allocated and retained,
    /// `Some(false)` if missing, and `None` on non-macOS platforms.
    pub fn has_ns_status_item(&self) -> Option<bool> {
        #[cfg(target_os = "macos")]
        {
            Some(self.tray.ns_status_item().is_some())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Probes whether the platform shell / tray host actually registered our icon.
    ///
    /// - Windows: `tray-icon` swallows `NIM_ADD` failure to wait for `TaskbarCreated`;
    ///   `set_tooltip` (`NIM_MODIFY`) or `rect()` (`Shell_NotifyIconGetRect`) confirms registration.
    /// - macOS: verifies `ns_status_item().is_some()` and that its status bar button has a layout `rect()`.
    /// - Linux (`ksni`): `tray-icon` passes `assume_sni_available(true)` and `set_tooltip` always returns `Ok`,
    ///   so we query `org.kde.StatusNotifierWatcher` over session D-Bus (`gdbus`) for our PID's item.
    pub fn describe_registration(&self, tooltip: &str) -> (bool, String) {
        #[cfg(windows)]
        {
            let registered =
                self.tray.set_tooltip(Some(tooltip)).is_ok() || self.tray.rect().is_some();
            let label = match (registered, self.tray.rect()) {
                (true, Some(rect)) => format!(
                    "visible in shell at ({:.0}, {:.0}) {}x{}",
                    rect.position.x, rect.position.y, rect.size.width, rect.size.height
                ),
                (true, None) => "registered in shell (rect unavailable)".to_owned(),
                (false, _) => {
                    "HWND alive, waiting for TaskbarCreated (no Shell_TrayWnd on this desktop)"
                        .to_owned()
                }
            };
            (registered, label)
        }

        #[cfg(target_os = "macos")]
        {
            let _ = tooltip;
            let has_item = self.tray.ns_status_item().is_some();
            let rect = self.tray.rect();
            let registered = has_item && rect.is_some();
            let label = match (has_item, rect) {
                (true, Some(rect)) => format!(
                    "NSStatusItem visible at ({:.0}, {:.0}) {}x{}",
                    rect.position.x, rect.position.y, rect.size.width, rect.size.height
                ),
                (true, None) => {
                    "NSStatusItem allocated (status bar window rect pending)".to_owned()
                }
                (false, _) => "NSStatusItem missing".to_owned(),
            };
            (registered, label)
        }

        #[cfg(target_os = "linux")]
        {
            let _ = tooltip;
            probe_linux_sni_registration()
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let registered = self.tray.set_tooltip(Some(tooltip)).is_ok();
            (registered, format!("registered={registered}"))
        }
    }

    pub fn set_tooltip(&self, tooltip: &str) -> Result<()> {
        self.tray
            .set_tooltip(Some(tooltip))
            .context("failed to update tray tooltip")
    }

    /// Cleanly detaches event dispatch and removes the tray icon before GPUI quits,
    /// avoiding ghost icons in the system tray / status bar.
    pub fn shutdown(self) {
        if let Ok(mut guard) = dispatch_slot().lock() {
            *guard = None;
        }
        drop(self.tray);
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_sni_registration() -> (bool, String) {
    let pid = std::process::id();
    let expected = format!("org.kde.StatusNotifierItem-{pid}-");
    let output = std::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.kde.StatusNotifierWatcher",
            "--object-path",
            "/StatusNotifierWatcher",
            "--method",
            "org.freedesktop.DBus.Properties.Get",
            "org.kde.StatusNotifierWatcher",
            "RegisteredStatusNotifierItems",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let registered = stdout.contains(&expected);
            let label = if registered {
                format!("SNI registered with org.kde.StatusNotifierWatcher: {stdout}")
            } else {
                format!("SNI watcher reachable but item {expected}* not listed: {stdout}")
            };
            (registered, label)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            (
                false,
                format!("org.kde.StatusNotifierWatcher unavailable ({stderr})"),
            )
        }
        Err(err) => (
            false,
            format!("unable to run gdbus for SNI registration probe ({err})"),
        ),
    }
}

/// Generates a crisp 32x32 RGBA icon (deep teal circle with a bright white diamond core)
/// so it is unmistakably visible against both dark and light Windows taskbars.
fn build_spike_icon() -> Result<Icon> {
    const SIZE: u32 = 32;
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    let center = (SIZE as f32 - 1.0) / 2.0;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let manhattan = dx.abs() + dy.abs();

            let pixel = if manhattan <= 6.5 {
                // Bright white inner diamond
                [255, 255, 255, 255]
            } else if dist <= 13.5 {
                // Vivid teal badge (#14B8A6)
                [20, 184, 166, 255]
            } else if dist <= 15.0 {
                // Crisp dark-teal outer ring (#0F766E)
                [15, 118, 110, 255]
            } else {
                [0, 0, 0, 0]
            };

            let idx = ((y * SIZE + x) * 4) as usize;
            rgba[idx..idx + 4].copy_from_slice(&pixel);
        }
    }

    Icon::from_rgba(rgba, SIZE, SIZE).context("Icon::from_rgba failed")
}

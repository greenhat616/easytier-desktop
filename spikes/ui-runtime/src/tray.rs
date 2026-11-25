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
            if should_toggle {
                if let Ok(guard) = dispatch_slot().lock() {
                    if let Some(dispatch) = guard.as_ref() {
                        let _ = dispatch.action_tx.try_send(TrayAction::ToggleWindow);
                    }
                }
            }
        }));

        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            if let Ok(guard) = dispatch_slot().lock() {
                if let Some(dispatch) = guard.as_ref() {
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

/// Main-thread tray adapter combining `tray-icon 0.26.1` and `muda 0.21.2`.
///
/// U1 reuse note: `TrayIcon` is `!Send` on Windows (`Rc<RefCell<...>>`) and creates a hidden
/// Win32 `HWND` on the calling thread. Always construct and drop it on GPUI's main thread
/// inside `application().run(...)` so GPUI's `GetMessageW` loop pumps `tray_proc`.
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
        let tray = TrayIconBuilder::new()
            .with_tooltip(tooltip)
            .with_icon(icon)
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true)
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

    pub fn rect(&self) -> Option<Rect> {
        self.tray.rect()
    }

    /// Probes whether the Windows Shell (`Shell_TrayWnd`) actually accepted `NIM_ADD`.
    ///
    /// `tray-icon 0.26.1` swallows `Shell_NotifyIconW(NIM_ADD)` failures so the hidden HWND can
    /// re-register later on `TaskbarCreated`; `set_tooltip` calls `NIM_MODIFY`, which returns
    /// `Ok(())` iff the icon is currently registered with Explorer (pinned or in overflow).
    pub fn probe_shell_registered(&self, tooltip: &str) -> bool {
        self.tray.set_tooltip(Some(tooltip)).is_ok()
    }

    pub fn set_tooltip(&self, tooltip: &str) -> Result<()> {
        self.tray
            .set_tooltip(Some(tooltip))
            .context("failed to update tray tooltip")
    }

    /// Cleanly detaches event dispatch and removes the tray icon (`NIM_DELETE` + `DestroyWindow`)
    /// before GPUI posts `WM_QUIT`, avoiding ghost icons in the Windows notification area.
    pub fn shutdown(self) {
        if let Ok(mut guard) = dispatch_slot().lock() {
            *guard = None;
        }
        drop(self.tray);
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

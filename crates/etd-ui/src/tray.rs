//! `etd_app::TrayBackend` implementation backed by `tray-icon` + `muda`.
//!
//! Incorporates the S3 runtime coexistence findings:
//! - Both `tray-icon` (`OnceCell`) and `muda` (`OnceLock`) only accept
//!   `set_event_handler` once per process, so a single process-wide forwarder
//!   routes events through a replaceable `Mutex<Option<TrayDispatch>>` slot
//!   using non-blocking `try_send`.
//! - On Windows, `tray-icon` ignores `Shell_NotifyIconW(NIM_ADD) == FALSE` to
//!   wait for `TaskbarCreated`; `install()` probes with `set_tooltip` / `rect()`
//!   so desktops without Explorer report [`TrayError::Unavailable`].
//! - Must be created and dropped on the GPUI main thread.

use std::sync::{Mutex, OnceLock};

use async_channel::{Receiver, Sender};
use etd_app::{TrayBackend, TrayError, TrayEvent, TrayIndicator, TrayMenu};
use muda::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

const ICON_SIZE: u32 = 32;

struct TrayDispatch {
    events: Sender<TrayEvent>,
    wake: Sender<()>,
}

static TRAY_DISPATCH: OnceLock<Mutex<Option<TrayDispatch>>> = OnceLock::new();
static HANDLERS_INSTALLED: OnceLock<()> = OnceLock::new();

fn dispatch_slot() -> &'static Mutex<Option<TrayDispatch>> {
    TRAY_DISPATCH.get_or_init(|| Mutex::new(None))
}

fn emit_event(event: TrayEvent) {
    if let Ok(guard) = dispatch_slot().lock()
        && let Some(dispatch) = guard.as_ref()
    {
        let _ = dispatch.events.try_send(event);
        let _ = dispatch.wake.try_send(());
    }
}

fn ensure_global_handlers_installed() {
    HANDLERS_INSTALLED.get_or_init(|| {
        TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| {
            let activated = matches!(
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
            if activated {
                emit_event(TrayEvent::Activated);
            }
        }));

        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            emit_event(TrayEvent::Menu(event.id.0));
        }));
    });
}

fn build_muda_menu(menu: &TrayMenu) -> Result<(Menu, Vec<MenuItem>), TrayError> {
    let muda_menu = Menu::new();
    let mut items = Vec::with_capacity(menu.items.len());
    for entry in &menu.items {
        let item = MenuItem::with_id(MenuId::new(&entry.id), &entry.label, entry.enabled, None);
        muda_menu
            .append(&item)
            .map_err(|error| TrayError::Backend(format!("failed to build tray menu: {error}")))?;
        items.push(item);
    }
    Ok((muda_menu, items))
}

/// Generates a 32x32 RGBA badge icon colored according to [`TrayIndicator`].
pub fn build_indicator_rgba(indicator: TrayIndicator) -> Vec<u8> {
    let (fill, ring) = match indicator {
        TrayIndicator::Idle => ([100, 116, 139, 255], [71, 85, 105, 255]),
        TrayIndicator::Connected => ([20, 184, 166, 255], [15, 118, 110, 255]),
        TrayIndicator::Attention => ([245, 158, 11, 255], [180, 83, 9, 255]),
        TrayIndicator::Error => ([239, 68, 68, 255], [185, 28, 28, 255]),
        _ => ([100, 116, 139, 255], [71, 85, 105, 255]),
    };

    let mut rgba = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
    let center = (ICON_SIZE as f32 - 1.0) / 2.0;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let manhattan = dx.abs() + dy.abs();

            let pixel = if manhattan <= 6.5 {
                [255, 255, 255, 255]
            } else if dist <= 13.5 {
                fill
            } else if dist <= 15.0 {
                ring
            } else {
                [0, 0, 0, 0]
            };

            let idx = ((y * ICON_SIZE + x) * 4) as usize;
            rgba[idx..idx + 4].copy_from_slice(&pixel);
        }
    }
    rgba
}

fn build_indicator_icon(indicator: TrayIndicator) -> Result<Icon, TrayError> {
    Icon::from_rgba(build_indicator_rgba(indicator), ICON_SIZE, ICON_SIZE)
        .map_err(|error| TrayError::Backend(format!("failed to construct tray icon: {error}")))
}

/// Real OS tray backend driven by [`etd_app::window_tray::TrayDriver`].
///
/// Main-thread only (not `Send` on Windows).
pub struct NativeTrayBackend {
    tray: Option<TrayIcon>,
    menu_items: Vec<MenuItem>,
    event_tx: Sender<TrayEvent>,
    event_rx: Receiver<TrayEvent>,
    wake_tx: Sender<()>,
    wake_rx: Receiver<()>,
}

impl NativeTrayBackend {
    pub fn new() -> Self {
        let (event_tx, event_rx) = async_channel::bounded(64);
        let (wake_tx, wake_rx) = async_channel::bounded(1);
        Self {
            tray: None,
            menu_items: Vec::new(),
            event_tx,
            event_rx,
            wake_tx,
            wake_rx,
        }
    }

    /// Wake signal fired whenever the single global handler enqueues a tray event,
    /// allowing GPUI to poll [`etd_app::window_tray::TrayDriver::poll`] reactively
    /// without a timer loop.
    pub fn wake_receiver(&self) -> Receiver<()> {
        self.wake_rx.clone()
    }
}

impl Default for NativeTrayBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TrayBackend for NativeTrayBackend {
    fn install(&mut self, tooltip: &str, menu: &TrayMenu) -> Result<(), TrayError> {
        self.remove();
        let (muda_menu, menu_items) = build_muda_menu(menu)?;
        let icon = build_indicator_icon(TrayIndicator::Idle)?;

        ensure_global_handlers_installed();
        if let Ok(mut slot) = dispatch_slot().lock() {
            *slot = Some(TrayDispatch {
                events: self.event_tx.clone(),
                wake: self.wake_tx.clone(),
            });
        }

        let built = TrayIconBuilder::new()
            .with_tooltip(tooltip)
            .with_icon(icon)
            .with_menu(Box::new(muda_menu))
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true)
            .build();

        let tray = match built {
            Ok(tray) => tray,
            Err(error) => {
                if let Ok(mut slot) = dispatch_slot().lock() {
                    *slot = None;
                }
                return Err(TrayError::Unavailable(error.to_string()));
            }
        };

        // S3 finding #4: on Windows, `tray-icon` swallows `NIM_ADD` failure so it can
        // wait for `TaskbarCreated`. Probe with `NIM_MODIFY` (`set_tooltip`) or `rect()`
        // so headless / trayless desktops report `TrayError::Unavailable`.
        #[cfg(windows)]
        {
            let registered = tray.set_tooltip(Some(tooltip)).is_ok() || tray.rect().is_some();
            if !registered {
                if let Ok(mut slot) = dispatch_slot().lock() {
                    *slot = None;
                }
                drop(tray);
                return Err(TrayError::Unavailable(
                    "Windows notification area is unavailable on this desktop".into(),
                ));
            }
        }

        self.tray = Some(tray);
        self.menu_items = menu_items;
        Ok(())
    }

    fn set_indicator(&mut self, indicator: TrayIndicator, tooltip: &str) -> Result<(), TrayError> {
        let Some(tray) = self.tray.as_ref() else {
            return Err(TrayError::Unavailable("tray icon is not installed".into()));
        };
        let icon = build_indicator_icon(indicator)?;
        tray.set_icon(Some(icon))
            .map_err(|error| TrayError::Backend(format!("failed to update tray icon: {error}")))?;
        // Per S3 finding #4, treat tooltip update errors as non-fatal backend errors.
        if let Err(error) = tray.set_tooltip(Some(tooltip)) {
            return Err(TrayError::Backend(format!(
                "failed to update tray tooltip: {error}"
            )));
        }
        Ok(())
    }

    fn set_menu(&mut self, menu: &TrayMenu) -> Result<(), TrayError> {
        let Some(tray) = self.tray.as_ref() else {
            return Err(TrayError::Unavailable("tray icon is not installed".into()));
        };
        let (muda_menu, menu_items) = build_muda_menu(menu)?;
        tray.set_menu(Some(Box::new(muda_menu)));
        self.menu_items = menu_items;
        Ok(())
    }

    fn try_next_event(&mut self) -> Option<TrayEvent> {
        self.event_rx.try_recv().ok()
    }

    fn remove(&mut self) {
        if let Ok(mut slot) = dispatch_slot().lock() {
            *slot = None;
        }
        self.tray = None;
        self.menu_items.clear();
    }
}

impl Drop for NativeTrayBackend {
    fn drop(&mut self) {
        self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_icons_have_expected_size_and_distinct_colors() {
        let idle = build_indicator_rgba(TrayIndicator::Idle);
        let connected = build_indicator_rgba(TrayIndicator::Connected);
        let attention = build_indicator_rgba(TrayIndicator::Attention);
        let error = build_indicator_rgba(TrayIndicator::Error);
        let expected_len = (ICON_SIZE * ICON_SIZE * 4) as usize;
        assert_eq!(idle.len(), expected_len);
        assert_eq!(connected.len(), expected_len);
        assert_eq!(attention.len(), expected_len);
        assert_eq!(error.len(), expected_len);
        assert_ne!(idle, connected);
        assert_ne!(connected, attention);
        assert_ne!(attention, error);
    }
}

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
//! - Tray glyphs come from the embedded Triad icon set
//!   (`packaging/assets/icons/tray/`), selecting state (`connected`, `connecting`,
//!   `disconnected`), taskbar light/dark ink, and 16 vs 24 px by DPI.
//! - Must be created and dropped on the GPUI main thread.

use std::sync::{Mutex, OnceLock};

use async_channel::{Receiver, Sender};
use etd_app::{TrayBackend, TrayError, TrayEvent, TrayIndicator, TrayMenu};
use muda::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::assets::app_icons::{TraySize, TrayTheme, TrayVisualState, tray_icon_rgba};

/// Combined taskbar theme + DPI size selection for the tray icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrayStyle {
    pub theme: TrayTheme,
    pub size: TraySize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TrayAppearanceTarget {
    taskbar_dark: Option<bool>,
    size: Option<TraySize>,
}

struct TrayDispatch {
    events: Sender<TrayEvent>,
    wake: Sender<()>,
}

static TRAY_DISPATCH: OnceLock<Mutex<Option<TrayDispatch>>> = OnceLock::new();
static HANDLERS_INSTALLED: OnceLock<()> = OnceLock::new();
static TRAY_APPEARANCE: OnceLock<Mutex<TrayAppearanceTarget>> = OnceLock::new();

fn dispatch_slot() -> &'static Mutex<Option<TrayDispatch>> {
    TRAY_DISPATCH.get_or_init(|| Mutex::new(None))
}

fn appearance_slot() -> &'static Mutex<TrayAppearanceTarget> {
    TRAY_APPEARANCE.get_or_init(|| Mutex::new(TrayAppearanceTarget::default()))
}

fn wake_tray_poll() {
    if let Ok(guard) = dispatch_slot().lock()
        && let Some(dispatch) = guard.as_ref()
    {
        let _ = dispatch.wake.try_send(());
    }
}

fn emit_event(event: TrayEvent) {
    if let Ok(guard) = dispatch_slot().lock()
        && let Some(dispatch) = guard.as_ref()
    {
        let _ = dispatch.events.try_send(event);
        let _ = dispatch.wake.try_send(());
    }
}

/// Update the desired taskbar theme and/or DPI tray size and nudge the UI
/// main-thread tray poll so a live tray icon swaps variants immediately.
pub(crate) fn update_system_tray_appearance(taskbar_dark: Option<bool>, size: Option<TraySize>) {
    let changed = if let Ok(mut target) = appearance_slot().lock() {
        let prev = *target;
        if let Some(dark) = taskbar_dark {
            target.taskbar_dark = Some(dark);
        }
        if let Some(sz) = size {
            target.size = Some(sz);
        }
        *target != prev
    } else {
        false
    };
    if changed {
        wake_tray_poll();
    }
}

fn resolved_tray_style() -> TrayStyle {
    let target = appearance_slot()
        .lock()
        .map(|guard| *guard)
        .unwrap_or_default();
    let dark = target
        .taskbar_dark
        .or_else(etd_sysfx_os::appearance::query_taskbar_dark)
        .unwrap_or(true);
    let size = target.size.unwrap_or_else(|| {
        etd_sysfx_os::appearance::query_tray_icon_px()
            .map(TraySize::for_icon_px)
            .unwrap_or(TraySize::Px16)
    });
    TrayStyle {
        // macOS template images use monochrome dark ink and AppKit recolors
        // them automatically for light or dark menu bars.
        theme: if cfg!(target_os = "macos") {
            TrayTheme::Light
        } else {
            TrayTheme::from_taskbar_dark(dark)
        },
        size,
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

/// Decodes the embedded Triad tray icon for `indicator` and `style` into
/// `(width, height, rgba_bytes)`.
pub fn build_tray_rgba(indicator: TrayIndicator, style: TrayStyle) -> (u32, u32, Vec<u8>) {
    let state = TrayVisualState::from_indicator(indicator);
    tray_icon_rgba(style.theme, style.size, state)
}

/// Decodes the default 24x24 dark-taskbar Triad RGBA icon for [`TrayIndicator`].
pub fn build_indicator_rgba(indicator: TrayIndicator) -> Vec<u8> {
    build_tray_rgba(
        indicator,
        TrayStyle {
            theme: TrayTheme::Dark,
            size: TraySize::Px24,
        },
    )
    .2
}

fn build_indicator_icon(indicator: TrayIndicator, style: TrayStyle) -> Result<Icon, TrayError> {
    let (width, height, rgba) = build_tray_rgba(indicator, style);
    Icon::from_rgba(rgba, width, height)
        .map_err(|error| TrayError::Backend(format!("failed to construct tray icon: {error}")))
}

fn apply_icon(tray: &TrayIcon, icon: Icon) -> Result<(), TrayError> {
    #[cfg(target_os = "macos")]
    let result = tray.set_icon_templated(Some(icon));
    #[cfg(not(target_os = "macos"))]
    let result = tray.set_icon(Some(icon));
    result.map_err(|error| TrayError::Backend(format!("failed to update tray icon: {error}")))
}

/// Real OS tray backend driven by [`etd_app::window_tray::TrayDriver`].
///
/// Main-thread only (not `Send` on Windows).
pub struct NativeTrayBackend {
    tray: Option<TrayIcon>,
    menu_items: Vec<MenuItem>,
    current_indicator: TrayIndicator,
    applied_style: Option<TrayStyle>,
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
            current_indicator: TrayIndicator::Idle,
            applied_style: None,
            event_tx,
            event_rx,
            wake_tx,
            wake_rx,
        }
    }

    /// Wake signal fired whenever the single global handler enqueues a tray event
    /// or system taskbar/DPI appearance changes, allowing GPUI to poll
    /// [`etd_app::window_tray::TrayDriver::poll`] reactively without a timer loop.
    pub fn wake_receiver(&self) -> Receiver<()> {
        self.wake_rx.clone()
    }

    fn sync_appearance_if_needed(&mut self) {
        let Some(tray) = self.tray.as_ref() else {
            return;
        };
        let desired = resolved_tray_style();
        if self.applied_style == Some(desired) {
            return;
        }
        match build_indicator_icon(self.current_indicator, desired)
            .and_then(|icon| apply_icon(tray, icon))
        {
            Ok(()) => self.applied_style = Some(desired),
            Err(error) => {
                tracing::debug!(%error, "failed to refresh tray icon after appearance change");
            }
        }
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
        let style = resolved_tray_style();
        let icon = build_indicator_icon(TrayIndicator::Idle, style)?;

        ensure_global_handlers_installed();
        if let Ok(mut slot) = dispatch_slot().lock() {
            *slot = Some(TrayDispatch {
                events: self.event_tx.clone(),
                wake: self.wake_tx.clone(),
            });
        }

        let builder = TrayIconBuilder::new()
            .with_tooltip(tooltip)
            .with_menu(Box::new(muda_menu))
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(true);
        #[cfg(target_os = "macos")]
        let builder = builder.with_icon_templated(icon);
        #[cfg(not(target_os = "macos"))]
        let builder = builder.with_icon(icon);
        let built = builder.build();

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
        self.current_indicator = TrayIndicator::Idle;
        self.applied_style = Some(style);
        Ok(())
    }

    fn set_indicator(&mut self, indicator: TrayIndicator, tooltip: &str) -> Result<(), TrayError> {
        let Some(tray) = self.tray.as_ref() else {
            return Err(TrayError::Unavailable("tray icon is not installed".into()));
        };
        let style = resolved_tray_style();
        let icon = build_indicator_icon(indicator, style)?;
        apply_icon(tray, icon)?;
        self.current_indicator = indicator;
        self.applied_style = Some(style);
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
        self.sync_appearance_if_needed();
        self.event_rx.try_recv().ok()
    }

    fn remove(&mut self) {
        if let Ok(mut slot) = dispatch_slot().lock() {
            *slot = None;
        }
        self.tray = None;
        self.menu_items.clear();
        self.applied_style = None;
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
    fn indicator_icons_have_expected_size_and_distinct_triad_states() {
        for theme in [TrayTheme::Light, TrayTheme::Dark] {
            for size in [TraySize::Px16, TraySize::Px24] {
                let style = TrayStyle { theme, size };
                let (w_idle, h_idle, idle) = build_tray_rgba(TrayIndicator::Idle, style);
                let (w_conn, h_conn, connected) = build_tray_rgba(TrayIndicator::Connected, style);
                let (w_attn, h_attn, attention) = build_tray_rgba(TrayIndicator::Attention, style);
                let (_, _, error) = build_tray_rgba(TrayIndicator::Error, style);
                let expected_len = (size.px() * size.px() * 4) as usize;
                assert_eq!((w_idle, h_idle), (size.px(), size.px()));
                assert_eq!((w_conn, h_conn), (size.px(), size.px()));
                assert_eq!((w_attn, h_attn), (size.px(), size.px()));
                assert_eq!(idle.len(), expected_len);
                assert_eq!(connected.len(), expected_len);
                assert_eq!(attention.len(), expected_len);
                assert_eq!(error.len(), expected_len);
                assert_ne!(idle, connected);
                assert_ne!(connected, attention);
                assert_ne!(attention, idle);
                // Idle and Error both map to Triad's disconnected hollow-ring glyph.
                assert_eq!(idle, error);
            }
        }
        assert_eq!(
            build_indicator_rgba(TrayIndicator::Connected).len(),
            24 * 24 * 4
        );
    }

    #[test]
    fn tray_size_thresholds_select_16_at_100_percent_and_24_at_hidpi() {
        assert_eq!(TraySize::for_icon_px(16), TraySize::Px16);
        assert_eq!(TraySize::for_icon_px(19), TraySize::Px16);
        assert_eq!(TraySize::for_icon_px(20), TraySize::Px24);
        assert_eq!(TraySize::for_icon_px(24), TraySize::Px24);
        assert_eq!(TraySize::for_icon_px(32), TraySize::Px24);

        assert_eq!(TraySize::for_scale_factor(1.0), TraySize::Px16);
        assert_eq!(TraySize::for_scale_factor(1.24), TraySize::Px16);
        assert_eq!(TraySize::for_scale_factor(1.25), TraySize::Px24);
        assert_eq!(TraySize::for_scale_factor(1.5), TraySize::Px24);
        assert_eq!(TraySize::for_scale_factor(2.0), TraySize::Px24);
    }
}

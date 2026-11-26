//! Application-owned Fluent palette and window material policy.
//!
//! Keep the toolkit theme's background opaque: inputs and dialogs consume it
//! as well. Only the actual window root and its chrome become transparent
//! when native Mica has been selected successfully.

use etd_sysfx_os::appearance::AccentRamp;
use std::rc::Rc;

use gpui_kit::{
    App, Global, Hsla, SharedString, Styled as _, Window, WindowAppearance,
    WindowBackgroundAppearance,
    component::{Theme, ThemeConfig, ThemeMode, ThemeSet},
    transparent_black,
};

const PALETTE: &str = include_str!("../assets/fluent-theme.json");
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SystemStyle {
    mica_requested: bool,
    dark: Option<bool>,
    light_accent: Option<AccentRamp>,
    dark_accent: Option<AccentRamp>,
}

#[derive(Default)]
struct FluentChrome {
    system: SystemStyle,
    font: Option<SharedString>,
    mica_active: bool,
}

impl Global for FluentChrome {}

/// Initialize the embedded theme independently of native settings, e.g. in
/// headless tests. GPUI Kit must already have been initialized.
pub fn install_palette(cx: &mut App) {
    let set: ThemeSet = serde_json::from_str(PALETTE).expect("embedded Fluent theme is valid JSON");
    let light = set
        .themes
        .iter()
        .find(|t| t.mode == ThemeMode::Light)
        .expect("embedded Fluent light theme")
        .clone();
    let dark = set
        .themes
        .iter()
        .find(|t| t.mode == ThemeMode::Dark)
        .expect("embedded Fluent dark theme")
        .clone();
    // Install the two profiles directly. Changing a registry global also
    // reloads the current profile asynchronously, which could overwrite a
    // system accent/font override. There is no theme-picker registry UI yet.
    Theme::update(cx, |theme| {
        theme.light_theme = Rc::new(light);
        theme.dark_theme = Rc::new(dark);
    });
    cx.set_global(FluentChrome::default());
    apply_theme(cx.window_appearance(), cx);
}

/// Initialize production appearance after `gpui_kit::init`.
pub fn init(cx: &mut App) {
    install_palette(cx);
    #[cfg(target_os = "windows")]
    windows::init(cx);
}

fn apply_theme(appearance: WindowAppearance, cx: &mut App) {
    if !cx.has_global::<FluentChrome>() {
        return;
    }
    let chrome = cx.global::<FluentChrome>();
    let dark = chrome
        .system
        .dark
        .unwrap_or(ThemeMode::from(appearance).is_dark());
    let font = chrome.font.clone();
    let accent = if dark {
        chrome.system.dark_accent
    } else {
        chrome.system.light_accent
    };
    // Start from the shipped profile every time, not the previous system
    // override. Persist the OS-adjusted config in Theme so an appearance
    // reload cannot accidentally restore an outdated accent or font.
    let set: ThemeSet = serde_json::from_str(PALETTE).expect("embedded Fluent theme is valid JSON");
    let mut config = set
        .themes
        .into_iter()
        .find(|t| t.mode.is_dark() == dark)
        .expect("embedded Fluent profile");
    if let Some(font) = font {
        config.font_family = Some(font);
    }
    if let Some(ramp) = accent {
        apply_accent(&mut config, ramp, dark);
    }
    Theme::update(cx, |theme| theme.apply_config(&Rc::new(config)));
}

fn apply_accent(config: &mut ThemeConfig, ramp: AccentRamp, dark: bool) {
    let hex = |value| Some(SharedString::from(format!("#{value:06X}")));
    let base = || hex(ramp.base);
    let hover = || hex(ramp.hover);
    let active = || hex(ramp.active);
    let foreground = || hex(if dark { 0x141414 } else { 0xFFFFFF });
    let c = &mut config.colors;
    c.primary = base();
    c.primary_hover = hover();
    c.primary_active = active();
    c.primary_foreground = foreground();
    c.button_primary = base();
    c.button_primary_hover = hover();
    c.button_primary_active = active();
    c.button_primary_foreground = foreground();
    c.sidebar_primary = base();
    c.sidebar_primary_foreground = foreground();
    c.ring = base();
    c.link = base();
    c.link_hover = hover();
    c.link_active = active();
    c.drag_border = base();
    c.drop_target = Some(format!("#{:06X}33", ramp.base).into());
    c.list_active_border = base();
    c.list_highlight_foreground = base();
    c.table_active_border = base();
    c.selection = Some(format!("#{:06X}4D", ramp.base).into());
    c.progress_bar = base();
    c.slider_bar = base();
}

/// Native window options use this before creating the window. Failure to
/// establish the backdrop subsequently falls back to the opaque theme.
pub(crate) fn window_background(cx: &App) -> WindowBackgroundAppearance {
    if cx
        .try_global::<FluentChrome>()
        .is_some_and(|c| c.system.mica_requested)
    {
        WindowBackgroundAppearance::MicaBackdrop
    } else {
        WindowBackgroundAppearance::Opaque
    }
}

/// The native material is only exposed by the window's chrome, never by the
/// shared theme background or controls that rely on an opaque layer.
pub(crate) fn chrome_fill(cx: &App, fallback: Hsla) -> Hsla {
    if cx
        .try_global::<FluentChrome>()
        .is_some_and(|c| c.mica_active)
    {
        transparent_black()
    } else {
        fallback
    }
}

/// Attach to the Kit-owned root after `gpui_kit::open_window` has created it.
/// The look follows the actual window appearance (including Linux's system
/// appearance) and survives window recreation from the tray.
pub(crate) fn bind_window(window: &mut Window, cx: &mut App) {
    if !cx.has_global::<FluentChrome>() {
        return;
    }
    apply_theme(window.appearance(), cx);
    sync_material(window, cx);
    window
        .observe_window_appearance(|window, cx| {
            apply_theme(window.appearance(), cx);
            sync_material(window, cx);
        })
        .detach();
}

fn sync_material(window: &mut Window, cx: &mut App) {
    if window.root::<gpui_kit::base::Root>().flatten().is_none() {
        return;
    }
    let appearance = window_background(cx);
    window.set_background_appearance(appearance);
    #[cfg(target_os = "windows")]
    let active =
        appearance == WindowBackgroundAppearance::MicaBackdrop && windows::mica_accepted(window);
    #[cfg(not(target_os = "windows"))]
    let active = false;
    if !active && appearance != WindowBackgroundAppearance::Opaque {
        window.set_background_appearance(WindowBackgroundAppearance::Opaque);
    }
    cx.global_mut::<FluentChrome>().mica_active = active;
    // Base::Root's per-root style is refined after the Component plugin's
    // background, so this removes only the root fill, not the palette used by
    // text boxes and popovers. Clearing the override restores the theme fill.
    gpui_kit::base::Root::update(window, cx, |root, _, cx| {
        root.style().background = active.then(|| transparent_black().into());
        cx.notify();
    });
    window.refresh();
}

#[cfg(any(test, target_os = "windows"))]
fn system_style(
    snapshot: etd_sysfx_os::appearance::AppearanceSnapshot,
    direct_composition: bool,
) -> SystemStyle {
    SystemStyle {
        mica_requested: snapshot.supports_mica() && direct_composition,
        dark: snapshot.dark,
        light_accent: snapshot
            .light_accent
            .and_then(|r| readable_accent(r, false)),
        dark_accent: snapshot.dark_accent.and_then(|r| readable_accent(r, true)),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn preferred_windows_font(names: &[String]) -> Option<SharedString> {
    // DirectWrite may expose the Variable Text family rather than the umbrella
    // name, depending on the installed Windows version. Never ask GPUI for a
    // family we did not discover; leave its system default as the last resort.
    ["Segoe UI Variable", "Segoe UI Variable Text", "Segoe UI"]
        .iter()
        .find_map(|candidate| {
            names
                .iter()
                .find(|name| name.eq_ignore_ascii_case(candidate))
        })
        .map(|name| name.clone().into())
}

#[cfg(any(test, target_os = "windows"))]
fn luminance(color: u32) -> f64 {
    fn linear(channel: u32) -> f64 {
        let s = f64::from(channel) / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linear((color >> 16) & 255)
        + 0.7152 * linear((color >> 8) & 255)
        + 0.0722 * linear(color & 255)
}

#[cfg(any(test, target_os = "windows"))]
fn contrast(a: u32, b: u32) -> f64 {
    let a = luminance(a);
    let b = luminance(b);
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

#[cfg(any(test, target_os = "windows"))]
fn readable_accent(ramp: AccentRamp, dark: bool) -> Option<AccentRamp> {
    let text = if dark { 0x141414 } else { 0xFFFFFF };
    let surface = if dark { 0x2B2B2B } else { 0xF3F3F3 };
    // Use the built-in Fluent blue if a chosen OS palette is too faint for
    // either a primary button label or a link on the content surface.
    [ramp.base, ramp.hover, ramp.active]
        .iter()
        .all(|&c| contrast(c, text) >= 4.5 && contrast(c, surface) >= 4.5)
        .then_some(ramp)
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use etd_sysfx_os::appearance::{AppearanceWatch, mica_backdrop_accepted};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    fn read_style(watch: &AppearanceWatch) -> SystemStyle {
        let dcomp = !std::env::var("GPUI_DISABLE_DIRECT_COMPOSITION")
            .is_ok_and(|v| v == "1" || v == "true");
        system_style(watch.snapshot(), dcomp)
    }

    pub(super) fn mica_accepted(window: &Window) -> bool {
        let Ok(handle) = HasWindowHandle::window_handle(window) else {
            return false;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return false;
        };
        // The OS adapter only reads DWM's result. If the backend failed to set
        // Mica, keep the solid fallback instead of exposing a blank root.
        mica_backdrop_accepted(handle.hwnd)
    }

    pub(super) fn init(cx: &mut App) {
        let font = preferred_windows_font(&cx.text_system().all_font_names());
        cx.global_mut::<FluentChrome>().font = font;
        // Native callbacks may arrive off the GPUI thread. Only signal from
        // the adapter; all UI mutations happen in the foreground task.
        let (tx, rx) = async_channel::bounded(1);
        let Some(watch) = AppearanceWatch::new(move || {
            let _ = tx.try_send(());
        }) else {
            apply_theme(cx.window_appearance(), cx);
            return;
        };
        cx.global_mut::<FluentChrome>().system = read_style(&watch);
        apply_theme(cx.window_appearance(), cx);
        cx.spawn(async move |cx| {
            let watch = watch;
            while rx.recv().await.is_ok() {
                let next = read_style(&watch);
                cx.update(|cx| {
                    let previous = cx.global::<FluentChrome>().system;
                    if previous == next {
                        return;
                    }
                    cx.global_mut::<FluentChrome>().system = next;
                    apply_theme(cx.window_appearance(), cx);
                    if previous.mica_requested != next.mica_requested {
                        for handle in cx.windows() {
                            let _ = handle.update(cx, |_, window, cx| sync_material(window, cx));
                        }
                    }
                });
            }
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_kit::{TestAppContext, px, rgb};

    #[test]
    fn mica_policy_conservatively_falls_back() {
        use etd_sysfx_os::appearance::AppearanceSnapshot;
        let supported = AppearanceSnapshot {
            windows_build: Some(22621),
            transparency: Some(true),
            ..Default::default()
        };
        assert!(system_style(supported, true).mica_requested);
        assert!(!system_style(supported, false).mica_requested);
        assert!(!system_style(AppearanceSnapshot::default(), true).mica_requested);
    }

    #[test]
    fn windows_font_selection_prefers_installed_variable_family() {
        assert_eq!(
            preferred_windows_font(&["Segoe UI".into(), "Segoe UI Variable Text".into()])
                .unwrap()
                .as_ref(),
            "Segoe UI Variable Text"
        );
        assert_eq!(
            preferred_windows_font(&["Segoe UI".into()])
                .unwrap()
                .as_ref(),
            "Segoe UI"
        );
        assert!(preferred_windows_font(&["Arial".into()]).is_none());
    }

    #[test]
    fn accent_requires_readable_text_in_both_uses() {
        assert!(
            readable_accent(
                AccentRamp {
                    base: 0x005FB8,
                    hover: 0x005FB8,
                    active: 0x004C96
                },
                false
            )
            .is_some()
        );
        assert!(
            readable_accent(
                AccentRamp {
                    base: 0xFAFAFA,
                    hover: 0xFFFFFF,
                    active: 0xEEEEEE
                },
                false
            )
            .is_none()
        );
        assert!(
            readable_accent(
                AccentRamp {
                    base: 0x60CDFF,
                    hover: 0x79D5FF,
                    active: 0x49B9ED
                },
                true
            )
            .is_some()
        );
    }

    #[gpui_kit::test]
    fn palette_changes_between_light_and_dark_with_solid_fallback(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            install_palette(cx);
            for (appearance, name, hue) in [
                (WindowAppearance::Light, "EasyTier Fluent Light", 0x005FB8),
                (WindowAppearance::Dark, "EasyTier Fluent Dark", 0x60CDFF),
            ] {
                apply_theme(appearance, cx);
                let t = Theme::global(cx);
                assert_eq!(t.theme_name().as_ref(), name);
                assert_eq!(t.radius, px(4.));
                assert_eq!(t.radius_lg, px(8.));
                assert!(!t.shadow);
                assert_eq!(t.primary, Hsla::from(rgb(hue)));
                assert_eq!(t.background.a, 1.0);
                assert_eq!(t.popover.a, 1.0);
                assert_eq!(chrome_fill(cx, t.background), t.background);
                assert_eq!(window_background(cx), WindowBackgroundAppearance::Opaque);
            }
        });
    }
}

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
    rgba, transparent_black,
};

use crate::{
    assets::app_icons::TraySize,
    preferences::{ThemePreference, UiPreferencesStore},
};

const PALETTE: &str = include_str!("../assets/fluent-theme.json");
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SystemStyle {
    mica_requested: bool,
    dark: Option<bool>,
    taskbar_dark: Option<bool>,
    tray_icon_px: Option<u32>,
    light_accent: Option<AccentRamp>,
    dark_accent: Option<AccentRamp>,
}

#[derive(Default)]
struct FluentChrome {
    system: SystemStyle,
    font: Option<SharedString>,
    mica_active: bool,
    preference: ThemePreference,
    preferences: Option<UiPreferencesStore>,
    preference_save_failed: bool,
    preference_path_unavailable: bool,
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
    let store = UiPreferencesStore::default_store();
    let preference = store
        .as_ref()
        .map(|store| {
            store.load().unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "Could not read UI preferences; following system");
            ThemePreference::default()
        })
        })
        .unwrap_or_default();
    let chrome = cx.global_mut::<FluentChrome>();
    chrome.preference = preference;
    chrome.preference_path_unavailable = store.is_none();
    chrome.preferences = store;
    set_native_preference(preference, cx);
    apply_theme(cx.window_appearance(), cx);
    #[cfg(target_os = "windows")]
    windows::init(cx);
}

/// The standalone component gallery follows the same appearance machinery,
/// but never opens or mutates the product's UI preference file.
pub(crate) fn init_gallery(preference: ThemePreference, cx: &mut App) {
    install_palette(cx);
    cx.global_mut::<FluentChrome>().preference = preference;
    set_native_preference(preference, cx);
    apply_theme(cx.window_appearance(), cx);
    #[cfg(target_os = "windows")]
    windows::init(cx);
}

pub(crate) fn preference(cx: &App) -> ThemePreference {
    cx.try_global::<FluentChrome>()
        .map(|chrome| chrome.preference)
        .unwrap_or_default()
}

pub(crate) fn preference_save_failed(cx: &App) -> bool {
    cx.try_global::<FluentChrome>()
        .is_some_and(|chrome| chrome.preference_save_failed)
}

fn set_native_preference(preference: ThemePreference, cx: &App) {
    // On macOS this toggles the application's native appearance override.
    // GPUI's Windows implementation is a no-op; see sync_material instead.
    cx.set_window_appearance(match preference {
        ThemePreference::FollowSystem => None,
        ThemePreference::Light => Some(WindowAppearance::Light),
        ThemePreference::Dark => Some(WindowAppearance::Dark),
    });
}

pub(crate) fn set_preference(preference: ThemePreference, window: &mut Window, cx: &mut App) {
    let chrome = cx.global_mut::<FluentChrome>();
    chrome.preference = preference;
    // Only production init connects a store, so the headless palette is
    // completely isolated from the user's real preference file.
    chrome.preference_save_failed = chrome.preference_path_unavailable
        || chrome
            .preferences
            .as_ref()
            .is_some_and(|store| match store.save(preference) {
                Ok(()) => false,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "Could not save UI preferences");
                    true
                }
            });
    set_native_preference(preference, cx);
    // macOS's app appearance changes immediately, whereas its window's
    // appearance callback may arrive later. Linux needs the window value.
    let appearance = if cfg!(target_os = "macos") {
        cx.window_appearance()
    } else {
        window.appearance()
    };
    apply_theme(appearance, cx);
    sync_material(window, cx);
}

fn apply_theme(appearance: WindowAppearance, cx: &mut App) {
    if !cx.has_global::<FluentChrome>() {
        return;
    }
    let chrome = cx.global::<FluentChrome>();
    let dark = chrome.preference.is_dark(
        chrome
            .system
            .dark
            .unwrap_or(ThemeMode::from(appearance).is_dark()),
    );
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
    Theme::update(cx, |theme| {
        theme.apply_config(&Rc::new(config));
        theme.focus_ring = false;
    });
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
    c.list_active = Some(format!("#{:06X}33", ramp.base).into());
    c.table_active = Some(format!("#{:06X}33", ramp.base).into());
    c.accent = Some(format!("#{:06X}1A", ramp.base).into());
    c.sidebar_accent = c.accent.clone();
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

/// WinUI surface brushes from `Common_themeresources_any.xaml`, as
/// `0xRRGGBBAA` for (light, dark). Translucent values are painted as-is so
/// they composite over whatever layer is really below them, as in XAML.
fn winui_brush(cx: &App, light: u32, dark: u32) -> Hsla {
    rgba(if Theme::global(cx).is_dark() {
        dark
    } else {
        light
    })
    .into()
}

/// NavigationView content area: `LayerFillColorDefault` (#80FFFFFF /
/// #4C3A3A3A) resolved over `SolidBackgroundFillColorBase` (#F3F3F3 /
/// #202020). Kept opaque so Mica stays limited to the window chrome.
pub(crate) fn content_layer(cx: &App) -> Hsla {
    winui_brush(cx, 0xF9F9F9FF, 0x282828FF)
}

/// `CardBackgroundFillColorDefault` (#B3FFFFFF / #0DFFFFFF): cards and
/// grouped sections sit slightly above the content layer, never below it.
pub(crate) fn card_fill(cx: &App) -> Hsla {
    winui_brush(cx, 0xFFFFFFB3, 0xFFFFFF0D)
}

/// `CardStrokeColorDefault` (#0F000000 / #19000000), also the
/// NavigationView content grid border.
pub(crate) fn card_stroke(cx: &App) -> Hsla {
    winui_brush(cx, 0x0000000F, 0x00000019)
}

/// `SubtleFillColorSecondary` (#09000000 / #0FFFFFFF): navigation and list
/// rows when hovered or selected.
pub(crate) fn subtle_fill_secondary(cx: &App) -> Hsla {
    winui_brush(cx, 0x00000009, 0xFFFFFF0F)
}

/// `SubtleFillColorTertiary` (#06000000 / #0AFFFFFF): the same rows pressed.
pub(crate) fn subtle_fill_tertiary(cx: &App) -> Hsla {
    winui_brush(cx, 0x00000006, 0xFFFFFF0A)
}

/// TextBox fill: `TextControlBackground` = `ControlFillColorDefault`
/// (#B3FFFFFF / #0FFFFFFF), focused `ControlFillColorInputActive` (#FFFFFF /
/// #B31E1E1E), disabled `ControlFillColorDisabled` (#4DF9F9F9 / #0BFFFFFF).
pub(crate) fn text_control_fill(focused: bool, disabled: bool, cx: &App) -> Hsla {
    if disabled {
        winui_brush(cx, 0xF9F9F94D, 0xFFFFFF0B)
    } else if focused {
        winui_brush(cx, 0xFFFFFFFF, 0x1E1E1EB3)
    } else {
        winui_brush(cx, 0xFFFFFFB3, 0xFFFFFF0F)
    }
}

/// Attach to the Kit-owned root after `gpui_kit::open_window` has created it.
/// The look follows the actual window appearance (including Linux's system
/// appearance) and survives window recreation from the tray.
pub(crate) fn bind_window(window: &mut Window, cx: &mut App) {
    if !cx.has_global::<FluentChrome>() {
        return;
    }
    #[cfg(target_os = "windows")]
    windows::set_window_icon(window);
    sync_tray_for_window(window);
    apply_theme(window.appearance(), cx);
    sync_material(window, cx);
    window
        .observe_window_appearance(|window, cx| {
            sync_tray_for_window(window);
            apply_theme(window.appearance(), cx);
            sync_material(window, cx);
        })
        .detach();
}

fn sync_tray_for_window(window: &Window) {
    let size = Some(TraySize::for_scale_factor(window.scale_factor()));
    // On Windows the taskbar theme comes from HKCU SystemUsesLightTheme via
    // `AppearanceWatch`, not from the app window appearance.
    #[cfg(target_os = "windows")]
    let taskbar_dark = None;
    #[cfg(not(target_os = "windows"))]
    let taskbar_dark = Some(ThemeMode::from(window.appearance()).is_dark());
    crate::tray::update_system_tray_appearance(taskbar_dark, size);
}

#[cfg(any(test, target_os = "windows"))]
fn material_after_native_mode(
    requested: WindowBackgroundAppearance,
    native_mode_applied: bool,
) -> WindowBackgroundAppearance {
    if native_mode_applied {
        requested
    } else {
        WindowBackgroundAppearance::Opaque
    }
}

fn sync_material(window: &mut Window, cx: &mut App) {
    if window.root::<gpui_kit::base::Root>().flatten().is_none() {
        return;
    }
    let appearance = window_background(cx);
    #[cfg(target_os = "windows")]
    let appearance = material_after_native_mode(
        appearance,
        windows::set_dark_mode(window, Theme::global(cx).is_dark()),
    );
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
        taskbar_dark: snapshot.taskbar_dark.or(snapshot.dark),
        tray_icon_px: snapshot.tray_icon_px,
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
pub(crate) fn contrast(a: u32, b: u32) -> f64 {
    let a = luminance(a);
    let b = luminance(b);
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

#[cfg(any(test, target_os = "windows"))]
fn readable_accent(ramp: AccentRamp, dark: bool) -> Option<AccentRamp> {
    let text = if dark { 0x141414 } else { 0xFFFFFF };
    let surface = if dark { 0x2B2B2B } else { 0xFFFFFF };
    // Base also serves as link text, so require AA on the content surface.
    // Hover/active fills must keep their button labels readable; their
    // distinction from the surrounding surface only needs 3:1.
    (contrast(ramp.base, text) >= 4.5
        && contrast(ramp.base, surface) >= 4.5
        && [ramp.hover, ramp.active]
            .iter()
            .all(|&c| contrast(c, text) >= 4.5 && contrast(c, surface) >= 3.0))
    .then_some(ramp)
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use etd_sysfx_os::appearance::{
        AppearanceWatch, mica_backdrop_accepted, set_window_dark_mode,
        set_window_icon_from_resource,
    };
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    const APP_ICON_RESOURCE_ID: u16 = 1;

    fn read_style(watch: &AppearanceWatch) -> SystemStyle {
        let dcomp = !std::env::var("GPUI_DISABLE_DIRECT_COMPOSITION")
            .is_ok_and(|v| v == "1" || v == "true");
        system_style(watch.snapshot(), dcomp)
    }

    fn sync_tray_appearance(style: SystemStyle) {
        crate::tray::update_system_tray_appearance(
            style.taskbar_dark,
            style.tray_icon_px.map(TraySize::for_icon_px),
        );
    }

    pub(super) fn set_window_icon(window: &Window) {
        let Ok(handle) = HasWindowHandle::window_handle(window) else {
            return;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return;
        };
        let _ = set_window_icon_from_resource(handle.hwnd, APP_ICON_RESOURCE_ID);
    }

    pub(super) fn set_dark_mode(window: &Window, dark: bool) -> bool {
        let Ok(handle) = HasWindowHandle::window_handle(window) else {
            return false;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return false;
        };
        set_window_dark_mode(handle.hwnd, dark)
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
        let initial = read_style(&watch);
        cx.global_mut::<FluentChrome>().system = initial;
        sync_tray_appearance(initial);
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
                    if previous.taskbar_dark != next.taskbar_dark
                        || previous.tray_icon_px != next.tray_icon_px
                    {
                        sync_tray_appearance(next);
                    }
                    apply_theme(cx.window_appearance(), cx);
                    if previous.mica_requested != next.mica_requested || previous.dark != next.dark
                    {
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
    fn native_mode_failure_disables_mica() {
        use WindowBackgroundAppearance::{MicaBackdrop, Opaque};
        assert_eq!(material_after_native_mode(MicaBackdrop, false), Opaque);
        assert_eq!(material_after_native_mode(MicaBackdrop, true), MicaBackdrop);
        assert_eq!(material_after_native_mode(Opaque, true), Opaque);
        assert_eq!(material_after_native_mode(Opaque, false), Opaque);
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

    fn rgb24(color: gpui_kit::Rgba) -> u32 {
        let byte = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u32;
        byte(color.r) << 16 | byte(color.g) << 8 | byte(color.b)
    }

    fn assert_readable(label: &str, text: Hsla, background: gpui_kit::Rgba) {
        let ratio = contrast(rgb24(text.to_rgb()), rgb24(background));
        assert!(
            ratio >= 4.5,
            "{label}: {ratio:.2}:1 is below AA (text {text:?}, background {background:?})"
        );
    }

    #[gpui_kit::test]
    fn badge_and_input_text_pairs_meet_aa_in_both_modes(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            install_palette(cx);
            for appearance in [WindowAppearance::Light, WindowAppearance::Dark] {
                apply_theme(appearance, cx);
                let t = Theme::global(cx);
                let surface = content_layer(cx).to_rgb();
                let normal_card = surface.blend(card_fill(cx).to_rgb());
                let selected_card = normal_card.blend(t.primary.opacity(0.08).to_rgb());
                // The selected card may use any readable OS accent. Include
                // the worst luminance extreme, not just the default blue.
                let extreme: Hsla = rgb(if t.is_dark() { 0xFFFFFF } else { 0x000000 }).into();
                let extreme_card = normal_card.blend(extreme.opacity(0.08).to_rgb());
                let base = t.background.to_rgb();
                let parents = [
                    base,
                    surface,
                    t.title_bar.to_rgb(),
                    normal_card,
                    selected_card,
                    extreme_card,
                ];
                // Neutral badge and tinted success/error/waiting badges are
                // the exact pairs in render_instance_card/render_header.
                assert_readable(
                    "neutral badge",
                    t.secondary_foreground,
                    t.secondary.to_rgb(),
                );
                // The header's no-tray pill is opaque: popover plus 20% warning.
                assert_readable(
                    "no-tray badge",
                    t.warning,
                    t.popover.to_rgb().blend(t.warning.opacity(0.2).to_rgb()),
                );
                for parent in parents {
                    for (name, semantic) in [
                        ("success badge", t.success),
                        ("danger badge", t.danger),
                        ("warning badge", t.warning),
                    ] {
                        assert_readable(
                            name,
                            semantic,
                            parent.blend(semantic.opacity(0.15).to_rgb()),
                        );
                    }
                    // FluentInput paints the WinUI TextControlBackground
                    // states over whichever surface holds the field.
                    let enabled = parent.blend(text_control_fill(false, false, cx).to_rgb());
                    let focused = parent.blend(text_control_fill(true, false, cx).to_rgb());
                    let disabled = parent.blend(text_control_fill(false, true, cx).to_rgb());
                    assert_readable("enabled input", t.foreground, enabled);
                    assert_readable("focused input", t.foreground, focused);
                    assert_readable("input placeholder", t.muted_foreground, enabled);
                    assert_readable("disabled input", t.muted_foreground, disabled);
                    assert_readable(
                        "selected input text",
                        t.foreground,
                        enabled.blend(t.selection.to_rgb()),
                    );
                }
                assert_readable(
                    "header warning pill",
                    t.warning,
                    surface.blend(t.warning.opacity(0.2).to_rgb()),
                );
                assert_readable("editor text", t.foreground, surface);
                assert_readable("editor placeholder", t.muted_foreground, surface);
            }
        });
    }

    #[gpui_kit::test]
    fn system_accent_tints_survive_kit_alpha_clamping(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            install_palette(cx);
            let ramp = AccentRamp {
                base: 0x006822,
                hover: 0x006022,
                active: 0x00551B,
            };
            cx.global_mut::<FluentChrome>().system.light_accent = Some(ramp);
            apply_theme(WindowAppearance::Light, cx);
            let t = Theme::global(cx);
            assert_eq!(rgb24(t.primary.to_rgb()), ramp.base);
            for fill in [t.list_active, t.table_active] {
                assert_eq!(rgb24(fill.to_rgb()), ramp.base);
                assert!(fill.a > 0.19 && fill.a <= 0.2);
            }
            for fill in [t.accent, t.sidebar_accent] {
                assert_eq!(rgb24(fill.to_rgb()), ramp.base);
                assert!(fill.a > 0.09 && fill.a < 0.12);
            }
        });
    }

    #[gpui_kit::test]
    fn manual_theme_ignores_system_mode_but_uses_live_accent(cx: &mut TestAppContext) {
        cx.update(|cx| {
            gpui_kit::init(cx);
            install_palette(cx);
            let light = AccentRamp {
                base: 0x006822,
                hover: 0x006022,
                active: 0x00551B,
            };
            let dark = AccentRamp {
                base: 0x60CDFF,
                hover: 0x79D5FF,
                active: 0x49B9ED,
            };
            let chrome = cx.global_mut::<FluentChrome>();
            chrome.system = SystemStyle {
                dark: Some(false),
                light_accent: Some(light),
                dark_accent: Some(dark),
                ..Default::default()
            };
            chrome.preference = ThemePreference::Dark;
            apply_theme(WindowAppearance::Light, cx);
            assert!(Theme::global(cx).is_dark());
            assert_eq!(rgb24(Theme::global(cx).primary.to_rgb()), dark.base);
            // An OS accent change while manually dark reprojects the dark ramp.
            let new_dark = AccentRamp {
                base: 0x78D46B,
                ..dark
            };
            cx.global_mut::<FluentChrome>().system.dark_accent = Some(new_dark);
            apply_theme(WindowAppearance::Light, cx);
            assert_eq!(rgb24(Theme::global(cx).primary.to_rgb()), new_dark.base);
            let chrome = cx.global_mut::<FluentChrome>();
            chrome.system.dark = Some(true);
            chrome.preference = ThemePreference::Light;
            apply_theme(WindowAppearance::Dark, cx);
            assert!(!Theme::global(cx).is_dark());
            assert_eq!(rgb24(Theme::global(cx).primary.to_rgb()), light.base);
            cx.global_mut::<FluentChrome>().preference = ThemePreference::FollowSystem;
            apply_theme(WindowAppearance::Dark, cx);
            assert!(Theme::global(cx).is_dark());
            assert_eq!(rgb24(Theme::global(cx).primary.to_rgb()), new_dark.base);
            cx.global_mut::<FluentChrome>().system.dark = Some(false);
            apply_theme(WindowAppearance::Light, cx);
            assert!(!Theme::global(cx).is_dark());
        });
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

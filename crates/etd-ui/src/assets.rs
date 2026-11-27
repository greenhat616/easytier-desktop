//! Embedded Fluent System Icons (MIT), composed with GPUI Kit's default assets.
//!
//! The original upstream files and license/attribution are in `assets/fluent`.
//! All other Kit assets retain their original lookup behavior.

use std::borrow::Cow;

use gpui_kit::{AssetSource, Result, SharedString};

#[derive(Clone, Copy, Default)]
pub struct FluentAssets;

const FLUENT: &[(&str, &[u8])] = &[
    ("add.svg", include_bytes!("../assets/fluent/add.svg")),
    (
        "arrow-clockwise.svg",
        include_bytes!("../assets/fluent/arrow-clockwise.svg"),
    ),
    (
        "arrow-counterclockwise.svg",
        include_bytes!("../assets/fluent/arrow-counterclockwise.svg"),
    ),
    (
        "arrow-download.svg",
        include_bytes!("../assets/fluent/arrow-download.svg"),
    ),
    (
        "arrow-left.svg",
        include_bytes!("../assets/fluent/arrow-left.svg"),
    ),
    (
        "arrow-right.svg",
        include_bytes!("../assets/fluent/arrow-right.svg"),
    ),
    (
        "arrow-sync.svg",
        include_bytes!("../assets/fluent/arrow-sync.svg"),
    ),
    (
        "arrow-upload.svg",
        include_bytes!("../assets/fluent/arrow-upload.svg"),
    ),
    (
        "checkmark-circle.svg",
        include_bytes!("../assets/fluent/checkmark-circle.svg"),
    ),
    (
        "checkmark.svg",
        include_bytes!("../assets/fluent/checkmark.svg"),
    ),
    (
        "chevron-down.svg",
        include_bytes!("../assets/fluent/chevron-down.svg"),
    ),
    (
        "chevron-left.svg",
        include_bytes!("../assets/fluent/chevron-left.svg"),
    ),
    (
        "chevron-right.svg",
        include_bytes!("../assets/fluent/chevron-right.svg"),
    ),
    (
        "chevron-up.svg",
        include_bytes!("../assets/fluent/chevron-up.svg"),
    ),
    ("copy.svg", include_bytes!("../assets/fluent/copy.svg")),
    ("delete.svg", include_bytes!("../assets/fluent/delete.svg")),
    (
        "dismiss.svg",
        include_bytes!("../assets/fluent/dismiss.svg"),
    ),
    (
        "document.svg",
        include_bytes!("../assets/fluent/document.svg"),
    ),
    ("edit.svg", include_bytes!("../assets/fluent/edit.svg")),
    (
        "error-circle.svg",
        include_bytes!("../assets/fluent/error-circle.svg"),
    ),
    (
        "eye-off.svg",
        include_bytes!("../assets/fluent/eye-off.svg"),
    ),
    ("eye.svg", include_bytes!("../assets/fluent/eye.svg")),
    ("folder.svg", include_bytes!("../assets/fluent/folder.svg")),
    (
        "error-circle-filled.svg",
        include_bytes!("../assets/fluent/error-circle-filled.svg"),
    ),
    (
        "warning-filled.svg",
        include_bytes!("../assets/fluent/warning-filled.svg"),
    ),
    (
        "checkmark-circle-filled.svg",
        include_bytes!("../assets/fluent/checkmark-circle-filled.svg"),
    ),
    (
        "info-filled.svg",
        include_bytes!("../assets/fluent/info-filled.svg"),
    ),
    (
        "navigation.svg",
        include_bytes!("../assets/fluent/navigation.svg"),
    ),
    (
        "dismiss-circle-filled.svg",
        include_bytes!("../assets/fluent/dismiss-circle-filled.svg"),
    ),
    ("color.svg", include_bytes!("../assets/fluent/color.svg")),
    ("grid.svg", include_bytes!("../assets/fluent/grid.svg")),
    (
        "panel-left.svg",
        include_bytes!("../assets/fluent/panel-left.svg"),
    ),
    (
        "speaker-2.svg",
        include_bytes!("../assets/fluent/speaker-2.svg"),
    ),
    ("globe.svg", include_bytes!("../assets/fluent/globe.svg")),
    (
        "globe-filled.svg",
        include_bytes!("../assets/fluent/globe-filled.svg"),
    ),
    ("info.svg", include_bytes!("../assets/fluent/info.svg")),
    (
        "link-dismiss.svg",
        include_bytes!("../assets/fluent/link-dismiss.svg"),
    ),
    ("link.svg", include_bytes!("../assets/fluent/link.svg")),
    (
        "more-horizontal.svg",
        include_bytes!("../assets/fluent/more-horizontal.svg"),
    ),
    (
        "network-check.svg",
        include_bytes!("../assets/fluent/network-check.svg"),
    ),
    ("person.svg", include_bytes!("../assets/fluent/person.svg")),
    ("play.svg", include_bytes!("../assets/fluent/play.svg")),
    ("search.svg", include_bytes!("../assets/fluent/search.svg")),
    ("server.svg", include_bytes!("../assets/fluent/server.svg")),
    (
        "settings.svg",
        include_bytes!("../assets/fluent/settings.svg"),
    ),
    ("shield.svg", include_bytes!("../assets/fluent/shield.svg")),
    (
        "shield-filled.svg",
        include_bytes!("../assets/fluent/shield-filled.svg"),
    ),
    (
        "sign-out.svg",
        include_bytes!("../assets/fluent/sign-out.svg"),
    ),
    ("stop.svg", include_bytes!("../assets/fluent/stop.svg")),
    (
        "subtract.svg",
        include_bytes!("../assets/fluent/subtract.svg"),
    ),
    (
        "warning.svg",
        include_bytes!("../assets/fluent/warning.svg"),
    ),
    (
        "LICENSE.txt",
        include_bytes!("../assets/fluent/LICENSE.txt"),
    ),
];

fn fluent_name(path: &str) -> Option<&str> {
    if let Some(name) = path.strip_prefix("fluent/") {
        return Some(name);
    }
    // Override the matching Kit icons, including Input's mask toggle.
    let name = path.strip_prefix("icons/")?;
    Some(match name {
        "check.svg" => "checkmark.svg",
        "x.svg" => "dismiss.svg",
        "plus.svg" => "add.svg",
        "minus.svg" => "subtract.svg",
        "refresh-cw.svg" => "arrow-clockwise.svg",
        "refresh-ccw.svg" => "arrow-counterclockwise.svg",
        "download.svg" => "arrow-download.svg",
        "upload.svg" => "arrow-upload.svg",
        "ellipsis.svg" => "more-horizontal.svg",
        "circle-check.svg" => "checkmark-circle.svg",
        "circle-alert.svg" | "circle-x.svg" => "error-circle.svg",
        "alert-triangle.svg" => "warning.svg",
        "unlink.svg" => "link-dismiss.svg",
        "user.svg" => "person.svg",
        "log-out.svg" => "sign-out.svg",
        "trash.svg" | "trash-2.svg" => "delete.svg",
        "pencil.svg" => "edit.svg",
        "file.svg" => "document.svg",
        _ => name,
    })
}

impl AssetSource for FluentAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(name) = fluent_name(path)
            && let Some((_, bytes)) = FLUENT.iter().find(|(candidate, _)| *candidate == name)
        {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(FLUENT.iter().filter_map(|(name, _)| {
            let name = format!("fluent/{name}");
            name.starts_with(path).then(|| name.into())
        }));
        paths.sort_unstable();
        paths.dedup();
        Ok(paths)
    }
}

/// Embedded Triad application and tray icon PNGs generated from
/// `packaging/assets/icons/` (see `packaging/assets/README.md`).
pub mod app_icons {
    use std::sync::Arc;

    use etd_app::TrayIndicator;

    /// Desktop/taskbar appearance variant for the monochrome tray glyph.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TrayTheme {
        /// Dark ink (`#1B1B1B`) for light taskbars (and macOS template images).
        Light,
        /// White ink (`#FFFFFF`) for dark taskbars.
        Dark,
    }

    impl TrayTheme {
        pub fn from_taskbar_dark(dark: bool) -> Self {
            if dark { Self::Dark } else { Self::Light }
        }
    }

    /// Pixel-aligned tray raster size chosen from system DPI / scale factor.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TraySize {
        Px16,
        Px24,
    }

    impl TraySize {
        pub const fn px(self) -> u32 {
            match self {
                Self::Px16 => 16,
                Self::Px24 => 24,
            }
        }

        /// Pick 24px whenever the OS small-icon metric is 20px or larger
        /// (125% / 120 DPI and above on Windows), and 16px at 100% DPI.
        pub const fn for_icon_px(icon_px: u32) -> Self {
            if icon_px >= 20 {
                Self::Px24
            } else {
                Self::Px16
            }
        }

        /// Pick 24px for HiDPI scale factors (>= 1.25x) and 16px for 1x.
        pub fn for_scale_factor(scale_factor: f32) -> Self {
            if scale_factor >= 1.25 {
                Self::Px24
            } else {
                Self::Px16
            }
        }
    }

    /// Triad tray state variants corresponding to the three pixel-aligned glyphs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TrayVisualState {
        Connected,
        Connecting,
        Disconnected,
    }

    impl TrayVisualState {
        /// Map [`TrayIndicator`] to the three Triad tray glyphs:
        /// - `Connected` -> solid nodes + struts (`connected`)
        /// - `Attention` -> solid nodes + broken struts (`connecting`)
        /// - `Idle` / `Error` -> hollow rings (`disconnected`)
        pub fn from_indicator(indicator: TrayIndicator) -> Self {
            match indicator {
                TrayIndicator::Connected => Self::Connected,
                TrayIndicator::Attention => Self::Connecting,
                TrayIndicator::Idle | TrayIndicator::Error => Self::Disconnected,
                _ => Self::Disconnected,
            }
        }
    }

    const APP_ICON_64_PNG: &[u8] = include_bytes!("../../../packaging/assets/icons/png/app-64.png");

    const TRAY_LIGHT_16_CONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-16-connected.png");
    const TRAY_LIGHT_16_CONNECTING: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-16-connecting.png");
    const TRAY_LIGHT_16_DISCONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-16-disconnected.png");
    const TRAY_LIGHT_24_CONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-24-connected.png");
    const TRAY_LIGHT_24_CONNECTING: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-24-connecting.png");
    const TRAY_LIGHT_24_DISCONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/light-24-disconnected.png");

    const TRAY_DARK_16_CONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-16-connected.png");
    const TRAY_DARK_16_CONNECTING: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-16-connecting.png");
    const TRAY_DARK_16_DISCONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-16-disconnected.png");
    const TRAY_DARK_24_CONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-24-connected.png");
    const TRAY_DARK_24_CONNECTING: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-24-connecting.png");
    const TRAY_DARK_24_DISCONNECTED: &[u8] =
        include_bytes!("../../../packaging/assets/icons/tray/dark-24-disconnected.png");

    /// Return the embedded PNG bytes for a tray theme, size, and state.
    pub const fn tray_icon_png(
        theme: TrayTheme,
        size: TraySize,
        state: TrayVisualState,
    ) -> &'static [u8] {
        match (theme, size, state) {
            (TrayTheme::Light, TraySize::Px16, TrayVisualState::Connected) => {
                TRAY_LIGHT_16_CONNECTED
            }
            (TrayTheme::Light, TraySize::Px16, TrayVisualState::Connecting) => {
                TRAY_LIGHT_16_CONNECTING
            }
            (TrayTheme::Light, TraySize::Px16, TrayVisualState::Disconnected) => {
                TRAY_LIGHT_16_DISCONNECTED
            }
            (TrayTheme::Light, TraySize::Px24, TrayVisualState::Connected) => {
                TRAY_LIGHT_24_CONNECTED
            }
            (TrayTheme::Light, TraySize::Px24, TrayVisualState::Connecting) => {
                TRAY_LIGHT_24_CONNECTING
            }
            (TrayTheme::Light, TraySize::Px24, TrayVisualState::Disconnected) => {
                TRAY_LIGHT_24_DISCONNECTED
            }
            (TrayTheme::Dark, TraySize::Px16, TrayVisualState::Connected) => TRAY_DARK_16_CONNECTED,
            (TrayTheme::Dark, TraySize::Px16, TrayVisualState::Connecting) => {
                TRAY_DARK_16_CONNECTING
            }
            (TrayTheme::Dark, TraySize::Px16, TrayVisualState::Disconnected) => {
                TRAY_DARK_16_DISCONNECTED
            }
            (TrayTheme::Dark, TraySize::Px24, TrayVisualState::Connected) => TRAY_DARK_24_CONNECTED,
            (TrayTheme::Dark, TraySize::Px24, TrayVisualState::Connecting) => {
                TRAY_DARK_24_CONNECTING
            }
            (TrayTheme::Dark, TraySize::Px24, TrayVisualState::Disconnected) => {
                TRAY_DARK_24_DISCONNECTED
            }
        }
    }

    fn decode_embedded_png(bytes: &'static [u8]) -> image::RgbaImage {
        image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
            .expect("embedded Triad PNG asset is valid")
            .into_rgba8()
    }

    /// Decode an embedded Triad tray icon to `(width, height, rgba_bytes)`.
    pub fn tray_icon_rgba(
        theme: TrayTheme,
        size: TraySize,
        state: TrayVisualState,
    ) -> (u32, u32, Vec<u8>) {
        let img = decode_embedded_png(tray_icon_png(theme, size, state));
        let (w, h) = img.dimensions();
        debug_assert_eq!(w, size.px());
        debug_assert_eq!(h, size.px());
        (w, h, img.into_raw())
    }

    /// Decode the 64x64 Triad app icon for GPUI window options (`_NET_WM_ICON` on X11).
    pub fn window_icon_rgba() -> Arc<image::RgbaImage> {
        Arc::new(decode_embedded_png(APP_ICON_64_PNG))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composed_assets_override_kit_icons_and_keep_fallbacks() {
        let assets = FluentAssets;
        let fluent = assets.load("fluent/eye.svg").unwrap().unwrap();
        assert_eq!(assets.load("icons/eye.svg").unwrap().unwrap(), fluent);
        assert_eq!(
            assets.load("icons/plus.svg").unwrap(),
            assets.load("fluent/add.svg").unwrap()
        );
        let original = gpui_kit::assets::Assets
            .load("icons/eye.svg")
            .unwrap()
            .unwrap();
        assert_ne!(fluent, original);
        // Exercise an actual fallback path from Kit rather than assuming a
        // particular optional Lucide glyph is in the default bundle.
        let fallback = gpui_kit::assets::Assets
            .list("icons/")
            .unwrap()
            .into_iter()
            .find(|p| fluent_name(p).is_none_or(|n| !FLUENT.iter().any(|(f, _)| *f == n)))
            .expect("Kit contains icons outside the Fluent subset");
        assert_eq!(
            assets.load(&fallback).unwrap(),
            gpui_kit::assets::Assets.load(&fallback).unwrap()
        );
        assert!(
            assets
                .list("fluent/")
                .unwrap()
                .iter()
                .any(|p| p.as_ref() == "fluent/LICENSE.txt")
        );
    }

    #[test]
    fn triad_app_and_tray_pngs_decode_with_expected_dimensions() {
        use super::app_icons::*;

        let window_icon = window_icon_rgba();
        assert_eq!(window_icon.dimensions(), (64, 64));
        assert!(
            window_icon
                .as_raw()
                .as_chunks::<4>()
                .0
                .iter()
                .any(|px| px[3] > 0)
        );

        for theme in [TrayTheme::Light, TrayTheme::Dark] {
            for size in [TraySize::Px16, TraySize::Px24] {
                let connected = tray_icon_rgba(theme, size, TrayVisualState::Connected);
                let connecting = tray_icon_rgba(theme, size, TrayVisualState::Connecting);
                let disconnected = tray_icon_rgba(theme, size, TrayVisualState::Disconnected);
                for (w, h, rgba) in [&connected, &connecting, &disconnected] {
                    assert_eq!((*w, *h), (size.px(), size.px()));
                    assert_eq!(rgba.len(), (w * h * 4) as usize);
                    assert!(rgba.as_chunks::<4>().0.iter().any(|px| px[3] > 0));
                }
                assert_ne!(connected.2, connecting.2);
                assert_ne!(connecting.2, disconnected.2);
                assert_ne!(connected.2, disconnected.2);
            }
        }

        // Light and dark variants must use distinct ink colors.
        assert_ne!(
            tray_icon_rgba(TrayTheme::Light, TraySize::Px16, TrayVisualState::Connected).2,
            tray_icon_rgba(TrayTheme::Dark, TraySize::Px16, TrayVisualState::Connected).2
        );
    }
}

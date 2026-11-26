//! Read-only Windows appearance settings and DWM acknowledgement. Neither
//! system settings nor window attributes are written by this adapter.

use std::{num::NonZeroIsize, sync::Arc};

use ::windows::{
    Foundation::TypedEventHandler,
    UI::{
        Color,
        ViewManagement::{UIColorType, UISettings},
    },
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::HWND,
        Graphics::Dwm::{
            DWM_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW, DWMWA_SYSTEMBACKDROP_TYPE,
            DwmGetWindowAttribute,
        },
        System::SystemInformation::OSVERSIONINFOW,
    },
    core::IInspectable,
};

use crate::appearance::{AccentRamp, AppearanceSnapshot};

fn windows_build() -> Option<u32> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: the caller-owned buffer is writable and its size initialized.
    unsafe { RtlGetVersion(&mut version) }
        .is_ok()
        .then_some(version.dwBuildNumber)
}

fn rgb(color: Color) -> u32 {
    (u32::from(color.R) << 16) | (u32::from(color.G) << 8) | u32::from(color.B)
}

// Microsoft's desktop theme detection samples the system foreground; a light
// foreground means dark mode. This matches GPUI's own Windows appearance test.
fn foreground_is_light(color: Color) -> bool {
    5 * u32::from(color.G) + 2 * u32::from(color.R) + u32::from(color.B) > 8 * 128
}

fn ramp(settings: &UISettings, kinds: [UIColorType; 3]) -> Option<AccentRamp> {
    let color = |kind| settings.GetColorValue(kind).ok().map(rgb);
    Some(AccentRamp {
        base: color(kinds[0])?,
        hover: color(kinds[1])?,
        active: color(kinds[2])?,
    })
}

/// Objects and event tokens remain on the constructing UI thread. Native
/// callbacks may occur on a different thread; `on_change` must only signal,
/// not mutate GUI state directly. Dropping the watch unregisters the events.
pub struct AppearanceWatch {
    settings: UISettings,
    build: Option<u32>,
    effect_token: Option<i64>,
    color_token: Option<i64>,
}

impl AppearanceWatch {
    pub fn new(on_change: impl Fn() + Send + Sync + 'static) -> Option<Self> {
        let settings = UISettings::new().ok()?;
        let on_change = Arc::new(on_change);
        let effects = on_change.clone();
        let effect_token = settings
            .AdvancedEffectsEnabledChanged(&TypedEventHandler::<UISettings, IInspectable>::new(
                move |_, _| {
                    effects();
                    Ok(())
                },
            ))
            .ok();
        let color_token = settings
            .ColorValuesChanged(&TypedEventHandler::<UISettings, IInspectable>::new(
                move |_, _| {
                    on_change();
                    Ok(())
                },
            ))
            .ok();
        Some(Self {
            settings,
            build: windows_build(),
            effect_token,
            color_token,
        })
    }

    /// Sample current settings; OS query errors become `None` individually.
    pub fn snapshot(&self) -> AppearanceSnapshot {
        AppearanceSnapshot {
            windows_build: self.build,
            transparency: self.settings.AdvancedEffectsEnabled().ok(),
            dark: self
                .settings
                .GetColorValue(UIColorType::Foreground)
                .ok()
                .map(foreground_is_light),
            light_accent: ramp(
                &self.settings,
                [
                    UIColorType::AccentDark1,
                    UIColorType::AccentDark2,
                    UIColorType::AccentDark3,
                ],
            ),
            dark_accent: ramp(
                &self.settings,
                [
                    UIColorType::AccentLight2,
                    UIColorType::AccentLight3,
                    UIColorType::AccentLight1,
                ],
            ),
        }
    }
}

impl Drop for AppearanceWatch {
    fn drop(&mut self) {
        if let Some(token) = self.effect_token {
            let _ = self.settings.RemoveAdvancedEffectsEnabledChanged(token);
        }
        if let Some(token) = self.color_token {
            let _ = self.settings.RemoveColorValuesChanged(token);
        }
    }
}

/// Return whether DWM accepted `DWMSBT_MAINWINDOW` for this borrowed HWND.
/// Invalid/unsupported handles return false; no attribute is set or changed.
pub fn mica_backdrop_accepted(hwnd: NonZeroIsize) -> bool {
    let hwnd = HWND(hwnd.get() as *mut std::ffi::c_void);
    let mut actual = DWM_SYSTEMBACKDROP_TYPE::default();
    // SAFETY: HWND is an opaque Win32 handle verified by DWM; the output
    // buffer and byte size match the documented attribute type.
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE,
            (&mut actual as *mut DWM_SYSTEMBACKDROP_TYPE).cast(),
            std::mem::size_of::<DWM_SYSTEMBACKDROP_TYPE>() as u32,
        )
    }
    .is_ok()
        && actual == DWMSBT_MAINWINDOW
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rgb_and_system_foreground() {
        let blue = Color {
            A: 255,
            R: 0,
            G: 95,
            B: 184,
        };
        assert_eq!(rgb(blue), 0x005FB8);
        assert!(foreground_is_light(Color {
            A: 255,
            R: 243,
            G: 243,
            B: 243
        }));
        assert!(!foreground_is_light(Color {
            A: 255,
            R: 27,
            G: 27,
            B: 27
        }));
    }
}

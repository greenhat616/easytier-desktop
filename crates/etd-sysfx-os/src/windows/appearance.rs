//! Windows appearance queries and DWM acknowledgement. The only write is
//! the dark-mode attribute of an application-owned window; never OS settings.

use std::{ffi::c_void, num::NonZeroIsize, sync::Arc};

use ::windows::{
    Foundation::TypedEventHandler,
    UI::{
        Color,
        ViewManagement::{UIColorType, UISettings},
    },
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, WPARAM},
        Graphics::Dwm::{
            DWM_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW, DWMWA_SYSTEMBACKDROP_TYPE,
            DWMWA_USE_IMMERSIVE_DARK_MODE, DwmGetWindowAttribute, DwmSetWindowAttribute,
        },
        System::{
            Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW},
            SystemInformation::OSVERSIONINFOW,
        },
        UI::WindowsAndMessaging::{
            GWL_EXSTYLE, GWLP_HINSTANCE, GetSystemMetrics, GetWindowLongPtrW,
            GetWindowThreadProcessId, HWND_TOPMOST, ICON_BIG, ICON_SMALL, IMAGE_ICON,
            IsWindowVisible, LR_SHARED, LoadImageW, SM_CXICON, SM_CXSMICON, SM_CYICON, SM_CYSMICON,
            SW_HIDE, SW_SHOWNOACTIVATE, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
            SendMessageW, SetWindowLongPtrW, SetWindowPos, ShowWindow, WM_SETICON, WS_EX_APPWINDOW,
            WS_EX_TOOLWINDOW,
        },
    },
    core::{BOOL, IInspectable, PCWSTR, w},
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
            taskbar_dark: query_taskbar_dark(),
            tray_icon_px: query_tray_icon_px(),
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
                    UIColorType::AccentLight2,
                ],
            ),
        }
    }
}

fn system_uses_light_theme_to_dark(dword: u32) -> bool {
    dword == 0
}

/// Read the Windows taskbar/shell theme (`SystemUsesLightTheme`) from HKCU.
/// This is distinct from `AppsUseLightTheme`: Windows allows a dark taskbar
/// with light apps. Returns `Some(true)` for a dark taskbar, `Some(false)` for
/// a light taskbar, or `None` if the registry value cannot be read.
pub fn query_taskbar_dark() -> Option<bool> {
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `value` is a caller-owned writable u32 buffer and `size` matches its byte length.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
            w!("SystemUsesLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast::<c_void>()),
            Some(&mut size),
        )
    };
    (status.0 == 0 && size == std::mem::size_of::<u32>() as u32)
        .then(|| system_uses_light_theme_to_dark(value))
}

/// Query the Windows system small-icon dimension (`SM_CXSMICON`), which tracks
/// system DPI (16 at 100%, 20 at 125%, 24 at 150%, 32 at 200%).
pub fn query_tray_icon_px() -> Option<u32> {
    // SAFETY: `GetSystemMetrics` has no preconditions and takes a scalar index.
    let px = unsafe { GetSystemMetrics(SM_CXSMICON) };
    u32::try_from(px).ok().filter(|&v| v > 0)
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

/// Set the native window's dark appearance to match the app theme. Only
/// HWNDs owned by the current process are accepted. Failure leaves the
/// caller free to fall back to a solid background of its chosen theme.
pub fn set_window_dark_mode(hwnd: NonZeroIsize, dark: bool) -> bool {
    let hwnd = HWND(hwnd.get() as *mut std::ffi::c_void);
    let mut owner = 0;
    // SAFETY: HWND is borrowed from the UI; owner is a valid output buffer.
    if unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) } == 0
        || owner != std::process::id()
    {
        return false;
    }
    let enabled = BOOL::from(dark);
    // SAFETY: the BOOL buffer and size match the documented DWM attribute.
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&enabled as *const BOOL).cast(),
            std::mem::size_of::<BOOL>() as u32,
        )
    }
    .is_ok()
}

/// Attach both `ICON_SMALL` (titlebar, pixel-tuned 16/24px frame) and `ICON_BIG`
/// (Alt+Tab / taskbar, 32/48px frame) from the executable's embedded icon
/// resource to an application-owned window. Only HWNDs owned by the current
/// process are accepted.
pub fn set_window_icon_from_resource(hwnd: NonZeroIsize, resource_id: u16) -> bool {
    let hwnd = HWND(hwnd.get() as *mut c_void);
    let mut owner = 0;
    // SAFETY: HWND is borrowed from the UI; owner is a valid output buffer.
    if unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) } == 0
        || owner != std::process::id()
    {
        return false;
    }
    // SAFETY: `hwnd` is verified to belong to the current process.
    let raw_instance = unsafe { GetWindowLongPtrW(hwnd, GWLP_HINSTANCE) };
    if raw_instance == 0 {
        return false;
    }
    let hinst = HINSTANCE(raw_instance as *mut c_void);
    let name = PCWSTR(usize::from(resource_id) as *const u16);

    let mut applied = false;
    for (icon_slot, cx_metric, cy_metric) in [
        (ICON_SMALL, SM_CXSMICON, SM_CYSMICON),
        (ICON_BIG, SM_CXICON, SM_CYICON),
    ] {
        // SAFETY: `GetSystemMetrics` and `LoadImageW` with `LR_SHARED` load a
        // shared handle owned by the module that does not need `DestroyIcon`.
        let cx = unsafe { GetSystemMetrics(cx_metric) };
        let cy = unsafe { GetSystemMetrics(cy_metric) };
        if let Ok(handle) = unsafe { LoadImageW(Some(hinst), name, IMAGE_ICON, cx, cy, LR_SHARED) }
            && !handle.is_invalid()
        {
            // SAFETY: `hwnd` belongs to this process and `handle` is a valid shared HICON.
            unsafe {
                SendMessageW(
                    hwnd,
                    WM_SETICON,
                    Some(WPARAM(icon_slot as usize)),
                    Some(LPARAM(handle.0 as isize)),
                );
            }
            applied = true;
        }
    }
    applied
}

/// Keeps an application-owned window above other windows and out of the
/// taskbar and Alt+Tab: WS_EX_TOPMOST through `SetWindowPos(HWND_TOPMOST)`,
/// and WS_EX_TOOLWINDOW in place of WS_EX_APPWINDOW. The shell only reads
/// the taskbar style when a window is shown, so a visible window is hidden
/// and shown again around the change. Only HWNDs owned by the current
/// process are accepted.
pub fn pin_window_on_top(hwnd: NonZeroIsize) -> bool {
    let hwnd = HWND(hwnd.get() as *mut c_void);
    let mut owner = 0;
    // SAFETY: HWND is borrowed from the UI; owner is a valid output buffer.
    if unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) } == 0
        || owner != std::process::id()
    {
        return false;
    }
    // SAFETY: `hwnd` is verified to belong to the current process; these
    // calls only change its own styles, z-order and visibility.
    unsafe {
        let visible = IsWindowVisible(hwnd).as_bool();
        if visible {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
        let style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        let style = (style | WS_EX_TOOLWINDOW.0 as isize) & !(WS_EX_APPWINDOW.0 as isize);
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, style);
        let pinned = SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        )
        .is_ok();
        if visible {
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        }
        pinned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinning_refuses_a_window_of_another_process() {
        use ::windows::Win32::UI::WindowsAndMessaging::GetDesktopWindow;
        // SAFETY: GetDesktopWindow only returns a handle; nothing is changed.
        let desktop = unsafe { GetDesktopWindow() };
        let hwnd = NonZeroIsize::new(desktop.0 as isize).expect("desktop window");
        assert!(!pin_window_on_top(hwnd));
    }

    /// Creates a real top-level window, so it runs in Windows CI only
    /// (ci.yml), never on a developer's desktop.
    #[test]
    #[ignore = "creates a real Win32 window; Windows CI only"]
    fn pinning_makes_a_window_topmost_and_a_tool_window() {
        use ::windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW,
        };
        // SAFETY: a plain window of the system STATIC class, owned by this
        // thread and destroyed below.
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_APPWINDOW,
                w!("STATIC"),
                w!("etd pin test"),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                200,
                120,
                None,
                None,
                None,
                None,
            )
        }
        .expect("create a test window");
        // SAFETY: `hwnd` was created above and is still alive.
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        }
        let style = || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32;
        assert_ne!(style() & WS_EX_APPWINDOW.0, 0);
        assert_eq!(style() & WS_EX_TOPMOST.0, 0);

        let pinned = pin_window_on_top(NonZeroIsize::new(hwnd.0 as isize).unwrap());
        let after = style();
        // SAFETY: `hwnd` was created above and is still alive.
        let visible = unsafe { IsWindowVisible(hwnd).as_bool() };
        // SAFETY: as above; the window is not used afterwards.
        unsafe { DestroyWindow(hwnd) }.expect("destroy the test window");

        assert!(pinned);
        assert_ne!(after & WS_EX_TOOLWINDOW.0, 0, "tool window");
        assert_eq!(after & WS_EX_APPWINDOW.0, 0, "app window cleared");
        assert_ne!(after & WS_EX_TOPMOST.0, 0, "topmost");
        assert!(visible, "shown again after the style change");
    }

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

    #[test]
    fn system_uses_light_theme_maps_zero_to_dark() {
        assert!(system_uses_light_theme_to_dark(0));
        assert!(!system_uses_light_theme_to_dark(1));
    }

    #[test]
    fn tray_icon_metric_is_positive_on_windows() {
        let px = query_tray_icon_px().expect("SM_CXSMICON should be positive");
        assert!(px >= 16);
    }
}

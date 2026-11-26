//! Plain-data desktop appearance queries. Native handles and Windows Runtime
//! types are confined to the OS adapter.

#[cfg(not(windows))]
use std::num::NonZeroIsize;

/// RGB values in `0xRRGGBB` form, in normal / hover / active order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccentRamp {
    pub base: u32,
    pub hover: u32,
    pub active: u32,
}

/// Unknown or unavailable settings are represented as `None`, so callers can
/// choose safe opaque/default-color fallbacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AppearanceSnapshot {
    pub windows_build: Option<u32>,
    pub transparency: Option<bool>,
    pub dark: Option<bool>,
    pub light_accent: Option<AccentRamp>,
    pub dark_accent: Option<AccentRamp>,
}

impl AppearanceSnapshot {
    /// The documented DWM system-backdrop API begins with Windows 11 22H2.
    pub fn supports_mica(self) -> bool {
        self.windows_build.is_some_and(|build| build >= 22621) && self.transparency == Some(true)
    }
}

#[cfg(windows)]
pub use crate::windows::appearance::{
    AppearanceWatch, mica_backdrop_accepted, set_window_dark_mode,
};

#[cfg(not(windows))]
#[derive(Debug)]
pub struct AppearanceWatch;

#[cfg(not(windows))]
impl AppearanceWatch {
    pub fn new(_on_change: impl Fn() + Send + Sync + 'static) -> Option<Self> {
        None
    }

    pub fn snapshot(&self) -> AppearanceSnapshot {
        AppearanceSnapshot::default()
    }
}

/// Non-Windows has no Windows DWM material; the UI chooses an opaque fallback.
#[cfg(not(windows))]
pub fn mica_backdrop_accepted(_hwnd: NonZeroIsize) -> bool {
    false
}

/// Non-Windows has no DWM window dark-mode attribute.
#[cfg(not(windows))]
pub fn set_window_dark_mode(_hwnd: NonZeroIsize, _dark: bool) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_or_unknown_appearance_preserves_solid_fallback() {
        assert!(!AppearanceSnapshot::default().supports_mica());
        for (build, transparency, expected) in [
            (Some(19045), Some(true), false),
            (Some(22000), Some(true), false),
            (Some(22621), Some(false), false),
            (Some(22621), None, false),
            (None, Some(true), false),
            (Some(22621), Some(true), true),
        ] {
            assert_eq!(
                AppearanceSnapshot {
                    windows_build: build,
                    transparency,
                    ..Default::default()
                }
                .supports_mica(),
                expected
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_adapter_is_inert() {
        assert!(AppearanceWatch::new(|| panic!("no WinRT event on non-Windows")).is_none());
        assert!(!mica_backdrop_accepted(NonZeroIsize::new(1).unwrap()));
        assert!(!set_window_dark_mode(NonZeroIsize::new(1).unwrap(), true));
    }
}

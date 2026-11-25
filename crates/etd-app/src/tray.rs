//! Frozen interface (F0): the minimal tray surface (tray-icon + muda) that
//! the window/tray state table drives. Implemented by U1; faked in
//! etd-testkit. Lives on the UI thread, hence not `Send`.

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum TrayError {
    /// No tray on this desktop (e.g. GNOME without an extension): the UI
    /// must keep a visible window instead of hiding to the tray.
    #[error("no system tray available: {0}")]
    Unavailable(String),
    #[error("tray backend error: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrayIndicator {
    Idle,
    Connected,
    Attention,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuItem {
    /// Stable id echoed back in [`TrayEvent::Menu`].
    pub id: String,
    pub label: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrayMenu {
    pub items: Vec<TrayMenuItem>,
}

/// Well-known menu ids every menu carries.
pub mod menu_id {
    pub const OPEN: &str = "open";
    pub const EXIT: &str = "exit";
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrayEvent {
    /// Icon clicked.
    Activated,
    /// Menu item chosen, by [`TrayMenuItem::id`].
    Menu(String),
}

pub trait TrayBackend {
    fn install(&mut self, tooltip: &str, menu: &TrayMenu) -> Result<(), TrayError>;
    fn set_indicator(&mut self, indicator: TrayIndicator, tooltip: &str) -> Result<(), TrayError>;
    fn set_menu(&mut self, menu: &TrayMenu) -> Result<(), TrayError>;
    /// Next pending event, if any; never blocks.
    fn try_next_event(&mut self) -> Option<TrayEvent>;
    fn remove(&mut self);
}

//! Window and tray state table (shown / hidden-to-tray / no tray), driven by
//! [`crate::TrayBackend`] events; converges under reordered events. Owned
//! by A1.
//!
//! | input                     | shown, tray        | shown, no tray     | hidden               |
//! |---------------------------|--------------------|--------------------|----------------------|
//! | close requested           | close → hidden     | keep window        | nothing              |
//! | window gone (current gen) | → hidden           | reopen             | nothing              |
//! | window gone (old gen)     | nothing            | nothing            | nothing              |
//! | show / icon / "open"      | focus              | focus              | open (new gen)       |
//! | tray lost                 | → no tray          | nothing            | open (new gen)       |
//! | exit                      | begin exit         | begin exit         | begin exit           |
//!
//! Closing the window is not exiting. Once exit began, every input is
//! ignored. The host link is not an input at all: losing the host leaves
//! window and tray as they are.
//!
//! The platform opens and closes windows asynchronously, so every window has
//! a generation and a late "gone" report for an older window changes
//! nothing. The view layer must use `QuitMode::Explicit` and answer the
//! title-bar close through [`WindowInput::CloseRequested`].
use crate::{
    HostLink, InstanceCondition, StateStore, SyncState, TrayBackend, TrayError, TrayEvent,
    TrayIndicator, TrayMenu, TrayMenuItem, menu_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Shown,
    HiddenToTray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// "Exit" in the tray menu.
    TrayMenu,
    /// "Exit" in the application menu.
    AppMenu,
    /// Logoff or shutdown of the operating system.
    SessionEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowInput {
    /// The user asked to close the window (title bar, shortcut).
    CloseRequested,
    /// The platform reports that the window of this generation is gone.
    WindowGone {
        generation: u64,
    },
    /// Bring the window up (second launch, dock icon).
    ShowRequested,
    Tray(TrayEvent),
    TrayAvailability(bool),
    ExitRequested(ExitReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAction {
    OpenWindow {
        generation: u64,
    },
    FocusWindow {
        generation: u64,
    },
    /// Destroy the window; the application keeps running in the tray. Like
    /// `FocusWindow`, it does nothing if that window is already gone (its
    /// report may still be on the way).
    CloseWindow {
        generation: u64,
    },
    /// There is no tray to hide into: veto the close and say how to exit.
    KeepWindow,
    /// Run the [`crate::ExitGate`]. Emitted once.
    BeginExit(ExitReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowTray {
    visibility: Visibility,
    tray_available: bool,
    generation: u64,
    exiting: bool,
}

impl WindowTray {
    /// The tray counts as unavailable until the backend installed an icon, so
    /// the first window is always opened.
    pub fn new() -> (Self, WindowAction) {
        (
            Self {
                visibility: Visibility::Shown,
                tray_available: false,
                generation: 1,
                exiting: false,
            },
            WindowAction::OpenWindow { generation: 1 },
        )
    }

    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    pub fn tray_available(&self) -> bool {
        self.tray_available
    }

    /// Generation of the window that is open, or was last open.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_exiting(&self) -> bool {
        self.exiting
    }

    pub fn handle(&mut self, input: WindowInput) -> Option<WindowAction> {
        if let WindowInput::TrayAvailability(available) = input {
            self.tray_available = available;
        }
        if self.exiting {
            return None;
        }
        match input {
            WindowInput::CloseRequested => match self.visibility {
                Visibility::HiddenToTray => None,
                Visibility::Shown if self.tray_available => {
                    self.visibility = Visibility::HiddenToTray;
                    Some(WindowAction::CloseWindow {
                        generation: self.generation,
                    })
                }
                Visibility::Shown => Some(WindowAction::KeepWindow),
            },
            WindowInput::WindowGone { generation } => {
                if generation != self.generation || self.visibility == Visibility::HiddenToTray {
                    None
                } else if self.tray_available {
                    self.visibility = Visibility::HiddenToTray;
                    None
                } else {
                    Some(self.open())
                }
            }
            WindowInput::ShowRequested => Some(self.show()),
            WindowInput::Tray(TrayEvent::Activated) => Some(self.show()),
            WindowInput::Tray(TrayEvent::Menu(id)) => match id.as_str() {
                menu_id::OPEN => Some(self.show()),
                menu_id::EXIT => Some(self.exit(ExitReason::TrayMenu)),
                _ => None,
            },
            WindowInput::TrayAvailability(available) => {
                (!available && self.visibility == Visibility::HiddenToTray).then(|| self.open())
            }
            WindowInput::ExitRequested(reason) => Some(self.exit(reason)),
        }
    }

    fn show(&mut self) -> WindowAction {
        match self.visibility {
            Visibility::Shown => WindowAction::FocusWindow {
                generation: self.generation,
            },
            Visibility::HiddenToTray => self.open(),
        }
    }

    fn open(&mut self) -> WindowAction {
        self.generation += 1;
        self.visibility = Visibility::Shown;
        WindowAction::OpenWindow {
            generation: self.generation,
        }
    }

    fn exit(&mut self, reason: ExitReason) -> WindowAction {
        self.exiting = true;
        WindowAction::BeginExit(reason)
    }
}

/// What the tray icon says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraySummary {
    pub indicator: TrayIndicator,
    pub tooltip: String,
}

pub const APP_TITLE: &str = "EasyTier Desktop";

/// `None` while the store does not reflect a connected host: the tray then
/// keeps showing what it showed before ("reconnecting" is a message in the
/// window, not a tray state).
pub fn tray_summary(store: &StateStore) -> Option<TraySummary> {
    if store.link != HostLink::Connected || store.sync != SyncState::Synced {
        return None;
    }
    let (mut running, mut failed, mut attention) = (0usize, 0usize, 0usize);
    for instance in store.instances.values() {
        match instance.condition() {
            InstanceCondition::RunningBasic | InstanceCondition::Running => running += 1,
            InstanceCondition::GaveUp | InstanceCondition::Quarantined => failed += 1,
            InstanceCondition::CutUnconfirmed
            | InstanceCondition::Backoff
            | InstanceCondition::Waiting
            | InstanceCondition::Unknown => attention += 1,
            InstanceCondition::Stopped
            | InstanceCondition::Starting
            | InstanceCondition::Stopping
            | InstanceCondition::Reclaiming => {}
        }
    }
    attention += store.reclaim.candidates.len() + store.reclaim.conflicts.len();
    let indicator = if failed > 0 {
        TrayIndicator::Error
    } else if attention > 0 {
        TrayIndicator::Attention
    } else if running > 0 {
        TrayIndicator::Connected
    } else {
        TrayIndicator::Idle
    };
    let mut tooltip = format!("{APP_TITLE}: {running} running");
    if failed > 0 {
        tooltip.push_str(&format!(", {failed} failed"));
    }
    if attention > 0 {
        tooltip.push_str(&format!(", {attention} need attention"));
    }
    Some(TraySummary { indicator, tooltip })
}

/// The menu every tray carries. The view supplies localized labels.
pub fn tray_menu(open_label: &str, exit_label: &str) -> TrayMenu {
    TrayMenu {
        items: [(menu_id::OPEN, open_label), (menu_id::EXIT, exit_label)]
            .into_iter()
            .map(|(id, label)| TrayMenuItem {
                id: id.to_owned(),
                label: label.to_owned(),
                enabled: true,
            })
            .collect(),
    }
}

/// Drives a [`TrayBackend`] from the UI thread and reports availability to
/// the state table.
pub struct TrayDriver<B: TrayBackend> {
    backend: B,
    installed: bool,
    shown: Option<TraySummary>,
}

impl<B: TrayBackend> TrayDriver<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            installed: false,
            shown: None,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Installs (or re-installs, after the desktop's tray came back) the icon
    /// and returns the availability to feed to [`WindowTray`].
    pub fn install(&mut self, menu: &TrayMenu) -> WindowInput {
        if self.installed {
            self.backend.remove();
        }
        self.shown = None;
        let result = self.backend.install(APP_TITLE, menu);
        if let Err(error) = &result {
            tracing::warn!(%error, "tray icon not installed");
        }
        self.installed = result.is_ok();
        WindowInput::TrayAvailability(self.installed)
    }

    /// Shows a summary if it differs from the current one. Returns an input
    /// only when the tray turned out to be gone. Other backend errors are not
    /// fatal; the next call tries again.
    pub fn show(&mut self, summary: &TraySummary) -> Option<WindowInput> {
        if !self.installed || self.shown.as_ref() == Some(summary) {
            return None;
        }
        match self
            .backend
            .set_indicator(summary.indicator, &summary.tooltip)
        {
            Ok(()) => {
                self.shown = Some(summary.clone());
                None
            }
            Err(TrayError::Unavailable(reason)) => {
                tracing::warn!(%reason, "tray disappeared");
                self.backend.remove();
                self.installed = false;
                Some(WindowInput::TrayAvailability(false))
            }
            Err(error) => {
                tracing::debug!(%error, "tray update failed");
                None
            }
        }
    }

    /// Pending tray events as state-table inputs.
    pub fn poll(&mut self) -> Vec<WindowInput> {
        std::iter::from_fn(|| self.backend.try_next_event())
            .map(WindowInput::Tray)
            .collect()
    }

    /// Removes the icon; call it before quitting the UI toolkit.
    pub fn remove(&mut self) {
        if self.installed {
            self.backend.remove();
            self.installed = false;
        }
    }
}

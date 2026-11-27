//! Desktop UI (`etd-ui`, package U1) built on `gpui-kit`, `tray-icon`, and `muda`.
//!
//! All views bind strictly to [`etd_app::StateStore`] and dispatch [`etd_app::UserCommand`]
//! through [`etd_app::AppBridge`]. Network secrets are never stored locally and are scrubbed
//! from the editor immediately after submission.

pub mod assets;
pub mod composition;
pub mod controller;
pub mod editor;
pub mod gallery;
pub mod model;
mod preferences;
pub mod theme;
pub mod tray;
pub mod views;

pub use composition::{
    ElevatedAwareLauncher, LocalGrpcClientFactory, PlatformServiceInstaller, ServiceInstaller,
    build_local_services, default_profile_store, is_process_elevated,
};
pub use controller::{ExitHook, UiController};
pub use editor::{NetworkEditorState, SecretMode};
pub use model::{DetailTab, InstallStatus, Section, UiModel};
pub use tray::NativeTrayBackend;
pub use views::MainView;

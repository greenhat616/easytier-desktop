//! UI-independent application logic: state store, host launching, profiles,
//! window/tray state. No gpui, no OS bindings.
//!
//! Frozen interfaces (F0): `launcher`, `profiles`, `tray`. Everything else
//! is owned by A1.
pub mod launcher;
pub mod profiles;
pub mod tray;

pub mod bridge;
pub mod exit_gate;
pub mod launcher_user;
pub mod profiles_toml;
pub mod reducer;
pub mod state;
pub mod window_tray;

pub use bridge::*;
pub use exit_gate::*;
pub use launcher::*;
pub use profiles::*;
pub use state::*;
pub use tray::*;

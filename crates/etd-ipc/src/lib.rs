//! Local IPC transport abstractions; platform adapters will live here.
mod transport;
pub use transport::*;
pub mod platform;

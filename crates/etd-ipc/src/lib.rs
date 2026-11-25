//! Local IPC: named pipes (Windows) and Unix-domain sockets, peer identity,
//! and the tonic transport glue. No business authorisation happens here.
mod transport;
pub use transport::*;
pub mod platform;
pub mod tonic_io;

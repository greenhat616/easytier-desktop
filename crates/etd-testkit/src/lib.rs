//! Test doubles, conformance suites, scripted servers and the fake-core
//! binary. Test-only: never a normal dependency of a product crate (xtask
//! enforces it).
//!
//! F0 owns this file and `fakes/mod.rs`; every other file has its own owner
//! (see doc#7's ownership table).
pub mod fakes;
/// Shared conformance suites run against every implementation of a trait.
pub mod conformance {
    pub mod ledger;
}
pub mod scripted_server;
pub mod sysdiff;
pub mod transport;

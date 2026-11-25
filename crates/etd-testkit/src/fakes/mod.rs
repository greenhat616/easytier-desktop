//! Fakes of every frozen trait, one file per owner.
/// Fake `Authorizer` (H2).
pub mod auth;
/// Virtual `Clock` (P1, M1).
pub mod clock;
/// Fake `CoreDriver` / `CoreSession` (H1).
pub mod core;
/// Fake `HostClient` (A1).
pub mod host;
/// Fake `HostLauncher` (A1).
pub mod launcher;
/// In-memory `Ledger` (L1, milestone M1).
pub mod ledger;
/// Scripted `ProcessEngine` (P1, M1).
pub mod process;
/// Fake `ProfileStore` (A1).
pub mod profiles;
/// Fake `CoreStore` (H2).
pub mod store;
/// Fault-injecting fake system: `Reclaimer`, `Sweeper`, `BootIdSource`,
/// `SystemObserver`, `PortFence` (R1, M1).
pub mod system;

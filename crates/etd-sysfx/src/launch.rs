//! Frozen launch inputs (F0): everything `CoreDriver::plan_launch` consumes
//! besides the instance and epoch. They are persisted with each generation
//! ([`crate::GenerationPlan::inputs`]) so the orchestrator replays an
//! accepted plan deterministically from what was committed, never by
//! re-planning against current state. A changed kernel, spec or setting
//! means a new generation, never a different launch of a committed one.
use etd_contract::{NetworkSpec, Revision};
use std::{net::SocketAddr, path::PathBuf};

/// Privilege of the host the kernel will run under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Privilege {
    /// SYSTEM / root (service or elevated session).
    System,
    /// Current user (user host): no TUN, no fence.
    User,
}

/// How the management port is protected for one launch. The host asks for
/// `Fence` when a fence is available on a privileged host; when fencing is
/// unavailable or failed it plans the next generation with `DenyAll` (v7
/// fence step 4), which the driver accepts only if the profile's deny-all
/// configuration is verified. User hosts ask for `Unguarded`, or
/// `LifecycleOnly` for a kernel without an adapter profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ManagementGuard {
    /// Privileged host: a verified fence is required before any RPC.
    Fence,
    /// Kernel whitelist closes the port to everyone; lifecycle only.
    DenyAll,
    /// User host: the kernel runs as the user; no fence.
    Unguarded,
    /// No adapter profile (user host only): no RPC at all.
    LifecycleOnly,
}

/// The verified kernel a generation launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRef {
    pub version: String,
    pub proto_revision: String,
    /// SHA-256 of the binary as verified when the plan was made; replay
    /// re-verifies it and fails the generation on mismatch.
    pub sha256: [u8; 32],
    /// Binary inside the protected kernel store.
    pub binary: PathBuf,
    /// Adapter profile id (`None`: lifecycle-only).
    pub profile: Option<String>,
}

/// Inputs of one generation's plan.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchInputs {
    /// The configuration as committed (including its secret).
    pub spec: NetworkSpec,
    /// Ledger revision that committed `spec`.
    pub spec_revision: Revision,
    /// `run/<instance>/<epoch>/`, writable only by the host.
    pub runtime_dir: PathBuf,
    /// `naming::interface_name(install key, instance)`.
    pub interface_name: String,
    /// Loopback management (RPC portal) address forced on the kernel.
    pub management: SocketAddr,
    pub privilege: Privilege,
    pub guard: ManagementGuard,
    pub core: CoreRef,
}

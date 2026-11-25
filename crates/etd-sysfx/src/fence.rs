//! Frozen management-port fence interface (F0). The kernel's management RPC
//! is unauthenticated TCP on loopback, so a privileged host walls it off
//! before use (doc#2 v7, "内核自己的管理端口：先围住，再使用"):
//!
//! 1. record the fence in the ledger ([`PortFence::plan`] + `Ledger::record`
//!    or `begin_epoch`), then [`PortFence::install`] a persistent system rule
//!    letting only the host's identity connect to the port;
//! 2. start the kernel and confirm the listener is the process just spawned;
//! 3. probe both directions on that live listener ([`PortFence::verify`]):
//!    the host must connect, a dropped-privilege probe must be refused;
//!    a refusal on an empty port does not count. Any mismatch: kill the
//!    kernel and reclaim;
//! 4. (fallback, not here) a deny-all kernel configuration, only when the
//!    adapter profile marks it verified;
//! 5. [`PortFence::remove`] only after the kernel is verified dead.
//!
//! Implementations: etd-sysfx-os (O1 WFP, O2 nftables by uid, O3 PF by
//! user). Fences live in product-exclusive containers.
use crate::*;
use async_trait::async_trait;
use etd_contract::InstanceId;
use std::net::SocketAddr;

/// One fenced management endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceSpec {
    pub instance: InstanceId,
    pub epoch: Epoch,
    /// Loopback address and port the kernel will listen on.
    pub address: SocketAddr,
}

/// Who listens on the fenced port.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenerCheck {
    /// The expected process.
    Expected,
    /// Somebody else: never trust this port.
    Other {
        pid: u32,
    },
    NotListening,
    Indeterminate(String),
}

/// One connection attempt against a live listener.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectionResult {
    Connected,
    Refused,
    /// Nothing listening: the attempt proves nothing.
    NoListener,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceVerification {
    pub listener: ListenerCheck,
    /// Connection as the host's own identity.
    pub host: DirectionResult,
    /// Connection from a probe running with no privileges.
    pub unprivileged: DirectionResult,
}

impl FenceVerification {
    /// Both directions as required, on the expected live listener.
    pub fn passed(&self) -> bool {
        self.listener == ListenerCheck::Expected
            && self.host == DirectionResult::Connected
            && self.unprivileged == DirectionResult::Refused
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FenceError {
    /// This platform/host cannot fence: no privileged instance unless the
    /// profile has a verified deny-all configuration.
    #[error("fencing unsupported: {0}")]
    Unsupported(String),
    #[error("access denied: {0}")]
    PermissionDenied(String),
    /// The dropped-privilege probe could not be started.
    #[error("probe failed: {0}")]
    Probe(String),
    #[error("operating system error {code}: {message}")]
    Os { code: i64, message: String },
}

#[async_trait]
pub trait PortFence: Send + Sync {
    /// Ledger intent for the fence rule (kind, key in the exclusive
    /// container, persistent). Recorded before [`PortFence::install`].
    fn plan(&self, spec: &FenceSpec) -> EffectIntent;
    /// Install the persistent rule. Returns what to record as applied.
    async fn install(&self, spec: &FenceSpec) -> Result<Observation, FenceError>;
    /// Steps 2 and 3 against the listener owned by `listener_pid`.
    async fn verify(
        &self,
        spec: &FenceSpec,
        listener_pid: u32,
    ) -> Result<FenceVerification, FenceError>;
    /// Remove the rule. Precondition: the kernel is verified dead.
    /// Idempotent.
    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError>;
}

//! Frozen kernel-adapter model (F0). No EasyTier type appears here.
use etd_contract::InstanceId;
use etd_proc::Command;
pub use etd_sysfx::{CoreRef, LaunchInputs, ManagementGuard, Privilege};
use etd_sysfx::{EffectIntent, Epoch, ObjectKey};
use std::{net::SocketAddr, path::PathBuf, time::Duration, time::SystemTime};

/// What a kernel binary says it is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoreDescriptor {
    /// Kernel version, e.g. "2.7.1".
    pub version: String,
    /// Upstream proto revision the binary was built from, e.g. "c97f36b".
    pub proto_revision: String,
}

/// An adapter profile: one kernel version paired exactly with its RPC
/// method table and side-effect predictions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterProfile {
    /// E.g. "2.7.1-c97f36b".
    pub id: String,
    /// The deny-all management configuration of this kernel version has been
    /// verified by privileged tests (fence fallback allowed).
    pub deny_all_verified: bool,
}

/// Everything `plan_launch` consumes: the generation and its persisted
/// inputs. The host chooses the interface name, management address, guard
/// and kernel; the spec cannot. Built from `GenerationPlan` on replay.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchContext {
    pub instance: InstanceId,
    /// Reserved epoch (`Ledger::next_epoch`); it appears in the runtime
    /// directory and in every planned record.
    pub epoch: Epoch,
    pub inputs: LaunchInputs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreEndpoint(pub SocketAddr);

/// A file the host writes into the epoch directory before spawning. May
/// contain the network secret: never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedFile {
    pub path: PathBuf,
    pub contents: Vec<u8>,
}

impl std::fmt::Debug for PlannedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedFile")
            .field("path", &self.path)
            .field("contents", &format_args!("<{} bytes>", self.contents.len()))
            .finish()
    }
}

/// Basic-readiness condition, judged by the host from system observation
/// (never from the management RPC).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadinessCondition {
    /// The expected interface exists and carries an address.
    InterfaceAddress(ObjectKey),
    /// System-assigned interface name (macOS utun): an interface held by the
    /// kernel process (`SystemObserver::interfaces_owned_by`) carries an
    /// address.
    OwnedInterfaceAddress,
    /// Instances without an interface: the expected listening port.
    Listener(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// The process must stay alive at least this long.
    pub minimum_uptime: Duration,
    pub condition: ReadinessCondition,
}

/// Classification of one configured feature by its side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeatureClass {
    /// Side effects computable before launch.
    Supported,
    /// Writes a machine-wide shared object: one instance at a time.
    SingleWriter { resource: String },
    /// Would damage objects that are not ours on this platform.
    Disabled { reason: String },
    /// Write set only known at run time or not modelled.
    Rejected { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureVerdict {
    /// `NetworkSpec` field name, e.g. "magic_dns".
    pub feature: String,
    pub class: FeatureClass,
}

/// Pure planning result: command line, files, readiness and every side
/// effect this kernel version will cause with this configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    pub command: Command,
    pub files: Vec<PlannedFile>,
    pub readiness: Readiness,
    /// Effects the kernel will cause, recorded (as `Planned`) before the
    /// process is spawned. The host adds its own records to the same
    /// generation (process, runtime directory, fence); the driver never
    /// produces those.
    pub effects: Vec<EffectIntent>,
    /// The guard this plan implements (echoes `LaunchContext`).
    pub management: ManagementGuard,
    pub endpoint: CoreEndpoint,
    /// Single-writer resources this launch claims (host enforces one owner).
    pub exclusive: Vec<String>,
    /// Classification of every configured feature.
    pub features: Vec<FeatureVerdict>,
}

/// Read back once fully ready (macOS: the system-assigned utun name).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoreRuntimeInfo {
    pub interface_name: Option<String>,
    pub ipv4_cidr: Option<String>,
    pub peer_id: Option<u32>,
    pub hostname: Option<String>,
    pub version: Option<String>,
}

/// Position in a kernel's event history (kernel-local, not the contract
/// cursor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoreEventCursor(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreEventKind {
    PeerAdded {
        peer_id: u32,
    },
    PeerRemoved {
        peer_id: u32,
    },
    ConnectionAdded {
        peer_id: u32,
        tunnel: String,
    },
    ConnectionRemoved {
        peer_id: u32,
        tunnel: String,
    },
    InterfaceReady {
        name: String,
    },
    AddressChanged {
        ipv4_cidr: Option<String>,
    },
    ListenerFailed {
        url: String,
        message: String,
    },
    /// Anything the profile does not map yet.
    Other {
        name: String,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreEvent {
    pub cursor: CoreEventCursor,
    pub at: SystemTime,
    pub kind: CoreEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A configured feature's write set is unknown or only decided at run
    /// time; a privileged host must refuse it.
    #[error("unmodelled side effects: {features:?}")]
    UnmodelledEffects { features: Vec<String> },
    /// The requested management guard cannot be planned (e.g. `DenyAll`
    /// without a verified deny-all configuration, `Unguarded` on a
    /// privileged host).
    #[error("management guard {0:?} unavailable for this kernel")]
    GuardUnavailable(ManagementGuard),
    /// A configured feature is disabled or rejected on this platform.
    #[error("feature {feature} rejected: {reason}")]
    FeatureRejected { feature: String, reason: String },
    /// No adapter profile for this kernel version.
    #[error("no adapter profile for kernel {version}")]
    NoProfile { version: String },
    #[error("invalid network spec: {0}")]
    InvalidSpec(String),
    #[error("could not identify kernel binary: {0}")]
    Identify(String),
    #[error("cannot reach management endpoint: {0}")]
    Connect(String),
    #[error("management RPC failed: {0}")]
    Rpc(String),
    #[error("timed out")]
    Timeout,
    #[error("management session closed")]
    SessionClosed,
    #[error("unsupported: {0}")]
    Unsupported(String),
}

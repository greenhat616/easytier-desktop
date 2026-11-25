//! Public desktop contract (`etd.v1`); never exposes kernel or transport types.
//!
//! The Protobuf files under `proto/` are the source of truth. This crate holds
//! the generated messages, version constants, capability names, the method to
//! role table read from the `(etd.v1.required_role)` method option, and a few
//! Rust-side identifier types. It depends on `prost` only.
pub mod v1 {
    #![allow(clippy::doc_lazy_continuation, clippy::large_enum_variant)]
    include!(concat!(env!("OUT_DIR"), "/etd.v1.rs"));
}
mod model;
mod roles;

pub use model::*;
pub use roles::{MethodRole, method_roles, required_role};
pub use v1::{
    AllowEntry, CandidateDecision, Desired, DesiredInstance, ErrorCode, ErrorDetail, Event,
    EventCursor, Hello, HostMode, HostPhase, HostSnapshot, InstanceState, InstanceStatus, LogLine,
    NetworkSpec, OsPrincipal, QueryKind, QueryResponse, Receipt, ReclaimReport, Role, Welcome,
};

/// Contract major version; must match exactly between client and host.
pub const VERSION_MAJOR: u32 = 1;
/// Contract minor version; minor versions only add.
pub const VERSION_MINOR: u32 = 0;
/// gRPC metadata key every call carries, value `"<major>.<minor>"`.
pub const VERSION_METADATA_KEY: &str = "etd-contract-version";
/// Fully qualified gRPC service name.
pub const SERVICE_NAME: &str = "etd.v1.HostService";
/// Field number of the `(etd.v1.required_role)` method option.
pub const REQUIRED_ROLE_OPTION: u32 = 50000;
/// Encoded `FileDescriptorSet` of every contract file.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/host_descriptor.bin"));

/// The value of [`VERSION_METADATA_KEY`] for this build.
pub fn version_metadata_value() -> String {
    format!("{VERSION_MAJOR}.{VERSION_MINOR}")
}

/// Parses a [`VERSION_METADATA_KEY`] value into `(major, minor)`.
pub fn parse_version_metadata(value: &str) -> Option<(u32, u32)> {
    let (major, minor) = value.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Capability names a host may list in `Welcome.capabilities`. Clients switch
/// features on these names, never on version numbers. New names may appear in
/// later minor versions; unknown names must be ignored.
pub mod capability {
    /// Snapshot, Subscribe, Apply, SetDesired, RemoveInstance, GetReceipt.
    pub const INSTANCES: &str = "instances";
    /// Query with `QUERY_KIND_NODES`.
    pub const QUERY_NODES: &str = "query.nodes";
    /// Query with `QUERY_KIND_ROUTES`.
    pub const QUERY_ROUTES: &str = "query.routes";
    /// Query with `QUERY_KIND_TRAFFIC`.
    pub const QUERY_TRAFFIC: &str = "query.traffic";
    /// StreamLogs.
    pub const LOGS: &str = "logs";
    /// GetReclaimReport and RetryReclaim.
    pub const RECLAIM: &str = "reclaim";
    /// ResolveCandidates.
    pub const RECLAIM_CANDIDATES: &str = "reclaim.candidates";
    /// ReleaseLease (session-form hosts).
    pub const LEASE: &str = "lease";
    /// GetAllowList and SetAllowList.
    pub const ADMIN_ALLOW_LIST: &str = "admin.allow_list";
    /// ListCores and SelectCore.
    pub const ADMIN_CORES: &str = "admin.cores";
    /// PurgeAllData.
    pub const ADMIN_PURGE: &str = "admin.purge";
    /// TUN instances are possible (privileged host forms).
    pub const TUN: &str = "tun";
}

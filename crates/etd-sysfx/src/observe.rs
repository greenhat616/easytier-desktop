//! Frozen independent-enumeration interface (F0). The host never trusts the
//! kernel's word about system objects: it looks for them itself, records
//! their creation credential as soon as they appear (shrinking the window in
//! which a record is only "planned"), and decides basic readiness from what
//! it sees. Implementations: etd-sysfx-os (O1-O3); fake in etd-testkit.
use crate::*;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub credential: Credential,
    /// Address and prefix length.
    pub addresses: Vec<(IpAddr, u8)>,
    pub up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInfo {
    pub address: SocketAddr,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ObserveError {
    #[error("access denied: {0}")]
    PermissionDenied(String),
    #[error("cannot observe {0} on this platform")]
    Unsupported(EffectKind),
    #[error("operating system error {code}: {message}")]
    Os { code: i64, message: String },
}

#[async_trait]
pub trait SystemObserver: Send + Sync {
    /// Look for the object a record describes and read back its creation
    /// credential. `Ok(None)`: not present.
    async fn observe(
        &self,
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError>;
    /// The interface with the expected identity (name and/or GUID), with
    /// its addresses; basic readiness waits for an address.
    async fn interface(&self, key: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError>;
    /// The process listening on a TCP address.
    async fn listener(&self, address: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError>;
    /// Interfaces held open by a process. This is the independent path for
    /// system-assigned names (macOS: the utun control sockets of `pid`, via
    /// `proc_pidinfo` file-descriptor enumeration, unit number -> `utunN`):
    /// basic readiness of such an instance waits for one of them to carry an
    /// address, and the host records the name it finds as the concrete key
    /// of the generation's interface record. Platforms where the host fixes
    /// the name may return what [`SystemObserver::interface`] finds.
    async fn interfaces_owned_by(&self, pid: u32) -> Result<Vec<InterfaceInfo>, ObserveError>;
    /// Full independent enumeration of one class of system objects, ours or
    /// not, for side-effect consistency diffs (G2 `sysdiff`).
    async fn enumerate(&self, class: SystemClass) -> Result<Vec<SystemEntry>, ObserveError>;
}

/// The object classes compared before and after an action in tier-3 tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SystemClass {
    Interfaces,
    Routes,
    DnsPolicy,
    FirewallRules,
    RegistryValues,
    Services,
    RuntimeDirs,
    Processes,
}

/// One enumerated object: a key plus a canonical description that changes
/// whenever the object's content changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SystemEntry {
    pub class: SystemClass,
    pub key: ObjectKey,
    pub description: String,
}

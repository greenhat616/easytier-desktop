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
}

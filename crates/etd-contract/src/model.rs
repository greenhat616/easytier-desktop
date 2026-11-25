//! Rust-side identifiers and the negotiated session summary. Wire messages
//! live in [`crate::v1`].
use crate::{HostMode, HostPhase, Role, Welcome};
use std::fmt;

/// Ledger revision of the desired state; increases with every committed
/// mutation.
pub type Revision = u64;

/// Client-generated instance identifier (a UUID string on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(pub String);

/// Client-generated request identifier; reused verbatim when retrying.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub String);

macro_rules! string_id {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}
string_id!(InstanceId);
string_id!(RequestId);

/// Outcome of the handshake as seen by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub major: u32,
    pub minor: u32,
    pub capabilities: Vec<String>,
    pub role: Role,
    pub host_mode: HostMode,
    pub host_phase: HostPhase,
    pub host_build: String,
    pub stream_id: String,
}

impl Negotiated {
    pub fn has_capability(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability == name)
    }
}

impl From<Welcome> for Negotiated {
    fn from(welcome: Welcome) -> Self {
        Self {
            major: welcome.major,
            minor: welcome.minor,
            role: welcome.role(),
            host_mode: welcome.host_mode(),
            host_phase: welcome.phase(),
            capabilities: welcome.capabilities,
            host_build: welcome.host_build,
            stream_id: welcome.stream_id,
        }
    }
}

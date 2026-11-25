//! Host-facing API shared by the UI and the CLI. Never depends on EasyTier.
mod host_client;
pub use host_client::*;

/// tonic client stubs for `etd.v1`, reusing the message types of
/// `etd_contract::v1`.
pub mod stub {
    tonic::include_proto!("etd.v1");
}

pub mod grpc;
pub mod negotiate;
pub mod reconnect;

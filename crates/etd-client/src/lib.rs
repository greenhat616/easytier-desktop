//! Host-facing API shared by the UI and CLI.
mod client;
pub use client::*;
pub mod grpc {
    tonic::include_proto!("etd.v1");
}

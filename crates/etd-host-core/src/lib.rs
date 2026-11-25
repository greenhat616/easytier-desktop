//! Host orchestration and service interface. Only abstract dependencies.
pub mod auth;
pub mod core_store;
pub mod supervisor;
pub mod grpc {
    tonic::include_proto!("etd.v1");
}

pub mod service;

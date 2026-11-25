//! Host orchestration and the contract service. Depends on trait crates
//! only (architecture boundary 3): every real implementation is injected
//! through [`api::HostDeps`].
//!
//! Frozen (F0): `api` (H1/H2 handle), the traits in `auth` and `core_store`.
//! H1 owns `lifecycle/`, `supervisor`, `boot`, `poller`, `fence_seq`,
//! `reclaimers`.
//! H2 owns `service/`, `auth/`, `core_store/`, `negotiate`, `events`.
pub mod api;
pub mod auth;
pub mod core_store;

/// tonic server stubs for `etd.v1`, reusing `etd_contract::v1` messages.
pub mod stub {
    tonic::include_proto!("etd.v1");
}

// H1
pub mod boot;
pub mod fence_seq;
pub mod lifecycle;
pub mod poller;
pub mod reclaimers;
pub mod supervisor;

// H2
pub mod events;
pub mod negotiate;
pub mod service;

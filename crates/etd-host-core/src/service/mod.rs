//! The `etd.v1.HostService` implementation over
//! [`crate::api::OrchestratorHandle`]: per-call version metadata
//! interceptor, per-method role checks from `etd_contract::required_role`,
//! idempotent commits, receipts, cursor-resumable events. Owned by H2.

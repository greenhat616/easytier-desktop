//! Instance state machine (basic / full readiness, backoff, gave up,
//! quarantine, cut-unconfirmed) and the orchestrator loop behind
//! [`crate::api::OrchestratorPort`]. Owned by H1.

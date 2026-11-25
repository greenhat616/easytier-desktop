//! Ledger conformance suite shared by the in-memory and SQLite ledgers.
//! Owned by L1.
//! Must cover the required cases listed in the `etd_sysfx::ledger` module
//! docs (claims held by an open generation across a config replacement,
//! compaction, idempotent replay).

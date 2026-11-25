//! SQLite ledger: one transaction per commit, dedicated blocking single
//! writer thread, WAL + synchronous=FULL (macOS fullfsync), versioned
//! migrations from `migrations/`. Owned by L1.

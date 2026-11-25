//! Startup self-check, six steps: singleton lock, open ledger + boot id,
//! orphan processes, reclaim open records in rank order, exclusive
//! containers / candidates, then serve and start desired instances.
//! Owned by H1.

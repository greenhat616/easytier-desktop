//! Startup self-check, six steps: singleton lock, open ledger + boot id,
//! orphan processes, reclaim open records in rank order, exclusive
//! containers / candidates, then serve and start desired instances.
//! In diagnose-only mode (ledger schema newer or unreadable) step 3 only
//! lists orphan processes and step 4 is `ReclaimEngine::diagnose`; nothing
//! is killed or deleted and no instance starts.
//! Owned by H1.

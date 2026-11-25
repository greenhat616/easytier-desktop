//! Reclaim engine: probe -> delete -> verify in rank order; delete only on a
//! matching credential or exclusive container, otherwise candidate; quarantine
//! after five failures; boot-id change closes volatile records unprobed;
//! repair-index name re-derivation after ledger loss. Owned by R1.

SQL migrations of the SQLite ledger. 000_baseline.sql defines the v0
fixture and is installed only on a genuinely empty database.
001_settings.sql upgrades that schema to v1, adding host settings, the removal-pending set and per-instance config revisions, in the same transaction. V0 had no per-config revision, so its configs start at the legacy snapshot revision.
Unknown schema versions or unreadable payloads are refused without writing.
Versioned JSON payloads are stored in typed rows, with request/ticket,
desired state, revision, epoch high-water, generation and ownership records
committed in a single SQLite transaction. Unsigned counters use decimal
TEXT to avoid the SQLite signed integer range limit.

A migration that changes the payload format or interpretation must not run
until reclaim has finished against the prior version's records (v7).
The v0 -> v1 migration is additive and preserves the prior payload format.

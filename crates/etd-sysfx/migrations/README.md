SQL migrations of the SQLite ledger. 000_baseline.sql defines the v0
fixture and is installed only on a genuinely empty database.
001_settings.sql upgrades that schema to v1, adding host settings and the removal-pending set, in the same transaction.
Unknown schema versions or unreadable payloads are refused without writing.
Versioned JSON payloads are stored in typed rows, with request/ticket,
desired state, revision, epoch high-water, generation and ownership records
committed in a single SQLite transaction. Unsigned counters use decimal
TEXT to avoid the SQLite signed integer range limit.

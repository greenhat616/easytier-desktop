# etd-sysfx

Side-effect bookkeeping for the host: the effect model, the ledger interface and its
SQLite implementation, the reclaim engine, and the interfaces that OS adapters
implement (reclaimers, sweeper, boot id, port fence, system observer). Host side,
library only. It never touches the system itself; the platform implementations live in
[`etd-sysfx-os`](../etd-sysfx-os/README.md).

The rule it encodes: every system object the kernel or the host creates is recorded
before the action ("record first, act second"), so the ledger can hold more than the
system but never less. Names only locate objects; deleting one needs the creation
credential read back after it appeared, or an exclusive container. See
[docs/ledger-and-reclaim.md](docs/ledger-and-reclaim.md) for the record life cycle, the
commit transaction and the reclaim order.

## Public surface

Frozen at `freeze-v1`: `lib.rs`, `Cargo.toml` and the modules `ledger`, `launch`,
`model`, `reclaim`, `fence`, `observe`, `naming` (signatures), plus the type name
`engine::ReclaimEngineImpl` and its `new(ReclaimDeps)`.

| Item | Purpose |
| --- | --- |
| `Effect`, `EffectIntent`, `EffectScope`, `EffectKind`, `EffectState` | A ledger record and what a planner asks to record |
| `ObjectKey`, `Credential`, `Observation` | Natural key (locates), creation credential (authorises), what a probe saw |
| `Undo`, `SettingValue`, `Persistence` | `EnsureAbsent` / `RestoreIfOurs` / `ReplayUpstreamRecovery`; lifetime incl. `Lease` |
| `Ledger`, `ChangeSet`, `Change`, `GenerationPlan`, `Ticket`, `RequestRecord` | Desired state, idempotent commits, epochs and claims |
| `RepairIndex`, `RepairIndexStore` | Out-of-ledger install key and instance list (for re-deriving names only) |
| `LaunchInputs`, `CoreRef`, `Privilege`, `ManagementGuard` | Persisted inputs of a generation's plan |
| `Reclaimer`, `Sweeper`, `BootIdSource`, `ReclaimDeps`, `ReclaimEngine`, `rank`, `QUARANTINE_AFTER` | Reclaim interfaces |
| `PortFence`, `FenceSpec`, `FenceVerification` | Management-port fence interface |
| `SystemObserver`, `SystemClass`, `SystemEntry` | Independent observation and enumeration |
| `naming::interface_name`, `naming::wintun_guid` | `etd-` + 8 hex of HMAC-SHA256(install key, instance); upstream's wintun GUID |
| `engine::ReclaimEngineImpl` | The reclaim engine |
| `sqlite::SqliteLedger`, `sqlite::OpenOptions` | SQLite ledger (one writer thread, WAL, `synchronous=FULL`) |

## Dependencies and boundaries

- **Used by:** `etd-core-api`, `etd-core-easytier`, `etd-sysfx-os`, `etd-host-core`,
  `etd-host`, `etd-testkit` (normal dependencies).
- **Depends on:** `etd-contract` only among workspace crates; `etd-testkit` as a
  dev-dependency.
- **Must not depend on:** system binding crates (`windows*`, `nix`, `libc`, `nftables`,
  ...) or `easytier*`. It is part of the closure `etd-host-core` may use, so it stays
  portable and kernel-free.

## Key modules

| Module | Responsibility |
| --- | --- |
| `model.rs` | Effect records, keys, credentials, undo, persistence, states, reports |
| `ledger.rs` | `Ledger` trait, change sets, generations, claims, tickets, errors |
| `launch.rs` | `LaunchInputs` and guards |
| `reclaim.rs`, `fence.rs`, `observe.rs` | Interfaces for OS adapters and the engine entry points |
| `naming.rs` | Interface name and wintun GUID derivation |
| `engine/` | `ReclaimEngineImpl`: per-record decision (`record.rs`), reports and candidate ids (`report.rs`) |
| `sqlite/` | Worker thread and storage (`mod.rs`, `storage.rs`), transactional state machine (`state.rs`), versioned on-disk codec (`codec.rs`) |
| `migrations/` | Schema SQL, see [migrations/README.md](migrations/README.md) |

The in-memory ledger used by tests is `etd-testkit` `fakes::ledger::MemoryLedger`; the
shared conformance suite is `etd-testkit` `conformance::ledger`. The repair index file
is implemented in `etd-host`; the `Process` and `RuntimeDir` reclaimers in
`etd-host-core`; all other reclaimers in `etd-sysfx-os`.

## Testing

```sh
cargo nextest run -p etd-sysfx
cargo test --doc -p etd-sysfx
```

All tests are unprivileged and use temporary directories, fakes and the in-memory
ledger.

| Test file | Covers |
| --- | --- |
| `ledger_conformance.rs` | The `etd-testkit` conformance suite against both `MemoryLedger` and `SqliteLedger` (idempotency, revision, claims while reclaiming, epochs and compaction, shared effects, pending removal) |
| `ledger_crash.rs` | Re-runs the test binary as a child, pauses its writer at each commit stage and kills it; reopening sees all or nothing (proptest) |
| `ledger_faults.rs` | Full disk, read-only, corrupt database, a pinned WAL reader |
| `ledger_format.rs` | Fixed JSON fixtures for persisted model types (format changes need a migration) |
| `ledger_migrate.rs` | v0 to v1 migration, newer schema left untouched, unknown kinds refused, scrubbing old tickets |
| `ledger_pragmas.rs` | WAL / synchronous / secure_delete on the writer connection; purge removes historical secrets |
| `reclaim_order.rs`, `reclaim_uncertain_hold.rs` | Process first, then rank order; a failing rank holds back higher ranks |
| `reclaim_credential.rs`, `reclaim_third_party.rs` | Foreign objects with our names are never deleted (conflict or candidate) |
| `reclaim_quarantine.rs`, `reclaim_idempotent.rs` | Quarantine after five failures, retry; second run writes nothing; reboot closes volatile records |
| `reclaim_left_in_place.rs` | `HeldBy` is a conflict and `NotDeletable` a candidate: no failure, self-closing once gone; other errors still quarantine |
| `reclaim_replay.rs` | Crash at every system or ledger step, then replay converges (proptest) |
| `reclaim_core.rs`, `reclaim_rulings.rs` | Core-binary and product scope, leases, decision gates, offline reports |

`reclaim_support/` is the shared fake system and harness.

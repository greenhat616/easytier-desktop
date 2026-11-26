# etd-testkit

Shared test support for the workspace (test-only library plus the `fake-core` binary):
fakes of the frozen traits, conformance suites, a scripted gRPC host, an in-memory
transport, the `NoWindow` helper, and the tier 2 / tier 3 test entry points. It is never
a normal dependency of a product crate: other crates take it as a dev-dependency only,
and `cargo xtask check-boundaries` fails on anything else (test isolation).

## Public surface

`src/lib.rs` and `src/fakes/mod.rs` are part of the `freeze-v1` interface set.

### Fakes (`fakes::*`), one per trait

| Module | Fake | Implements |
| --- | --- | --- |
| `auth` | `FakeAuthorizer` | `etd_host_core` `Authorizer`, with a configurable role. |
| `clock` | `FakeClock` | `etd_proc::Clock`; manually advanced monotonic and wall time. |
| `core` | `FakeCoreDriver`, `FakeCoreSession` | `etd_core_api` `CoreDriver` / `CoreSession`; plans like a real adapter (interfaces, management listener, Magic DNS claim) and scripts plan, attach, readiness and poll errors. |
| `host` | `FakeHostClient` | `etd_client::HostClient`; idempotent mutations by request id, revision checks, cursor-resumed events; scripts lost replies, rejections, duplicates and gaps. |
| `launcher` | `FakeHostLauncher` | `etd_app::HostLauncher`; scripted probe / ensure results. |
| `ledger` | `MemoryLedger` | `etd_sysfx` `Ledger`; same transactional state machine as SQLite, reusable across simulated restarts. |
| `process` | `FakeProcessEngine` | `etd_proc::ProcessEngine`; scripted spawns, exits, liveness and events, no real process. |
| `profiles` | `FakeProfileStore` | `etd_app::ProfileStore`; in memory, injectable load / save failures. |
| `store` | `FakeCoreStore` | `etd_host_core` `CoreStore`, with controllable verified kernels. |
| `system` | `FakeSystem` | `etd_sysfx` `Reclaimer`, `Sweeper`, `BootIdSource`, `SystemObserver`, `PortFence` over one in-memory machine with our and foreign objects, reboots and fault / crash injection at every step. |

There is no fake `TrayBackend` here; the `etd-app` and `etd-ui` tests define their own.

### Other modules

| Module | Purpose |
| --- | --- |
| `conformance::ledger` | Shared `Ledger` suite (idempotency, revisions and atomicity, claims, epochs and compaction, concurrency, shared effects, reservations, purge, ...). Each case gets a fresh empty ledger; run against `MemoryLedger` and the SQLite ledger. |
| `scripted_server` | `ScriptedHost`: real tonic `etd.v1.HostService` stubs over in-memory connections, with host semantics a client relies on (version metadata, idempotency, receipts, event resume with `ResyncRequired`) and scripted Welcome, replies, rejections, lost replies, drops, refusal and an impostor host. `ContractHost`: the real contract service on the same connections. |
| `transport` | `duplex()` in-memory `BoxConn` pair; `user_host()` builds the real contract service over `MemoryLedger` with a user-host allow-list authorizer. |
| `no_window` | `NoWindow` trait: `.no_window()` on `std` and tokio `Command` sets `CREATE_NO_WINDOW` on Windows (replacing earlier creation flags) and does nothing elsewhere. Every test spawn on Windows must use it. |
| `sysdiff` | Independent native inventory for tier 3 (`inventory.py`, Windows enumeration in `windows.ps1`): interfaces, routes, resolvers, firewall and WFP, registry, services, runtime directories and product processes. Snapshots are compared before and after; no product observer or ledger takes part. |

### `fake-core` binary

`src/bin/fake-core.rs` is a scriptable stand-in for `easytier-core` in process tests;
it is never packaged. Arguments (each takes a value):

| Argument | Effect |
| --- | --- |
| `--mode graceful\|ignore` | `graceful` exits on the first Ctrl+C / SIGINT / SIGTERM; `ignore` counts signals and keeps running. |
| `--ready-file <path>` | Publish its PID atomically (temp file + rename) after printing `READY <pid>` and a stderr line. |
| `--signal-log <path>` | Write the number of signals received. |
| `--exit-after-ms <ms>`, `--exit-file <path>`, `--exit-code <n>` | Exit after a delay or once a file exists, with the given code. |
| `--spawn-child <path>` | Start a descendant fake-core that publishes its own ready file (containment tests). |
| `-c` / `--config <path>` | Accepted like the real kernel's config flag. |
| `--host-probe <path>` | Act as a host: spawn a child through `ProcessKitEngine` and publish its identity (parent-death tests). |
| `--console-ctrl <pid>` | Helper mode: send Ctrl+C to that process's console and exit. |
| `--check-windows-env yes` | Fail unless `SystemRoot` / `windir` are consistent and a loopback socket can bind. |

It keeps running when its stdout/stderr pipes close, like a kernel that outlives its host.

## Dependencies and boundaries

- **Used by (dev-dependency only):** `etd-app`, `etd-client`, `etd-ctl`, `etd-host`,
  `etd-host-core`, `etd-ipc`, `etd-proc`, `etd-sysfx`, `etd-sysfx-os`, `etd-ui`.
- **Depends on:** `etd-app`, `etd-client`, `etd-contract`, `etd-core-api`,
  `etd-host-core`, `etd-ipc`, `etd-proc`, `etd-sysfx`, `etd-sysfx-os`.
- **Must not:** be a normal or build dependency of any crate (test isolation); depend
  on `etd-core-easytier` or `easytier*`, because `etd-host-core` tests use it and must
  never compile EasyTier (rule 3, kernel isolation).

## Testing

```sh
cargo nextest run -p etd-testkit
```

| Target | Content |
| --- | --- |
| `tests/real_process.rs` | Real `ProcessKitEngine` against `fake-core`: graceful stop, exit codes, tree kill on timeout, PID reuse, orphans, closed output pipes, parent death. |
| `tests/console_ctrl.rs` | Windows only: the hidden console helper delivers Ctrl+C exactly once. |
| `tests/tier2/` (`--test tier2`) | Tier 2: real host subprocess, native pipe/socket IPC, SQLite ledger and `fake-core`, with fake kernel driver and OS observations; no OS changes. Scenarios and the one privileged case are described in [`tests/tier2/README.md`](tests/tier2/README.md). |
| `tests/tier3/` (`--test tier3`) | Tier 3: the installed, unmodified service with the pinned release kernel on disposable GitHub-hosted runners only (`#[ignore]`, `require_runner()`). Rust entries run Python drivers: `product.py` (kernel and host crash recovery, native inventory, Magic DNS refusal, shared drivers, program rule conflict, bounded service stop, clean uninstall) and `takeover.py` with the `impostor.py` helper process (a foreign listener on the crashed kernel's management port and on the next generation's planned port; on macOS, reused utuns). Each running generation is compared with `sysdiff`, and the machine before install with the machine after uninstall. Run by `.github/workflows/privileged.yml`. |

The tier 2 privileged case (`killed_ui_does_not_stop_service_host_after_lease_grace`)
is `#[ignore]` and needs root / LocalSystem plus `ETD_G1_SERVICE_RUNTIME`; it runs only
with `--profile privileged --run-ignored only` in CI or a disposable VM, never on a
developer desktop. See [`../../docs/testing/README.md`](../../docs/testing/README.md).

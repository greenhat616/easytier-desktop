# Rust code guide

This is the style for handwritten Rust in the workspace (`Cargo.toml` at the
repository root). It covers how code is written; the crate split and the reasons behind
it are in the [architecture overview](../architecture/README.md), and building,
checking and committing are in [Development workflow](workflow.md).

Generated code (`prost`/`tonic` output under `OUT_DIR`) follows its generator and is
out of scope.

## 1. Rule status

- "Must" and "do not" are requirements. "Prefer" and "should" are defaults a review
  may waive for a stated reason.
- New code follows this guide even where nearby code does not. Existing code that does
  not is a known gap (section 12), not a pattern to copy.
- Keep changes minimal ([AGENTS.md](../../AGENTS.md) §3). Bring old code up to this
  guide in a focused change, not as part of unrelated work.

## 2. Toolchain and formatting

- `rust-toolchain.toml` pins **Rust 1.100.0** (stable) with `rustfmt` and `clippy`;
  the workspace uses edition 2024, resolver 3 and `rust-version = "1.100"`.
- Do not add `#![feature(...)]`; the toolchain is stable.
- Formatting is plain `rustfmt` with default settings (there is no `rustfmt.toml`).
  CI runs `cargo fmt --all -- --check`. Use `#[rustfmt::skip]` only for meaningful
  manual alignment, and say why.

## 3. Lints and suppressions

- CI runs `cargo clippy --locked --workspace -- -D warnings` on Windows, macOS and
  Linux. A warning anywhere, including `cfg(windows)` or `cfg(target_os = "macos")`
  code that only another OS compiles, fails the build. Some platform workflows add
  `--all-targets`; keep test code warning-free too.
- Every crate inherits `[lints] workspace = true`. The workspace currently allows
  `cargo::unused_dependencies` because the frozen manifests declared every planned
  dependency up front; this is temporary and will be tightened.
- Suppress a lint at the narrowest scope and give the reason. Prefer
  `#[expect(lint, reason = "...")]`, which warns once it is stale; otherwise
  `#[allow(lint, reason = "...")]`. Do not add crate-wide allow lists.

## 4. Crates, modules and dependencies

- Respect the crate roles: contract and trait crates (`etd-contract`, `etd-core-api`,
  the trait files of `etd-sysfx`, `etd-proc`, `etd-ipc`, `etd-client`), orchestration
  (`etd-host-core`, `etd-app`), adapters (`etd-proc`, `etd-ipc`, `etd-sysfx`,
  `etd-sysfx-os`, `etd-core-easytier`) and composition roots (`etd-host`, `etd-ui`,
  `etd-ctl`). `cargo xtask check-boundaries` enforces the dependency rules; see
  [workflow](workflow.md#architecture-boundaries).
- Add a dependency to `[workspace.dependencies]` and reference it with
  `{ workspace = true }`. Manifests are frozen interfaces
  ([workflow](workflow.md#frozen-interfaces)); a new dependency is a change request.
- Pinned versions (`=` requirements such as `gpui-kit`, `processkit`, `prost`, `tonic`)
  are deliberate. Do not bump them in passing.
- `cargo deny --locked check` gates licenses, sources and advisories. Only crates.io
  and the EasyTier Git repository are allowed sources. An advisory exception needs a
  reason and a condition for removing it, as in `deny.toml`.
- Keep EasyTier types inside `etd-core-easytier`. Other crates speak the contract
  (`etd-contract`) or the kernel-neutral model (`etd-core-api`).
- A crate's `lib.rs` declares its modules and says in `//!` docs which of them are
  frozen interfaces. Give a leaf module one responsibility.
- Use the narrowest visibility that serves real consumers. Avoid glob imports except
  `use super::*` in an inline `tests` module.

## 5. Types and traits

- Ports are traits owned by their consumer and kept narrow (`ProcessEngine`, `Ledger`,
  `Reclaimer`, `PortFence`, `SystemObserver`, `CoreDriver`, `HostClient`,
  `HostLauncher`). Injected dependencies are `Arc<dyn Trait>` or `Box<dyn Trait>`;
  use `#[async_trait]` for async methods on a trait used as `dyn`.
- Every real port has a fake in `etd-testkit`. When you add a trait method, extend the
  fake in the same change.
- Public enums in frozen interfaces are `#[non_exhaustive]`, so adding a variant is a
  compatible change. Security verdict enums (for example liveness and probe results)
  stay exhaustive so that a new verdict fails to compile where it is not handled.
- Use newtypes for identifiers that share a representation (instance ids, request ids,
  revisions, epochs) and typed enums for states, not strings or integers.
- Wire types live in `etd-contract`. Change them by editing the `.proto` files, never
  the generated Rust.

## 6. Errors, panics and fail-closed decisions

- Library crates use typed error enums with `thiserror`. Carry structured fields, not
  preformatted strings, and do not add catch-all `Other(String)` variants to new code.
- `anyhow` is for binaries (`etd-host`, `etd-ctl`, `etd-ui`), tests and test support.
  Add context where an error crosses a layer.
- At the contract boundary, map errors to the contract's typed error codes; clients
  (for example `etd-ctl` exit codes) depend on them.
- Do not panic on input from users, files, the network, the kernel process or the OS.
  In production code prefer `?`, `let ... else` and `match`; where an invariant really
  holds, use `expect("why it holds")` rather than a bare `unwrap()`. Tests may unwrap.
- **Fail closed.** A verdict the code cannot establish is not the convenient one:
  `Liveness::Uncertain` is never treated as dead, an object whose ownership cannot be
  proven is a candidate and is not deleted, a kernel version without an adapter profile
  is refused by a privileged host, and a fence that cannot be verified means no
  management RPC. Write new code the same way.

## 7. Async, threads and time

- Tokio is the runtime. Do not block an async worker: SQLite runs on the ledger's
  dedicated writer thread, and other blocking or OS calls go through
  `tokio::task::spawn_blocking` or a named thread.
- The UI has two executors: GPUI owns the main thread and Tokio runs on a background
  thread inside `etd-app`. They exchange messages over channels only and never share
  tasks or futures. Shutdown follows the exit gate order: settle pending requests,
  stop subscriptions, stop Tokio, then quit GPUI.
- Never hold a `std::sync` guard across `.await`; use `tokio::sync` only when a guard
  must live across an await point.
- Name long-lived threads (`std::thread::Builder::new().name(..)`).
- Time goes through the injected `Clock` (`etd-proc`) wherever behaviour depends on
  it (backoff, circuit breaker, poll rate), so tests use a fake clock instead of
  sleeping. Wall-clock timestamps use `jiff`; monotonic time uses `std::time::Instant`.
- Do not call `std::env::set_var` or `remove_var` outside tests.

## 8. Unsafe code and FFI

- `unsafe` belongs only in the crates that own system bindings: `etd-ipc`, `etd-proc`
  and `etd-sysfx-os` (test helpers in `etd-testkit` are the exception). Business logic,
  orchestration and UI code contain none.
- Wrap each unsafe call in a small safe function in a platform module. Own every
  handle or allocation with an RAII type (`OwnedHandle`, a `Drop` guard) so that error
  paths cannot leak it.
- Every `unsafe` block or `unsafe impl` in new code has a `// SAFETY:` comment stating
  the precondition and why it holds. Public unsafe functions document `# Safety`.
- Do not add `unsafe impl Send` or `Sync` to get past an executor boundary.

## 9. Platform code

- Gate platform code with `#[cfg(...)]` on the item or module and keep the
  counterpart (`cfg(not(...))` or per-OS modules with the same signatures) next to it.
  `etd-sysfx-os/src/lib.rs` dispatches to `windows/`, `linux/` and `macos/`.
- **Windows: no console windows.** Every child process spawned on Windows, in product
  code and in tests, sets `CREATE_NO_WINDOW` (`0x08000000`). Use
  `etd_testkit::no_window::NoWindow::no_window()` in tests and `creation_flags` (or ProcessKit's `create_no_window()`) in product code.
  `xtask/src/spawn_flags.rs` fails CI when a `Command::new(` under `crates/` has no
  flag nearby; a site that is never built for Windows, or whose helper sets the flag,
  says so with `// no-window: <reason>` on the line above. A `CREATE_NO_WINDOW` child
  gets its own `conhost.exe`; process-tree checks must account for it.
- Children start from a controlled environment: `etd-proc` gives every child a fixed
  trusted `PATH` and only the variables it needs. Privileged code resolves system
  directories through native APIs, not from environment variables, and treats the
  user's profile, `HKCU` and environment as untrusted input.
- Windows: the main thread has a 1 MiB stack. GPUI views build large components in
  small `#[inline(never)]` helpers returning `AnyElement` (see `etd-ui/src/views/ui.rs`)
  so debug builds do not overflow it.
- macOS has no parent-death signal; orphaned kernels are found by the next host's
  sweep. Linux uses a parent-death signal set from a dedicated thread, and ProcessKit
  may fall back from a cgroup to a process group.

## 10. Security-sensitive code

- Never log or snapshot network secrets. The plan and log paths redact them and tests
  check it (`plan_redaction`, tier-2 log redaction). The UI does not persist secrets.
- The host never reads files from user directories and never accepts a kernel path
  from a client. Kernels come only from the trusted bundle table embedded from
  `crates/etd-host/cores.lock`.
- Deletion requires a creation credential (LUID and device instance, interface index
  plus boot id, inode, or an exclusive container such as the WFP sublayer, nftables
  table, PF anchor or runtime directory). A name match alone is never enough.
- Settings are restored only when the current value is still the one we set.
- Authorisation is per method, by role, from OS peer credentials. Do not add a method
  without its `(etd.v1.required_role)` option.

## 11. Logging, documentation and tests

- Log with `tracing` and structured fields; there is no `log` crate in the workspace.
- A module starts with `//!` docs saying what it owns. Document every item exported to
  another crate with its contract (ownership, blocking or async requirements, units,
  ordering), not a restatement of its name. Do not commit commented-out code.
- Test pure logic with plain values, components with the fakes in `etd-testkit`, and
  real processes in tier 2. Use `proptest` for crash, ordering and convergence
  properties (keep the regression seeds), and `insta` snapshots for generated plans.
- Do not sleep for synchronisation; use acknowledgements, the fake clock, or explicit
  barriers.
- Privileged tests are `#[ignore = "<what runner it needs>"]` and run only through the
  `privileged` nextest profile. See [Testing](../testing/README.md).
- Tests use temporary directories, never real user configuration or the installed
  service's state.

## 12. Known gaps

These areas do not meet the guide yet. Fix each in a focused change.

1. Many `unsafe` blocks in `etd-ipc` and parts of `etd-sysfx-os` have no `// SAFETY:`
   comment.
2. Several lint suppressions use `#[allow(..)]` without a `reason`.
3. `cargo::unused_dependencies` is allowed workspace-wide until the manifests are
   reviewed.
4. Some production code still uses bare `unwrap()` where an invariant is assumed.

## 13. Review checklist

- `fmt`, Clippy with `-D warnings` (on every OS), `check-boundaries` and the affected
  crate's tests pass.
- The change is minimal, and new code follows this guide rather than nearby code.
- No EasyTier type outside `etd-core-easytier`; no adapter reached from
  `etd-host-core`; no system crate outside `etd-ipc`, `etd-proc`, `etd-sysfx-os`.
- Error, ownership and concurrency semantics match the trait's documented contract,
  and uncertain verdicts fail closed.
- Every new `unsafe` has its `SAFETY` comment; every new Windows spawn has
  `CREATE_NO_WINDOW`.
- Frozen files changed only through an approved change request.

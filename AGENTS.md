# AGENTS.md

EasyTier Desktop is a Rust workspace: a GPUI desktop client and a CLI that talk to a
host process over a versioned local gRPC contract, and a host that runs the upstream
EasyTier kernel, records every system side effect in a SQLite ledger before acting and
reclaims it after any exit. The system service and user host forms, the contract, the
ledger, reclaim and the per-OS adapters are implemented; the elevated session form,
installer packages and the visual design of the UI are in progress or planned.

## Mandatory reading: development standards

Before starting any repository work, read
[docs/development/README.md](docs/development/README.md) and the guides it routes to:
the [architecture overview](docs/architecture/README.md), the [Rust code
guide](docs/development/rust.md), the [development workflow](docs/development/workflow.md)
and [testing](docs/testing/README.md). Before changing a crate, read its `README.md`.

These guides are project requirements, not background. Follow them together with the
rules below; reading this file alone is not enough. If a guide is missing or conflicts
with the task, report it and resolve it before doing the affected work.

The behavioural guidelines in sections 1 to 4 reduce common coding-agent mistakes. They
favour caution over speed; for trivial tasks, use judgement.

## 0. Synchronisation policy

`CLAUDE.md` imports this file, so every agent follows the same instructions. The guides
under `docs/` hold the detailed rules; this file routes to them and restates only the
rules that are broken most often.

- When a shared rule changes, update its guide in the same change, and update this file
  only if it restates that rule.
- Link to guide sections instead of copying them here.
- Do not add a tool-specific or agent-specific exception to a project rule.

## 1. Think before coding

**Don't assume. Don't hide confusion. Surface trade-offs.**

- State your assumptions. If a request can be read two ways, say so; do not pick one
  silently.
- If a simpler approach exists, say so and push back when warranted.
- If something is unclear, stop and name what is unclear.
- Check the code before claiming how it behaves. Mark designed-but-unimplemented
  features as planned.

## 2. Simplicity first

**Minimum code that solves the problem. Nothing speculative.**

- No features, abstractions, configuration or error handling beyond what was asked
  and what can actually happen.
- If 200 lines could be 50, rewrite it.
- Simplicity never overrides the architecture: do not reach past a trait into an
  adapter, or add a dependency across a boundary, because it is shorter.

## 3. Surgical changes

**Touch only what you must. Clean up only your own mess.**

- Do not reformat, refactor or "improve" adjacent code. Match the existing layout; new
  code still follows the guides, not older patterns next to it.
- Mention unrelated problems you notice; do not fix them in the same change.
- Remove imports, variables and functions that your change made unused, and nothing
  else.

Every changed line should trace directly to the request.

## 4. Goal-driven execution

**Define success criteria. Loop until verified.**

Turn a task into checks: "fix the bug" becomes "write a test that reproduces it, then
make it pass". For multi-step work, state a short plan with a check per step:

```text
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
```

## 5. Workspace map and boundaries

| Crate | Role |
| --- | --- |
| `etd-contract` | `etd.v1` Protobuf contract, generated messages, version constants, role table |
| `etd-ipc` | Named pipes and Unix sockets, peer identity, server verification, tonic transport |
| `etd-client` | `HostClient` trait and its gRPC implementation: negotiation, reconnect, receipts |
| `etd-app` | UI logic without GPUI: state store, reducer, bridge, exit gate, tray state, launcher, profiles |
| `etd-ui` | GPUI desktop binary |
| `etd-ctl` | CLI binary |
| `etd-host` | Host binary: composition root, `run`, `install`, `uninstall`, `reclaim`, `doctor` |
| `etd-host-core` | Host orchestration and contract service; traits only |
| `etd-proc` | Process engine over ProcessKit, process identity, restart policy, clock |
| `etd-sysfx` | Side-effect model, ledger (SQLite), reclaim engine, fence and observer traits |
| `etd-sysfx-os` | Windows / Linux / macOS adapters and service installation |
| `etd-core-api` | Kernel adapter traits and plan model, independent of EasyTier |
| `etd-core-easytier` | The only EasyTier adapter: launch plans, effect prediction, management session |
| `etd-testkit` | Fakes, conformance suites, `fake-core`, tier-2/3 tests; test-only |
| `xtask` | `cargo xtask check-boundaries`, `cargo xtask fetch-cores` and repository tests |

`cargo xtask check-boundaries` fails CI on any violation
([rules](docs/development/workflow.md#architecture-boundaries)). Restated because they
are the most common violations:

- Nothing in the closure of `etd-ui`, `etd-app` or `etd-client` may reach
  `etd-core-easytier` or any `easytier*` crate. EasyTier types stay inside
  `etd-core-easytier`.
- Only `etd-proc` uses `processkit`. System binding crates (`windows*`, `nix`, `libc`,
  `rtnetlink`, `nftables`, `zbus`, `system-configuration`, ...) are direct
  dependencies only of `etd-sysfx-os`, `etd-ipc` and `etd-proc`.
- `etd-host-core` depends only on `etd-contract`, `etd-ipc`, `etd-proc`, `etd-sysfx`
  and `etd-core-api`. New behaviour reaches the OS through a trait injected by
  `etd-host`, never directly.
- `etd-testkit` is only ever a dev-dependency.

## 6. Frozen interfaces

Tagged `freeze-v1`: `crates/etd-contract/**`, `buf.yaml`, every `Cargo.toml` and
`lib.rs`, the trait and model files each `lib.rs` names as frozen, and
`etd-testkit/src/lib.rs` and `fakes/mod.rs`. See
[Frozen interfaces](docs/development/workflow.md#frozen-interfaces).

- Do not edit a frozen file as part of other work. Propose the change to the
  maintainers first (file, change, reason) and wait for approval.
- Compatible changes (new field, new variant of a `#[non_exhaustive]` enum, new method
  with a default body, new contract method) land as their own small PR.
- Breaking changes need a review of every consumer, and for the contract a new major
  version.
- Contract changes edit the `.proto` files, keep `(etd.v1.required_role)` on every
  method, pass `buf lint` and `buf breaking` against `freeze-v1` and against the
  start of the change (CI's `contract` job), and regenerate the descriptor baseline
  with `ETD_UPDATE_BASELINE=1 cargo nextest run -p etd-contract`.
- A new dependency is a manifest change: it goes into `[workspace.dependencies]` and
  needs approval.

## 7. Build and test

Follow [Development workflow](docs/development/workflow.md) and
[Testing](docs/testing/README.md).

- Always pass `--locked`. If you change dependencies, commit `Cargo.lock` with the
  change.
- Use a separate `CARGO_TARGET_DIR` per worktree or concurrent package build. Keep
  build load low: `CARGO_BUILD_JOBS=4`, at most four package builds at a time. If a
  build runs out of memory, report it; do not retry in a loop.
- Locally, run `fmt`, `check-boundaries`, Clippy with `-D warnings` and the affected
  crate's tests (`cargo nextest run --locked -p <crate>`). The three-platform matrix and
  privileged jobs run in CI: push and read the CI result rather than reproducing other
  operating systems locally.
- **Never run privileged tests on a developer desktop.** They are `#[ignore]` and run
  only with `--profile privileged --run-ignored only` on disposable CI runners or VMs.
  Do not run `etd-host install`, `uninstall` or `reclaim --all --purge` on a developer
  machine either.
- Use the fakes in `etd-testkit` and the fake clock; do not sleep in tests.

## 8. Platform rules

- **Windows child processes never open a window.** Every spawn of a console program on
  Windows, in product code and in tests (fake core, helpers, the CLI under test), sets
  `CREATE_NO_WINDOW` (`0x08000000`). A visible console flashing on a user's machine is
  a bug. `cargo nextest run -p xtask` checks it; a site that needs no flag says why
  with `// no-window: <reason>` on the line above. Such a child gets its own
  `conhost.exe`, which process-tree checks must allow for.
- `unsafe` lives only in `etd-ipc`, `etd-proc` and `etd-sysfx-os`, in small safe
  wrappers, each block with a `// SAFETY:` comment.
- Gate platform code with `#[cfg]` and keep every OS compiling: Clippy runs with
  `-D warnings` on Windows, macOS and Linux.

## 9. Security rules

- Never put secrets (network secrets, passwords, tokens, keys) in code, tests,
  fixtures, snapshots, logs or commit messages. Logs and plans redact network secrets;
  the UI never persists them.
- Kernels come only from the trusted bundle table embedded at build time from
  `crates/etd-host/cores.lock`; a local manifest cannot add one, and clients never
  choose a kernel path. Never edit `cores.lock` by hand: it is generated from the
  release pinned in `packaging/cores.toml` by `cargo xtask fetch-cores --update-lock`.
- The host never reads files from user directories. Privileged code treats the user's
  environment, profile and `HKCU` as untrusted and resolves system paths through native
  APIs.
- Never delete an OS object by name alone. Deletion needs a creation credential or an
  exclusive container; otherwise report a candidate. Uncertain verdicts fail closed.
- Every contract method declares its required role; authorisation comes from OS peer
  credentials, never from a shared secret.

## 10. Code style

| Area | Guide |
| --- | --- |
| Rust style, errors, async, unsafe, platform code, known gaps | [Rust code guide](docs/development/rust.md) |
| Building, checks, frozen interfaces, branches, commits | [Development workflow](docs/development/workflow.md) |
| Test tiers, privileged tests, CI workflows | [Testing](docs/testing/README.md) |
| Processes, crates, channels, host forms, ledger and reclaim | [Architecture](docs/architecture/README.md) |

Apply the guides when planning, not only at review. Existing violations are known gaps;
do not copy them and do not fix them outside the task.

## 11. Git commits

Follow [Git commits](docs/development/workflow.md#git-commits).

- Conventional Commits 1.0: `type(scope)!: summary`. The scope is the crate name
  (`fix(etd-proc): ...`, `docs(etd-host): ...`), or `workspace`, `xtask`, `ci`.
- Stage explicit paths only; never `git add .`, `-A` or `--all`.
- One commit does one thing and builds. No fix-up commits on unpushed work; rewriting
  pushed history needs consent.
- Do not work on `main`, do not skip hooks, and do not merge without green CI on all
  three platforms.

## 12. Final review

Before finishing, walk the [review checklist](docs/development/rust.md#13-review-checklist):
every changed line traces to the request, the success criteria were verified, no
boundary was crossed, no frozen file changed without approval, no secret entered the
repository, and every new Windows spawn sets `CREATE_NO_WINDOW`.

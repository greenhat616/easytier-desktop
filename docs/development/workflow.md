# Development workflow

How to build, check, change frozen interfaces and commit. Code style is in the
[Rust code guide](rust.md); test design and CI jobs are in [Testing](../testing/README.md).

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.100.0 | Installed by `rustup` from `rust-toolchain.toml`, with rustfmt and Clippy. MSVC toolchain on Windows. |
| protoc | 36.2 | Must be on `PATH`. CI installs it with `.github/scripts/setup-protoc.ps1`. |
| cargo-nextest | 0.9.x | Test runner used by CI (`0.9.152` there) and by the `.config/nextest.toml` profiles. |
| cargo-deny | 0.22.x | Dependency policy check (`deny.toml`). |
| buf | any v2 | Optional locally: contract lint and breaking-change check (`buf.yaml`). |

Platform toolchains: MSVC and the Windows SDK on Windows; Xcode Command Line Tools on
macOS; on Linux, the native build, graphics and windowing libraries listed in the
`check` job of `.github/workflows/ci.yml`.

## Build and run

```sh
cargo build --workspace --locked
cargo run -p etd-ui                        # desktop app
cargo run -p etd-host -- run --mode user   # user host in the foreground
cargo run -p etd-host -- doctor            # host diagnostics, no privileges needed
cargo run -p etd-ctl -- --host user --json status
```

Always pass `--locked`: CI does, and `Cargo.lock` is part of every change that alters
dependencies. Whoever changes dependencies commits the resulting `Cargo.lock` in the
same commit.

`cargo xtask` is an alias (`.cargo/config.toml`) for `cargo run --package xtask --`.

### Target directories and build load

- Give each worktree, and each concurrent package build that compiles a different
  version of a frozen interface, its own `CARGO_TARGET_DIR`. Never share one writable
  target directory between worktrees through links.
- Limit build load on shared machines: `CARGO_BUILD_JOBS=4` and no more than four
  package builds at the same time. If a build is killed for lack of memory, report it;
  do not retry in a loop.
- `CARGO_PROFILE_DEV_DEBUG=0` (as CI sets) saves link time and disk, above all on
  Windows.

## Checks

Run these before pushing; CI runs all of them. Locally, run the `buf` checks
whenever you touch the contract. CI's `contract` job runs `buf lint`, and `buf breaking`
against `freeze-v1` and against the start of the change (the merge base with `main`,
or `main`'s previous commit).

| Check | Command |
| --- | --- |
| Formatting | `cargo fmt --all -- --check` |
| Architecture boundaries | `cargo xtask check-boundaries` |
| Lints | `cargo clippy --locked --workspace -- -D warnings` |
| Tests (affected crate) | `cargo nextest run --locked -p <crate>` |
| Tests (workspace, CI profile) | `cargo nextest run --locked --workspace --profile ci` |
| Doc tests | `cargo test --locked --workspace --doc` |
| Repository tests | `cargo nextest run --locked -p xtask` |
| Dependency policy | `cargo deny --locked check` |
| Contract lint | `buf lint` |
| Contract compatibility | `buf breaking --against '.git#tag=freeze-v1'` and `buf breaking --against ".git#ref=$(git merge-base origin/main HEAD)"` |

### CI first

The full matrix (Windows, macOS, Linux) and every privileged job run in GitHub
Actions. Locally, run the checks above for the crates you touched; then push and read
the CI result instead of trying to reproduce other operating systems or privileged
scenarios on your machine.

**Never run privileged tests on a developer desktop.** They create TUN adapters,
firewall and WFP rules, services and second user accounts. They are `#[ignore]` and run
only with `--profile privileged --run-ignored only` on disposable CI runners or VMs. See
[Testing](../testing/README.md#tier-3-privileged).

## Architecture boundaries

`cargo xtask check-boundaries` reads `cargo metadata` (all targets, all features) and
fails on any of these:

| Rule | Meaning |
| --- | --- |
| rule 1 | The dependency closure of `etd-ui`, `etd-app` and `etd-client` contains neither `etd-core-easytier` nor any `easytier*` crate. |
| rule 2 | Only `etd-proc` depends on `processkit`; system binding crates (`windows*`, `winapi*`, `netlink*`, `rtnetlink`, `nix`, `libc`, `nftables`, `zbus`, `system-configuration`) are direct dependencies only of `etd-sysfx-os`, `etd-ipc` and `etd-proc`. |
| rule 3 | `etd-host-core` depends only on `etd-contract`, `etd-ipc`, `etd-proc`, `etd-sysfx` and `etd-core-api` (plus `etd-testkit` for tests), so its tests never compile EasyTier. |
| test isolation | `etd-testkit` is only ever a dev-dependency. |
| contract isolation | `etd-contract` depends only on `prost` and `prost-build`. |
| kernel isolation | Only `etd-core-easytier` depends on `easytier*` crates. |

Normal, build and dev dependencies and every target `cfg` count. Transitive
dependencies of third-party crates do not count for rule 2. See
[`xtask/README.md`](../../xtask/README.md).

## Frozen interfaces

The interfaces tagged `freeze-v1` let several people work in parallel without
breaking each other. Frozen:

- `crates/etd-contract/**` and `buf.yaml`;
- the root `Cargo.toml` and every crate's `Cargo.toml` and `lib.rs`;
- the trait and model files that each crate's `lib.rs` names as frozen (for example
  `etd-proc` `engine`/`model`/`restart`, `etd-sysfx` `ledger`/`model`/`reclaim`/
  `fence`/`observe`/`launch`/`naming`, `etd-core-api` `driver`/`model`,
  `etd-client` `host_client`, `etd-app` `launcher`/`profiles`/`tray`, `etd-ipc`
  `transport`, `etd-host-core` `api` and the traits in `auth` and `core_store`);
- `crates/etd-testkit/src/lib.rs` and `crates/etd-testkit/src/fakes/mod.rs`.

How a change is approved:

1. Open a change request with the maintainers (an issue or a draft PR) that names the
   file, the change and why it is needed. Do not edit a frozen file as a side effect
   of other work.
2. **Compatible** changes (a new field, a new enum variant on a `#[non_exhaustive]`
   enum, a new trait method with a default body, a new contract method or message) are
   reviewed and merged as a small PR of their own; affected branches rebase onto it.
3. **Breaking** changes (a changed signature, a removed or renumbered field, a changed
   meaning) need an explicit review of every consumer before they merge, and for the
   contract a new major version.

### Changing the contract

- The `.proto` files under `crates/etd-contract/proto/` are the source of truth.
  Never edit generated code.
- Every RPC method declares `(etd.v1.required_role)`; `etd_contract::required_role`
  reads the same table.
- Within `etd.v1` only additive changes are allowed. `buf breaking` against
  `freeze-v1` and against the start of the change must pass. `buf.yaml` exempts
  `host.proto` from `FIELD_SAME_CARDINALITY` for the two `NetworkFlags` fields that
  `3dcf200` gave explicit presence (wire compatible, approved).
- The descriptor baseline `crates/etd-contract/tests/baseline/etd.v1.txt` is checked
  by the tests. After an approved additive change, regenerate it with
  `ETD_UPDATE_BASELINE=1 cargo nextest run -p etd-contract` and include the diff in
  review.

See [`crates/etd-contract/docs/versioning.md`](../../crates/etd-contract/docs/versioning.md).

## Branches and worktrees

- Do not work on `main`. Use one branch per piece of work and, for anything larger than
  a small fix, a separate `git worktree` with its own target directory.
- Rebase onto `main` before merging; every merge needs green CI on all three
  platforms.

## Git commits

- Commit messages follow [Conventional Commits 1.0](https://www.conventionalcommits.org):
  `type(scope)!: summary`, with type one of `feat`, `fix`, `docs`, `style`,
  `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- The scope is the crate name (`feat(etd-sysfx): add sqlite ledger`,
  `fix(etd-proc): ...`), `workspace` for changes across the workspace, or `xtask` /
  `ci` for tooling.
- The summary is imperative, at most 72 characters, without a trailing period. A
  non-trivial change explains why in the body.
- Stage explicit paths. Never `git add .`, `-A` or `--all`.
- One commit does one thing and builds. Fold a correction into the unpushed commit it
  completes; rewriting pushed history needs the maintainers' consent.
- Do not skip hooks or checks (`--no-verify`).

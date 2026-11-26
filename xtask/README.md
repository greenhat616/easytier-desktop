# xtask

Repository checks for the workspace (binary, not published). It has one command,
`cargo xtask check-boundaries`, which enforces the architecture dependency rules, and
two test-only checks that run as ordinary unit tests: the Windows `CREATE_NO_WINDOW`
spawn check and the privileged CI profile check. The `cargo xtask` alias is defined in
`.cargo/config.toml` (`run --package xtask --`).

## `cargo xtask check-boundaries`

```sh
cargo xtask check-boundaries
```

Runs `cargo metadata --locked --all-features` on the workspace (no platform filter, so
every target is seen), prints each violation as `<rule>: <detail>` on stderr and exits
non-zero, or prints `All architecture boundaries passed.` CI runs it on every push and
pull request (`boundaries` job in `.github/workflows/ci.yml`).

### Rules, as printed

| Name | Rule |
| --- | --- |
| `rule 1` | The dependency closures of `etd-ui`, `etd-app` and `etd-client` contain neither `etd-core-easytier` nor any `easytier*` crate. The detail is one shortest path, e.g. `etd-app -> x -> easytier`. |
| `rule 2` | Only `etd-proc` depends on `processkit`. System binding crates (`windows`, `windows-*`, `winapi`, `winapi-*`, `netlink*`, `rtnetlink`, `nix`, `libc`, `nftables`, `zbus`, `system-configuration`) are direct dependencies only of `etd-sysfx-os`, `etd-ipc` and `etd-proc`. |
| `rule 3` | `etd-host-core` directly depends on no `etd-*` or kernel crate other than `etd-contract`, `etd-ipc`, `etd-proc`, `etd-sysfx`, `etd-core-api` (plus `etd-testkit` as a dev-dependency). Its library closure reaches no other `etd-*` or kernel crate through those, and the closure of its tests (testkit included) contains no `easytier*` / `etd-core-easytier`. |
| `test isolation` | `etd-testkit` is only ever a dev-dependency. |
| `contract isolation` | `etd-contract` has no normal or build dependency other than `prost` / `prost-build`. |
| `kernel isolation` | Only `etd-core-easytier` declares a dependency on an `easytier*` crate. |

Rule 2 and the isolation rules apply to direct dependencies declared by workspace members,
so third-party crates may use `libc` and the like internally. Dependencies are judged by
their real package name, so renaming a dependency in `Cargo.toml` does not hide it.

### What counts

- **Dependency kinds:** normal, dev and build dependencies all count. A direct
  violation's detail names the kind and target, e.g.
  `etd-host directly depends on etd-testkit (build-dependency)`.
- **Target cfgs:** every `[target.'cfg(...)'.*dependencies]` section counts, whatever
  the host platform, because the metadata is not filtered by platform. Optional
  dependencies count too (`--all-features`).
- **Closures:** a closure is what building a package and its own tests pulls in. It is
  computed breadth first over the resolve graph: the root's dependencies of every kind,
  then only normal and build dependencies of everything reached, because Cargo never
  builds the dev-dependencies of a dependency. Rule 3's library closure leaves out the
  root's dev-dependencies; its test closure includes them.

## Test-only repository checks

These live in `src/spawn_flags.rs` and `src/ci_config.rs`, compiled only under
`#[cfg(test)]`, and read the repository from disk.

### Windows spawn flags (`spawn_flags.rs`)

Every child process that can be spawned on Windows must not open a console window. A
text scan over every `.rs` file under `crates/` requires each `Command::new(` to be
followed, within 24 lines and before the next `Command::new(`, by `.no_window()` (the
`etd_testkit::no_window::NoWindow` helper), `creation_flags(` or `.create_no_window()`.
Comments do not count. `assert_cmd`'s `cargo_bin_cmd!` / `cargo_bin(` are always reported,
because they leave no way to set creation flags.

Skipped: files that never build for Windows, by path (a `linux`, `macos` or `unix`
directory, or `unix.rs`) or by a crate-level `#![cfg(unix)]`,
`#![cfg(target_os = "linux")]` or `#![cfg(target_os = "macos")]`. A single site that
needs no flag where it is built carries a marker on the line directly above it:

```rust
// no-window: Linux only
let mut cmd = Command::new("pkexec");
```

The reason must say why: the code is not built on Windows, or a helper sets the flag.

### Privileged CI profile (`ci_config.rs`)

Nextest has no profile key for `--run-ignored`, so the `privileged` profile selects only
`#[ignore]` tests because every command that uses it passes `--run-ignored only`. The
tests check that `.config/nextest.toml` defines `[profile.privileged]`, that every
non-comment line in `.github/workflows/*` that uses `--profile privileged` (or
`--profile=privileged`) also contains `--run-ignored only`, and that at least one
workflow uses the profile.

## Testing

```sh
cargo nextest run -p xtask
```

This runs the spawn-flag and CI-config checks over the real repository, plus the
boundary rule tests in `src/boundaries/tests.rs`. Those generate synthetic workspaces
of empty path crates in a temporary directory and run `cargo metadata --offline` on
them, so each rule is exercised with Cargo's real metadata shape (every dependency kind,
`cfg(windows)` / Linux / macOS target sections, renamed and disabled optional
dependencies). Nothing is privileged and nothing needs the network.

## Dependencies and boundaries

Depends on `anyhow`, `cargo_metadata`, `clap`, `serde_json` (`tempfile` for tests). It
depends on no workspace crate and nothing depends on it. See
[`../docs/development/workflow.md`](../docs/development/workflow.md) and
[`../docs/architecture/README.md`](../docs/architecture/README.md).

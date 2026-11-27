# xtask

Repository tasks for the workspace (binary, not published). It has three commands:
`cargo xtask check-boundaries`, which enforces the architecture dependency rules,
`cargo xtask fetch-cores`, which downloads and verifies the bundled upstream kernels, and
`cargo xtask dist`, which stages a release payload and builds its installer package.
Two test-only checks that run as ordinary unit tests: the Windows `CREATE_NO_WINDOW`
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

## `cargo xtask fetch-cores`

```sh
cargo xtask fetch-cores                                   # every pinned target, check cores.lock
cargo xtask fetch-cores --target host --bundle target/debug/cores
cargo xtask fetch-cores --release v2.7.1 --update-lock    # regenerate cores.lock
```

`packaging/cores.toml` pins the bundled upstream release: repository, tag, commit, the
kernel version `--version` prints, and per target triple one release archive with its
SHA-256 and the companion files to keep (Windows: `Packet.dll`, `wintun.dll`, and on
x86_64 `WinDivert64.sys`; the arm64 archive's `WinDivert64.sys` is a text placeholder
and is left out). The command:

1. downloads the release's `SHA256SUMS` and each selected archive with `curl -q`
   (no curlrc; `https` only, redirects too; `CREATE_NO_WINDOW` on Windows; size
   limits);
2. requires each archive's digest to equal both the pin and `SHA256SUMS`, and fails
   otherwise;
3. extracts by exact file name only `easytier-core[.exe]` and the listed companions
   (no directories, symlinks, unsafe paths, duplicates or oversize members; a missing
   one fails) into a staging directory beside the destination, mode 0755 for the
   kernel on Unix;
4. by default checks the extracted SHA-256 against `crates/etd-host/cores.lock`
   (parsed with `etd-host`'s own `core_lock.rs`); with `--update-lock` (every target,
   never combined with `--target`/`--bundle`) it rewrites the table instead;
5. only then replaces `<version>/` with the staging directory. On any failure the
   staging directory is removed and nothing is published.

| Option | Effect |
| --- | --- |
| `--release <tag>` | Must equal the pinned tag; a different release means editing `packaging/cores.toml` |
| `--target <triple>` | Repeatable; `host` is the running machine. Default: every pinned target |
| `--out <dir>` | Writes `<dir>/<triple>/<version>/`. Default: `<target dir>/etd-cores` |
| `--bundle <dir>` | One target only: writes `<dir>/<version>/`, the `cores/` layout `etd-host install` imports from beside its image |
| `--github-env <NAME>` | One target only: after verification appends `NAME=<absolute kernel path>` to `$GITHUB_ENV` |
| `--update-lock` | Regenerates `cores.lock` from all pinned targets |

CI uses it in `ci.yml` (`session_real` on every OS, `install_roundtrip` beside the test
host image) and in the O1/O2/O3 workflows. Binaries are never committed.

## `cargo xtask dist`

```sh
cargo xtask dist                       # this machine's target, release binaries
cargo xtask dist --dry-run             # stage, verify and render; no packaging tool
cargo xtask dist --bin-dir target/debug --cores target/debug/cores/2.7.1 --out out --package-version 0.1.1
```

1. Copies `etd-ui`, `etd-host` and `etd-ctl` and every file of the kernel bundle into a
   fresh `<out>/<triple>/payload/` (`cores/<version>/` beside the binaries, the layout the
   package installs). Links and directories are refused.
2. Checks the staged bundle against `crates/etd-host/cores.lock` with `etd-host`'s own
   `core_lock.rs`: the executable and every companion with its SHA-256, and no other file.
   Only the payload that was checked is packaged. The staged `etd-host` must embed every
   digest of that row (it was built from the same `cores.lock`) and must not carry the CI
   fault hook (`ci-test-fixtures`, recognised by the `ETD-CI-TEST-FIXTURES-BUILD` marker
   that feature compiles in); on
   Windows `etd-ui.exe` must be a GUI-subsystem (release) build, so it opens no console.
   `--allow-test-fixtures` lifts the last two checks for CI test packages.
3. Runs the target's packager: on Windows (`dist/windows.rs`) it renders
   `packaging/windows/Product.wxs.tmpl` into `<out>/<triple>/Product.wxs` (MSI version,
   payload paths, one component per kernel file, `packaging/assets/icons/app.ico` as the
   Add/Remove Programs icon) and, unless `--dry-run`, runs
   `wix build -acceptEula wix7 -arch x64 -ext WixToolset.Util.wixext` (WiX 7.0.1 required,
   `CREATE_NO_WINDOW`) into `easytier-desktop-<version>-<arch>.msi`. On Linux
   (`dist/linux.rs`) it renders the maintainer scripts and
   `packaging/linux/nfpm.yaml.tmpl` into `<out>/<triple>/` and, unless `--dry-run`, runs
   nfpm 2.49.0 once per format into a `.deb`, an `.rpm` and a `.pkg.tar.zst`. Other
   targets fail.
4. Runs the sign hook; `none`, the only one, leaves the package unsigned.

| Option | Effect |
| --- | --- |
| `--target <triple>` | Default `host` |
| `--bin-dir <dir>` | Built binaries. Default `<target dir>/<triple>/release`, else `<target dir>/release` |
| `--cores <dir>` | Kernel bundle. Default `<target dir>/etd-cores/<triple>/<kernel version>` (`fetch-cores` output) |
| `--out <dir>` | Default `<target dir>/dist` |
| `--package-version <x.y.z>` | Default the workspace version; no pre-release tag (installers order versions numerically) |
| `--dry-run` | Skip the packaging tool |
| `--sign-hook none` | Default; v1 packages are unsigned (issue #2) |
| `--allow-test-fixtures` | CI test packages only: accept an `etd-host` built with `ci-test-fixtures` and a debug `etd-ui` |

The MSI's design, custom actions and failure behaviour are in
[`../docs/packaging/README.md`](../docs/packaging/README.md).

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

This runs the spawn-flag and CI-config checks over the real repository, the
`fetch-cores` checks (the committed `cores.lock` covers exactly the pinned targets and
companions, pin validation, `SHA256SUMS` parsing, extraction from a synthetic zip; no
network), the `dist` checks (staging, bundle verification against a lock, the staged host's
fixture marker and embedded digests, the PE subsystem, MSI template rendering and
placeholders, custom-action conditions, MSI version limits), plus the
boundary rule tests in `src/boundaries/tests.rs`. Those generate synthetic workspaces
of empty path crates in a temporary directory and run `cargo metadata --offline` on
them, so each rule is exercised with Cargo's real metadata shape (every dependency kind,
`cfg(windows)` / Linux / macOS target sections, renamed and disabled optional
dependencies). Nothing is privileged and nothing needs the network.

## Dependencies and boundaries

Depends on `anyhow`, `cargo_metadata`, `clap`, `serde`, `serde_json`, `sha2`,
`tempfile`, `toml` and `zip` (deflate only), and needs `curl` on `PATH` for
`fetch-cores` and `wix` 7.0.1 for `dist` on Windows. It depends on no workspace crate (it compiles `etd-host`'s `core_lock.rs`
by path) and nothing depends on it. See
[`../docs/development/workflow.md`](../docs/development/workflow.md) and
[`../docs/architecture/README.md`](../docs/architecture/README.md).

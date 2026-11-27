# Testing

Tests are organised in tiers by what they need from the machine. The lower tiers run
everywhere on every push; the privileged tier runs only on disposable CI runners or
VMs. The judge of "clean" in the upper tiers is an independent enumeration of the
operating system, never the ledger's own opinion.

## Tiers

| Tier | What | Needs | Where it runs |
| --- | --- | --- | --- |
| 0 | Pure logic: state machines, reducers, launch plans, ledger crash injection (property tests), contract descriptor and role checks, boundary checks | Nothing | Every push, three platforms |
| 1 | Components with fakes: host orchestration with every port faked, UI logic against a fake host, IPC and gRPC over in-memory or real local transports | Nothing | Every push, three platforms |
| 2 | Real processes, unprivileged: a real user-form host, the `fake-core` binary, real pipes and sockets, killing the host or UI and checking self-check | Normal user | Every push, three platforms |
| 3 | Privileged: real TUN adapters, firewall/WFP/nftables/PF objects, service install, second accounts, the real `easytier-core` | Administrator / root on a disposable runner | CI jobs and manually dispatched workflows only |

Tiers 0 to 2 are the default `cargo nextest run` suite. Tier 3 tests are marked
`#[ignore = "<what the runner needs>"]` and are selected only by the `privileged`
profile.

### Tier 0 and 1: unit and component tests

Each crate's `tests/` directory and inline `#[cfg(test)]` modules. Notable suites:

- `etd-contract`: wire compatibility, descriptor baseline, method-to-role table.
- `etd-sysfx`: one ledger conformance suite run against the in-memory and SQLite
  ledgers; crash injection at every commit stage (`ledger_crash`, `proptest`);
  disk-full, read-only and corrupt databases; migrations; reclaim replay, ordering,
  idempotence, quarantine and third-party protection against a fake system.
- `etd-host-core`: the five exit scenarios, generations, fence ordering, states,
  boot self-check and poll rate, all with fakes from `etd-testkit` and a fake clock;
  contract service handshake, version metadata, roles, idempotency and event cursors.
- `etd-core-easytier`: `insta` snapshots of generated plans per platform, identity
  derivation, predicted effects, feature classification and secret redaction.
- `etd-app` and `etd-client`: reducer, window/tray convergence under out-of-order
  events (`proptest`), exit gate order, reconnect and receipt recovery.
- `xtask`: boundary rules on synthetic metadata, the Windows `CREATE_NO_WINDOW` text
  check, and the privileged-profile selection check.

### Tier 2: real processes

`crates/etd-testkit/tests/tier2` runs a real user-form host built from the product's
own serving code with the `fake-core` process, real local IPC, SQLite and ProcessKit:
killing the host while a kernel runs, between intent and spawn, and in the middle of
reclaim; killing the UI; lease expiry; lost responses; abnormal kernel exits; log
redaction. See its [README](../../crates/etd-testkit/tests/tier2/README.md) for what is
real and what is simulated. Some crates also run real processes in their own tests (for
example `etd-host` `user_mode_e2e` and `singleton`, `etd-ipc` peer credentials and
server verification).

### Tier 3: privileged

**Never run these on a developer desktop.** They install services, create adapters and
firewall rules, and create local user accounts.

```sh
cargo nextest run --locked --profile privileged -p <crate> --run-ignored only --test <name>
```

The `privileged` profile (`.config/nextest.toml`) runs one test at a time with longer
timeouts. Nextest has no profile setting that selects ignored tests, so every command
using the profile must pass `--run-ignored only` on the same line; an `xtask` test
checks every workflow for this.

| Test | Covers | Runner |
| --- | --- | --- |
| `etd-host --test install_roundtrip` | Install (including the bundled release kernel staged beside the test image), service start, peer identity and roles, uninstall leaves no service, directory or group; `upgrade` from a changed payload replaces the image, keeps install id, install key and allow list, is idempotent and refuses the installed image; a new host that never serves is rolled back and the previous service runs; an upgrade interrupted at `Replacing` is refused by `resume-service` and restored by the next upgrade and by uninstall | `ci.yml` job `privileged-install`, all three OSes |
| `etd-sysfx-os --test windows_reclaim`, `windows_fence` | Real wintun, firewall and registry objects, same-name conflicts; WFP fence against a second account | `o1-windows.yml` |
| `etd-sysfx-os --test linux_reclaim`, `linux_fence` | netlink adapters, systemd-resolved, nftables fence by uid, distribution parsers | `o2-linux.yml` |
| `etd-sysfx-os --test macos_reclaim`, `macos_fence`, `macos_resolver` | utun ownership, PF anchor fence against a second account, foreign resolver files untouched | `o3-macos.yml` |
| `etd-ipc --test unix_service`, `stale_endpoint` | Root-owned service sockets, second-account rejection, stale endpoint recovery | `ci.yml` job `privileged-install` as root: both on Linux, `stale_endpoint` on macOS (the macOS case of `unix_service` binds below the group-writable `/private/var/run`, which the listener refuses) |
| `etd-ipc --test pipe_acl` | Windows pipe ACL with a temporary second account. Not `#[ignore]`: the account case runs only with `ETD_IPC_CI_ACCOUNTS=1` and an elevated token. Never set that variable on a desktop | `ci.yml` `check` job on Windows |
| `etd-ipc --test session_pipe_acl`, `session_clients`, `session_server_verify` | Elevated session pipe: DACL and Medium no-write-up/no-read-up label, client admission (restricted Medium, Low, AppContainer and second-account tokens), server elevation check against a non-elevated squatter | `ci.yml` `privileged-install` on Windows |
| `etd-testkit --test tier2` (ignored case) | UI crash against a service-form test host | `ci.yml` job `privileged-install` on Linux and macOS, as root with `ETD_G1_SERVICE_RUNTIME`. Not on Windows: it needs LocalSystem, which the runner's administrator is not |
| `etd-core-easytier --test session_real` | Identify, start, readiness and queries against the bundled v2.7.1 release kernel | Unprivileged; `ci.yml` `check` job on all three OSes (`--profile ci --run-ignored only`, kernel from `cargo xtask fetch-cores`) |
| `etd-testkit --test tier3` | Installed service with the release kernel: crash recovery, native inventory, Magic DNS refusal (macOS), shared drivers, program rule conflict, bounded stop and clean uninstall (Windows), `etd-host upgrade` with a running network, management port and utun takeover by a test-owned impostor, the Windows MSI (refused first install, install, major upgrade, failed upgrade rolled back, uninstall) | `privileged.yml`, one job per suite on fresh hosted runners |

`o1-windows.yml`, `o2-linux.yml` and `o3-macos.yml` run on pushes to their adapter
branches and on manual dispatch (`workflow_dispatch`); run them by hand after changing
`crates/etd-sysfx-os`. They upload their logs as evidence artifacts.

`crates/etd-testkit/tests/tier3` holds the end-to-end privileged tests: the installed
service with the pinned release kernel, checked against an independent native inventory
(`etd-testkit::sysdiff`) for every running generation and from before install to after
uninstall. They refuse to run outside a GitHub-hosted runner. See the
[etd-testkit README](../../crates/etd-testkit/README.md#testing) for the cases.

## CI workflows

| Workflow | Trigger | Jobs |
| --- | --- | --- |
| `ci.yml` | Every push and pull request | `boundaries` (rustfmt, `check-boundaries`); `contract` (`buf lint`, `buf breaking` against `freeze-v1` and against the start of the change); `check` on Windows, macOS and Linux (Clippy `-D warnings`, `nextest --profile ci`, `session_real` against the release kernel, doc tests); `privileged-install` on all three (on Linux and macOS also the root-only `etd-ipc` socket tests and tier 2's service-form case); `dependencies` (`cargo deny`) |
| `o1-windows.yml` | Windows adapter branch, manual | Windows privileged adapters with the bundled release kernel and its Wintun |
| `o2-linux.yml` | Linux adapter branch, manual | Linux privileged adapters, distribution parser matrix (Debian 12, Fedora), kernel capability check |
| `o3-macos.yml` | macOS adapter branch, manual | macOS PF, utun, resolver and service reinstall |
| `privileged.yml` | `main` pushes and pull requests touching the code, nightly, manual | Tier 3 product suites (`etd-testkit --test tier3`) on Windows, macOS and Linux |

Notes:

- Only `main` writes the Rust cache; branches restore it.
- The `ci` nextest profile reports every failure and terminates hung tests after five
  minutes.
- CI installs `protoc` 36.2 and `cargo-nextest` 0.9.152.

## Writing tests

- Use the fakes in `etd-testkit` for every port; a new trait method needs a fake
  update in the same change. `etd-testkit` is only ever a dev-dependency.
- Use the fake clock instead of sleeping.
- Property tests keep their regression seeds; snapshot changes are reviewed like code.
- Tests use temporary directories and never touch real user configuration or an
  installed service.
- On Windows, every child process a test spawns uses
  `etd_testkit::no_window::NoWindow::no_window()`.
- Assert on typed errors and states, not just `is_err()`.
- A privileged test says in its `#[ignore = "..."]` reason what runner it needs, and is
  wired into a workflow with `--profile privileged --run-ignored only`.

## Planned tiers

Before a release, two more gates are planned:

- **Compatibility matrix:** the core tier-3 cases against every kernel version with an
  adapter profile and the latest upstream release, nightly.
- **Release gate:** a fault matrix (interrupt at intent committed, kernel wrote the
  system, request durable but reply lost, reclaim half done; by killing the kernel, the
  UI, the host, or cutting power), upgrade replay with an old ledger, and hard power
  cuts driven from outside disposable VMs. Every cell lists the expected objects per
  instance and generation and checks them against an independent enumeration; running
  the same recovery twice must make no second system write.

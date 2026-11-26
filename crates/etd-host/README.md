# etd-host

The host binary and composition root. It picks the host form, takes the singleton
lock, builds the real implementations (ProcessKit engine from
[`etd-proc`](../etd-proc/README.md), SQLite ledger and reclaim engine from
[`etd-sysfx`](../etd-sysfx/README.md), OS adapters and service installation from
[`etd-sysfx-os`](../etd-sysfx-os/README.md), the EasyTier driver from
[`etd-core-easytier`](../etd-core-easytier/README.md)), hands them to
[`etd-host-core`](../etd-host-core/README.md) and serves the `etd.v1` contract on a
named pipe or Unix socket. It never calls OS APIs itself. It is also the only crate
that embeds the trusted kernel table. Binary only.

## Command line

| Command | Purpose |
| --- | --- |
| `run [--mode user\|service]` | Run a host (default `user`). `service` is what the service manager starts. |
| `install [--allow-user <SID\|UID>]...` | Install the system service (administrator). |
| `uninstall` / `uninstall --status` | Stop, reclaim everything, remove the service; or report an unfinished uninstall. |
| `resume-service` | Re-enable a service disabled by an uninstall that stopped before reclaim finished. |
| `reclaim [--mode ...] [--all [--purge]]` | Reclaim ownership records while the host is stopped. |
| `remove-core <version> [--mode ...]` | Reclaim a kernel's binary-scoped records, then delete it from the store. |
| `doctor` | Print version, directories and adapter availability; no privileges needed. |
| `--console-ctrl <pid>` (hidden) | Windows graceful-stop helper; see `etd_proc::console_ctrl`. |

Flows, locks, paths and the per-OS install steps are described in
[docs/cli-and-install.md](docs/cli-and-install.md).

## Host forms

- **Service** (`run --mode service`): started by SCM, systemd or launchd from the
  protected installed image, as LocalSystem or root, only when the install journal
  says `Installed`. Uses the allow list for authorisation, the port fence for kernel
  management ports, and advertises the `TUN` and `ADMIN_ALLOW_LIST` capabilities.
- **User** (`run --mode user`): spawned by the UI as the current user; refuses an
  elevated token. Only its owner may connect (as admin). No TUN, no fence. Every open
  connection counts as a lease; 30 s after the last one closes the host stops its
  instances, reclaims and exits. On first start it installs the bundled kernels into
  its private store.
- **Elevated session**: rejected by the CLI (`run --mode elevated-session` fails);
  planned.

## Trusted kernels

`build.rs` parses `cores.lock` with `core_lock.rs` and embeds only the rows for the
current Rust target (`TRUSTED_CORES`). `storage::trusted_cores()` hands that table to
`ManifestCoreStore`. A kernel can be installed or launched only if its version and
SHA-256 (and every companion file's hash) appear in this table; the on-disk manifest
is an inventory, never a source of trust. **The checked-in `cores.lock` currently has
no rows, so a build from this repository trusts no kernel and cannot start one.**
Release packaging fills the table. Row format, accepted targets and validation rules
are in the header of `cores.lock` and in `core_lock.rs`.

## Dependencies and boundaries

- **Used by:** nothing (binary). `etd-testkit` re-executes its own test binary under
  the `etd-host` image name rather than linking this crate.
- **Depends on:** `etd-contract`, `etd-core-api`, `etd-core-easytier`,
  `etd-host-core`, `etd-ipc`, `etd-proc`, `etd-sysfx`, `etd-sysfx-os`; dev:
  `etd-client`, `etd-testkit`, `etd-sysfx-os` with `ci-test-fixtures`.
- **Must not:** depend on system binding crates directly (OS work goes through
  `etd-sysfx-os`, `etd-ipc`, `etd-proc`), or be a dependency of any UI-side crate.

## Key modules

| Module | Responsibility |
| --- | --- |
| `src/main.rs` | clap CLI; dispatches subcommands; Windows service dispatcher for `run --mode service`. |
| `src/host.rs` | Layout per form, dependency wiring, `run`, install / uninstall / resume, reclaim, remove-core, doctor. |
| `src/serving.rs` | Listener with allow-list ACL, capabilities, connection/lease presence, shutdown on signal or service stop. |
| `src/storage.rs` | Repair index file, kernel manifest, verified install of bundled kernels, native-adapter history. |
| `src/unavailable.rs` | Fail-closed adapters for a platform without native adapters: no new effects, no kernel launch. |
| `build.rs`, `core_lock.rs`, `cores.lock` | Build-time trusted kernel table. |

## Platform notes

- Windows: the service runs under the SCM dispatcher; the user host's pipe is
  `\\.\pipe\easytier-desk-user-<SID>`, the service's `\\.\pipe\easytier-desk-host`.
- Unix: the endpoint is `host.sock` in the socket directory (per-user runtime
  directory for a user host; `/run/easytier-desk` on Linux, inside the install
  directory on macOS for the service). `SIGTERM` and Ctrl-C shut the host down.
- Logs go to a daily-rolling `host.log` in the state directory.

## Testing

```sh
cargo nextest run -p etd-host
```

- `cli.rs`: `--help` and `doctor` work unprivileged; unknown commands, `--purge`
  without `--all` and `--mode elevated-session` are rejected.
- `core_lock.rs`: `cores.lock` parser (row forms, invalid names, duplicates, targets).
- `singleton.rs`: a second process cannot take the host lock until it is released.
- `user_mode_e2e.rs`: native IPC, the production composition and lease loop, real
  child containment, scripted kernel and OS observations; unprivileged.
- `install_roundtrip.rs`: real install, connect, uninstall. `#[ignore]`, and it also
  requires `CI=true` and `ETD_HOST_CI_INSTALL=1`. It runs only in the dedicated
  elevated CI jobs on disposable runners
  (`--profile privileged --run-ignored only --test install_roundtrip`). Never run it
  on a developer machine: it installs a machine-wide service.

See [docs/testing/README.md](../../docs/testing/README.md).

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
| `upgrade` | Replace the installed service with this build and merge its kernels, keeping all state (administrator; run from the new payload). |
| `uninstall` / `uninstall --status` | Stop, reclaim everything, remove the service; or report an unfinished uninstall. |
| `resume-service` | Re-enable a service disabled by an uninstall that stopped before reclaim finished. |
| `reclaim [--mode ...] [--all --purge]` | Reclaim ownership records while the host is stopped. `--purge` also removes product records and every configuration and requires `--all`, its explicit switch; `--all` alone changes nothing. |
| `remove-core <version> [--mode ...]` | Reclaim a kernel's binary-scoped records, then delete it from the store. |
| `doctor` | Print version, directories, adapter availability and, on Windows, whether firewall cleanup supports this build (listed, self-checked, or not supported with the reason); no privileges needed. |
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
- **Elevated session** (`run --mode elevated-session`, Windows only): run by the
  current user's elevated administrator token (TokenElevation, integrity High, not
  SYSTEM), never while the service is registered or its state directory remains. It
  shares the service's maintenance and host locks, keeps its state in the protected
  tree `%ProgramData%\EasyTierDesk.session\<SID>`, uses the fence, advertises `TUN`
  and `LEASE` (no allow list) and serves `\\.\pipe\easytier-desk-session-<SID>`. The
  owner in the host's Windows session controls it; an elevated owner administers it.
  Only connections from the `etd-ui.exe` beside the host image hold its lease (an
  image check, not an authentication). Refusals have their own exit codes; see
  [docs/cli-and-install.md](docs/cli-and-install.md#run---mode-elevated-session).
  The UI integration (launcher, messages) is planned (ES4).

## Trusted kernels

`build.rs` parses `cores.lock` with `core_lock.rs` and embeds only the rows for the
current Rust target (`TRUSTED_CORES`). `storage::trusted_cores()` hands that table to
`ManifestCoreStore`. A kernel can be installed or launched only if its version and
SHA-256 (and every companion file's hash) appear in this table; the on-disk manifest
is an inventory, never a source of trust. The checked-in `cores.lock` lists the
official EasyTier v2.7.1 release kernels for x86_64/aarch64 Windows, Linux and macOS
(Windows rows include `Packet.dll`, `wintun.dll` and, on x86_64, `WinDivert64.sys`).
It is generated from `packaging/cores.toml` by `cargo xtask fetch-cores --update-lock`;
never edit it by hand. Because the table is not empty, `install` (and a user host's
first start) needs `cores/2.7.1/` beside the image: stage it with
`cargo xtask fetch-cores --target host --bundle <image dir>/cores`. Row format,
accepted targets and validation rules are in the header of `cores.lock` and in
`core_lock.rs`.

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
| `src/upgrade.rs` | `upgrade`: durable stages, image swap with `.prev` backup, kernel merge, registration backup, commit by the new host, rollback and crash recovery. |
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

- `cli.rs`: `--help` and `doctor` work unprivileged; unknown commands and `--purge`
  without `--all` are rejected; the elevated session mode parses without any path
  option, `--all-users` only with it, and on Unix it is refused as Windows-only.
- `session_e2e.rs` (Windows, privileged, `ETD_HOST_CI_INSTALL=1`): refusals for a
  non-conforming session root, a leftover service state directory, a registered
  service and a junction in the tree; a real run with handshake, `install` and
  `reclaim` failing on the shared lock, exit after the lease grace with a non-UI
  client, a real kernel (the bundled release) applied, ready and stopped, then
  `ReleaseLease`; a file in place of `profile`; another user's leftover blocking until
  `reclaim --all-users`; the uninstaller purge run as LocalSystem; `install` draining
  a session root.
- `core_lock.rs`: `cores.lock` parser (row forms, invalid names, duplicates, targets).
- `singleton.rs`: a second process cannot take the host lock until it is released.
- `user_mode_e2e.rs`: native IPC, the production composition and lease loop, real
  child containment, scripted kernel and OS observations; unprivileged.
- `install_roundtrip.rs`: real install, connect, uninstall; upgrade from a changed
  payload (twice), state kept; rollback when the new host never serves; an upgrade
  interrupted at `Replacing`, refused by `resume-service`, restored by the next
  upgrade and by uninstall. The faults come from a CI-only fixture compiled only with
  `etd-sysfx-os/ci-test-fixtures`. `#[ignore]`, and it also
  requires `CI=true` and `ETD_HOST_CI_INSTALL=1`. It runs only in the dedicated
  elevated CI jobs on disposable runners
  (`--profile privileged --run-ignored only --test install_roundtrip`). Never run it
  on a developer machine: it installs a machine-wide service.

See [docs/testing/README.md](../../docs/testing/README.md).

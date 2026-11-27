# etd-sysfx-os

The OS side-effect adapters: the only crate that observes or changes system
networking, firewall, registry or DNS on the host's behalf. It implements the
[`etd-sysfx`](../etd-sysfx/README.md) interfaces (`Reclaimer`, `Sweeper`,
`BootIdSource`, `SystemObserver`, `PortFence`) for Windows, Linux and macOS, and also
holds the system-service installer and the desktop appearance queries used by the UI.
Library only. Most of it runs inside `etd-host`; the UI and CLI use only `service` and
`appearance` helpers.

Per-platform details (kinds, ownership proofs, fences, boot ids, Magic DNS, what is not
reclaimed, privileged tests) are in [docs/platforms.md](docs/platforms.md).

## Public surface

`lib.rs` is frozen at `freeze-v1`.

| Item | Purpose |
| --- | --- |
| `adapters(&OsConfig) -> Result<OsAdapters, OsError>` | Build the running platform's adapters; `Unsupported` on other systems |
| `OsConfig` | `state_dir` (ledger, repair index), `run_dir` (root of `run/<instance>/<epoch>/`), `core_store_dir` (protected kernel store) |
| `OsAdapters` | `reclaimers` (one per OS kind), `sweeper`, `boot_id`, `observer`, `fence: Option<_>` |
| `OsError` | `Unsupported`, `PermissionDenied`, `Os { code, message }` |
| `driver_bundle_referenced`, `driver_bundle_reference` | Windows: does any registered or loaded driver point into a kernel bundle (checked before a kernel is removed); always `false` / `None` elsewhere |
| `service::{HostLayout, HostFilesystem, NativeHostFilesystem, ServiceManager, NativeServiceManager, HostLock, MaintenanceLock, LifecycleJournal, SERVICE_NAME, installed_host_dir, ...}` | Host directories, singleton locks, service install / uninstall (SCM, systemd, launchd) |
| `appearance::{AppearanceSnapshot, AccentRamp, AppearanceWatch, mica_backdrop_accepted, set_window_dark_mode}` | Desktop appearance for the UI; inert stubs outside Windows |
| `windows`, `linux`, `macos` | Platform modules (compiled only on their OS); internals are private |

Feature `ci-test-fixtures` compiles the Windows identity fixture `service::ci_fixture`
and `windows::worker_diagnostics`. Only `etd-host`'s dev-dependency and the privileged
`windows_session_inputs` run enable it, on disposable CI runners.

## What each platform provides

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Reclaimers | `win.*` kinds, `route`, `driver` | `linux.tun`, `linux.resolved_link`, `route`, `linux.fence_rule` | `macos.utun`, `route`, `macos.fence_rule` |
| Fence | WFP (service: permit SYSTEM; elevated session: SYSTEM and elevated administrators) | nftables (uid 0 only) | PF anchor (user 0 only), root hosts only |
| Boot id | volatile registry marker | kernel `boot_id` | `kern.bootsessionuuid` |
| Service | SCM, LocalSystem | systemd unit | launchd |

`Process` and `RuntimeDir` reclaimers are in `etd-host-core`; the UPnP mapping is
record-only and needs no reclaimer.

Default host directories (`service`):

| | Service state | Kernel store | User-host state |
| --- | --- | --- | --- |
| Windows | `%ProgramData%\EasyTierDesk` | `%ProgramFiles%\EasyTierDesk\cores` | `%LocalAppData%\EasyTierDesk` |
| Linux | `/var/lib/easytier-desk` | `/usr/local/lib/easytier-desk/cores` | `$XDG_STATE_HOME/easytier-desk` or `~/.local/state/easytier-desk` |
| macOS | `/Library/Application Support/easytier-desk/state` | `/Library/Application Support/easytier-desk/cores` | `~/Library/Application Support/easytier-desk` |

## Dependencies and boundaries

- **Used by:** `etd-host` (normal; dev with `ci-test-fixtures`), `etd-ui` and `etd-ctl`
  (`service` and `appearance` helpers only), `etd-testkit`.
- **Depends on:** `etd-contract`, `etd-sysfx`; `etd-testkit` as a dev-dependency.
  System crates per target: `windows`, `windows-service` (Windows); `libc`, `nix`
  (Unix); `nftables`, `rtnetlink`, `zbus` (Linux); `system-configuration` (macOS).
- **Boundaries:** one of only three crates allowed to depend directly on system binding
  crates (with `etd-ipc` and `etd-proc`). It must not depend on `processkit` (only
  `etd-proc` may) or on `easytier*`, because `etd-ui` depends on it and the UI closure
  must stay kernel-free.

## Key modules

| Module | Responsibility |
| --- | --- |
| `lib.rs` | `OsConfig`, `OsAdapters`, dispatch to the platform module |
| `windows/mod.rs` | Reclaimers, observer, sweeper, fence wiring |
| `windows/wfp.rs`, `probe.rs`, `token.rs` | WFP fence of the host's form (persistent for the service, non-persistent for the elevated session); LocalService or restricted-token connection probe; host form from the process token |
| `windows/interfaces.rs`, `registry.rs`, `magic.rs` | wintun identity, registry and boot marker, Magic DNS recovery replay |
| `windows/execution.rs`, `system.ps1` | Constant PowerShell script for firewall, NRPT, profiles, registry and listener queries; no module autoloading, absolute imports, explicit environment (profile variables in the session tree under an elevated host that is not SYSTEM) |
| `windows/driver_refs.rs`, `appearance.rs` | Driver references into the kernel store; DWM / appearance |
| `linux/mod.rs`, `network.rs`, `observe.rs` | Reclaimers, sweeper, links / routes / listeners, runtime directories |
| `linux/fence.rs`, `resolved.rs` | nftables fence; resolve1 per-link DNS |
| `macos/mod.rs`, `observe.rs`, `reclaim.rs`, `holders.rs` | utun and route observation, verify-only reclaim, listener and utun holder identity |
| `macos/pf.rs`, `fence.rs` | PF anchor and fence |
| `service/` | Layout, locks, lifecycle journal, SCM / systemd / launchd adapters |
| `appearance.rs` | Plain-data appearance types and non-Windows stubs |

## Platform notes

- Nothing is deleted by name alone. Objects outside an exclusive container are deleted
  only when the probe reads back the recorded credential; interfaces and routes are
  never deleted on Windows and macOS (verify only), and routes never on Linux.
- Each fence is verified on the live listener: the host must connect, a probe without
  privileges must be refused, and the refusal must come from this fence.
- Windows Magic DNS is replayed only while no other EasyTier process runs; Linux Magic
  DNS state is reverted on the credential-checked link; macOS Magic DNS is refused by
  the planner.
- Every child process on Windows is started with `CREATE_NO_WINDOW`.

## Testing

```sh
cargo nextest run -p etd-sysfx-os
cargo test --doc -p etd-sysfx-os
```

The unprivileged run covers the unit tests inside the platform modules (key and name
grammar, listener parsing, credential matching, PowerShell encoding, ACL checks,
sweep error handling) for the system it runs on. Everything that touches real system
objects is `#[ignore]`, guarded by CI-only environment variables, and runs only with
`--profile privileged --run-ignored only` in the platform workflows
`.github/workflows/o1-windows.yml`, `o2-linux.yml`, `o3-macos.yml`, and in the
`privileged-install` job of `ci.yml`. Never run them on a developer machine. The test
files and what each covers are listed in [docs/platforms.md](docs/platforms.md).

See also [docs/architecture/side-effects.md](../../docs/architecture/side-effects.md)
and [docs/testing/README.md](../../docs/testing/README.md).

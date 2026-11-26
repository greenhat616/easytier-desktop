# etd-app

UI-independent application logic for the desktop client (UI side, library). It holds the
state store the views bind to, reduces host snapshots and events into it, runs the
background tokio runtime that talks to the host, finds or starts a host, keeps the
user's profile library, and drives the window/tray state table and the exit sequence.
It has no `gpui` and no OS binding crates; `etd-ui` supplies those.

## Public surface

| Item | Purpose |
| --- | --- |
| `HostLauncher`, `HostTarget`, `LaunchError` (`launcher.rs`, frozen) | Find (`probe`) or start (`ensure`) a host of one form. |
| `Profile`, `ProfileStore`, `ProfileError` (`profiles.rs`, frozen) | The user's saved network configurations. |
| `TrayBackend`, `TrayMenu`, `TrayEvent`, `TrayIndicator`, `TrayError` (`tray.rs`, frozen) | Minimal tray surface; implemented in `etd-ui`. Not `Send`. |
| `StateStore`, `HostLink`, `InstanceCondition`, `Operation`, `AppServices` (`state.rs`) | The whole read model of the UI and its injected services. |
| `AppRuntime`, `AppBridge`, `UserCommand`, `BridgeConfig` (`bridge.rs`) | Background runtime and the UI's two channel ends. |
| `ExitGate`, `ExitSteps`, `ExitDeadlines`, `ExitReport` (`exit_gate.rs`) | The single exit path. |
| `window_tray::{WindowTray, TrayDriver}` | Window/tray state machine and tray driver. |
| `launcher_user::LocalHostLauncher` | Real launcher: installed service or spawned user host. |
| `profiles_toml::TomlProfileStore` | Real profile store (TOML file). |

`lib.rs`, `Cargo.toml` and the three frozen modules belong to the `freeze-v1` interface
set: change them only through an approved change request (see
[Frozen interfaces](../../docs/development/workflow.md#frozen-interfaces)).

## Dependencies and boundaries

- **Used by:** `etd-ui` (normal), `etd-testkit` (normal; fakes of the frozen traits).
- **Depends on:** `etd-client`, `etd-contract`, `etd-ipc`; `etd-testkit` as a
  dev-dependency only.
- **Must not depend on:** `etd-core-easytier` or any `easytier*` crate, anywhere in its
  closure (rule 1); system binding crates such as `windows*`, `nix`, `libc` (rule 2).
  Checked by `cargo xtask check-boundaries`, see
  [`../../xtask/README.md`](../../xtask/README.md).

## Key modules

| Module | Responsibility |
| --- | --- |
| `state` | `StateStore`, instance conditions ("cut, unconfirmed" is never folded into "stopped"), `Secret` / `SecretInput`, `SUGGESTED_LISTENERS`. |
| `reducer` | Pure functions: snapshot, event and connection changes into the store. Events apply strictly in cursor order; duplicates are dropped; a gap, a different host run or a host resync request marks the store stale and asks for a new snapshot. |
| `bridge` (+ `request`, `tasks`) | Background actor, one host session at a time, mutation queue, lost-reply recovery, query polling, profile writer. |
| `exit_gate` | Ordered exit with per-step deadlines. |
| `window_tray` | Window/tray state table, tray summary and menu, `TrayDriver`. |
| `launcher_user` | `LocalHostLauncher`, service and user-host configuration, spawner. |
| `profiles_toml` | Versioned TOML profile library with atomic replace and migration. |

### gpui <-> tokio bridge

`AppRuntime::start` builds a multi-thread tokio runtime (2 workers) and drives it from
its own thread (`etd-tokio`). The UI never enters a tokio context and no task is shared
between executors. The UI holds an `AppBridge`: `commands` (unbounded `async-channel`
of `UserCommand`) and `states` (bounded to one value, the latest `StateStore`; a slow
reader skips intermediate states). All state lives in one actor that never waits on the
host: each host call runs in its own task and reports back as a message.

Mutations are sent one at a time, each with the revision the store showed when it was
sent. A revision conflict is reported, never retried with a newer revision. A request
whose reply was lost is looked up by request id (up to `recovery_attempts`) and is only
ever resent unchanged, so it takes effect at most once. When a user host vanishes, the
actor starts it again from reconnect attempt `relaunch_after` (default 2).

### Exit gate

Every exit path goes through `ExitGate::run`, on the UI executor, before the toolkit is
told to quit. The order is fixed and runs once:

1. **Settle instances**: apply commands already queued, wait for pending requests and
   profile writes, then give the lease back to a session-form host (user or elevated
   session) with the requested `LeaseRelease`. A service host needs nothing.
2. **Stop subscriptions**: cancel the event stream and query polling tasks.
3. **Stop the tokio runtime** and join its thread without blocking the caller.
4. **Quit the UI** (the caller's closure removes the tray icon and quits).

Default deadlines are 2.5 s, 0.5 s and 1.5 s, so an exit stays under five seconds. A
failed or late step is recorded in the `ExitReport` and never stops the following steps.

### Window and tray state table

| Input | Shown, tray | Shown, no tray | Hidden |
| --- | --- | --- | --- |
| Close requested | close, hidden | keep window | nothing |
| Window gone (current generation) | hidden | reopen | nothing |
| Window gone (old generation) | nothing | nothing | nothing |
| Show / icon / "open" | focus | focus | open (new generation) |
| Tray lost | no tray | nothing | open (new generation) |
| Exit | begin exit | begin exit | begin exit |

Closing the window is not exiting. Every window has a generation, so a late "gone"
report for an older window changes nothing. The tray counts as unavailable until an
icon is installed, so the first window always opens. Once exit began every input is
ignored. The host link is not an input: losing the host leaves window and tray alone.

### User-host launcher

`LocalHostLauncher::probe` returns the service when it answers or its binary is
installed, else a user host that already answers; it starts nothing. `ensure(User)`
spawns `etd-host run --mode user` as the current user (null stdio, `CREATE_NO_WINDOW`
on Windows, not killed when the UI drops it; it ends through its lease) and waits up to
20 s for it to answer. Its endpoint is `\\.\pipe\easytier-desk-user-<SID>` on Windows
and `host.sock` in the user's runtime directory on Linux and macOS. A host counts as
reachable only after the connector verified the server process; if something else
answers, nothing is started and nothing is sent. `ensure(Service)` never installs:
`LaunchError::NotInstalled` lets the UI offer installation. The elevated-session form
returns `LaunchError::Unsupported` (planned).

### Profiles and secrets

`TomlProfileStore` keeps `profiles.toml` in the user's configuration directory
(`TomlProfileStore::default_path`). Schema version 1 is current; an unversioned file is
migrated on load and rewritten on the next save; a newer or unparsable file is never
overwritten. Saves write a temporary file in the same directory and rename it into
place. Network secrets are not persisted by the UI: the stored layout has no secret
field, `SecretFreeSpec` and `scrub_secret` remove it before anything is kept, the
reducer drops any secret a snapshot carries, and `Secret`'s `Debug` output is masked.
A secret only travels to the host inside an Apply, as `SecretInput::Set`.

## Testing

```sh
cargo nextest run -p etd-app
```

All tests are unprivileged and use fakes from `etd-testkit`; none touch the real host.

- `tests/bridge.rs`: the runtime driven only through the two channels and the exit gate.
- `tests/real_client.rs`: the runtime with the real gRPC client against the scripted
  in-memory contract server.
- `tests/reducer.rs`: snapshot and event reduction, ordering and resync.
- `tests/exit_gate.rs`: exit order, deadlines, run-once.
- `tests/window_tray.rs`: the state table, plus proptest convergence under reordered
  events.
- `tests/launcher.rs`: probe and ensure with scripted connectors and processes.
- `tests/profiles.rs`: atomic replace, migration, never losing the original (proptest).

See also [`../etd-ui/README.md`](../etd-ui/README.md) and
[`../../docs/testing/README.md`](../../docs/testing/README.md).

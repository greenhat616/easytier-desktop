# etd-core-api

The kernel-independent adapter interface between the host and a VPN kernel. It defines
how the host identifies a kernel binary, asks for a launch plan, and opens a management
session, without naming a single EasyTier type. Host side, library only. The only real
implementation is [`etd-core-easytier`](../etd-core-easytier/README.md); `etd-testkit`
provides fakes so that `etd-host-core` and its tests never compile EasyTier.

## Public surface

The whole crate is frozen at tag `freeze-v1` (`lib.rs`, `driver.rs`, `model.rs`).
Enums are `#[non_exhaustive]`; compatible changes are new fields, variants and methods
with default bodies.

| Item | Purpose |
| --- | --- |
| `CoreDriver` | `identify(binary)`, `profile(core)`, `plan_launch(ctx)`, `attach(endpoint, core)` |
| `CoreSession` | `wait_ready(deadline)` (full readiness), `query(QueryKind)`, `poll_events(since)` |
| `CoreDescriptor` | What a binary reports: kernel `version` and upstream `proto_revision` |
| `AdapterProfile` | One kernel build paired with the adapter's knowledge of it (`id`, `deny_all_verified`) |
| `LaunchContext` | Instance, reserved epoch and the persisted `LaunchInputs` (re-exported from `etd-sysfx`) |
| `LaunchPlan` | `Command`, files to write, `Readiness`, predicted `EffectIntent`s, guard, endpoint, single-writer claims, feature verdicts |
| `PlannedFile` | A file for the epoch directory; `Debug` prints only its size (it may hold the network secret) |
| `Readiness`, `ReadinessCondition` | Basic readiness judged by the host from system observation: interface with address, owned interface (macOS utun), or a listener |
| `FeatureVerdict`, `FeatureClass` | `Supported`, `SingleWriter { resource }`, `Disabled { reason }`, `Rejected { reason }` |
| `CoreRuntimeInfo` | Read back once fully ready (interface name, IPv4, peer id, hostname, version) |
| `CoreEvent`, `CoreEventKind`, `CoreEventCursor` | Kernel-local event history (peers, connections, interface, address, listener failures, `Other`) |
| `CoreEndpoint` | Loopback management address |
| `CoreError` | `UnmodelledEffects`, `GuardUnavailable`, `FeatureRejected`, `NoProfile`, `InvalidSpec`, `Identify`, `Connect`, `Rpc`, `Timeout`, `SessionClosed`, `Unsupported` |
| re-exports | `CoreRef`, `LaunchInputs`, `ManagementGuard`, `Privilege` from `etd-sysfx` |

Contract points every implementation must keep:

- `plan_launch` is pure and deterministic in its `LaunchContext`: the host replays a
  committed generation by calling it again with the persisted inputs and requires the
  same effects.
- It returns `UnmodelledEffects` for a feature whose write set is unknown or decided at
  run time and `FeatureRejected` for a disabled feature. A privileged host refuses both.
- The plan lists only the kernel's own effects. The host adds the process record, the
  runtime directory and the management-port fence to the same generation.
- Basic readiness never goes through the management RPC; `CoreSession::wait_ready` is
  the stronger "RPC answers and node info read back" check.
- The kernel has no streaming RPC, so the host polls `poll_events`.

## Dependencies and boundaries

- **Used by:** `etd-core-easytier`, `etd-host-core`, `etd-host`, `etd-testkit` (all
  normal dependencies).
- **Depends on:** `etd-contract` (query and instance types), `etd-proc` (`Command`),
  `etd-sysfx` (effect intents, launch inputs).
- **Must not depend on:** `etd-core-easytier` or any `easytier*` crate. It is one of
  the crates `etd-host-core` may depend on, so its closure must stay kernel-free
  (checked by `cargo xtask check-boundaries`).

## Key modules

| Module | Responsibility |
| --- | --- |
| `driver.rs` | `CoreDriver` and `CoreSession` traits |
| `model.rs` | Descriptor, profile, launch context and plan, readiness, feature classes, events, errors |

## Testing

The crate has no tests of its own; it is a set of traits and plain data. Its contract
is exercised through the EasyTier implementation
([`etd-core-easytier`](../etd-core-easytier/README.md) tests) and through the fakes in
`etd-testkit` used by `etd-host-core`. Doc tests, if any are added:
`cargo test --doc -p etd-core-api`.

See also [docs/architecture/README.md](../../docs/architecture/README.md) for where the
adapter sits in the host.

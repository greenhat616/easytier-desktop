# etd-core-easytier

The EasyTier adapter: the one implementation of the
[`etd-core-api`](../etd-core-api/README.md) `CoreDriver`, and the only crate in the
workspace allowed to depend on EasyTier. It identifies `easytier-core` binaries, pairs
them with an adapter profile, turns a `NetworkSpec` into a TOML file and a command line,
predicts the system side effects the kernel will cause, and talks to the kernel's
loopback management RPC. Host side, library only; linked into `etd-host`.

## Pinned upstream

`easytier-proto` (feature `api`) and `easytier-core` (feature `management-rpc`) come
from the EasyTier git repository at revision
`c97f36b8d40f3bde7a95cc9ec99fe95fe35a6ff0` (workspace version 2.7.1), pinned in the
root `Cargo.toml` with default features off. `PROTOTYPE_REVISION` holds the same hash.
Upstream types never leave this crate.

The kernel shipped beside the host is the official upstream release v2.7.1 (commit
`0d9c52b169dc2112687ddefcf571cd01d383193c`, pinned in `packaging/cores.toml`). Its
management proto, CLI and TOML schema are byte-identical to `c97f36b`, so the linked
crates and this adapter serve both.

## Public surface

`lib.rs` (frozen at `freeze-v1`) only wires `EasyTierDriver` to the modules below.

| Item | Purpose |
| --- | --- |
| `EasyTierDriver` | `CoreDriver` implementation used by the host |
| `identify::identify`, `parse_version_output` | Run `<binary> --version` and parse the version and commit |
| `profiles::{Profile, ALL, profile_for, find, by_id}` | Adapter profiles: `2.7.1-c97f36b` (source-built development kernels, fixtures) and `2.7.1-0d9c52b` (the bundled release) |
| `plan::{plan_launch, plan_for, Platform}` | Pure launch planning; `plan_for` plans for any platform (used by tests) |
| `plan::spec::{Settings, redact_uri, kernel_instance_id, render_toml}` | Spec validation and TOML |
| `plan::effects::{adapter_guid, interface_rule_names, program_rule_names, ...}` | Side-effect prediction helpers |
| `plan::classify::{classify, enforce, exclusive, WINDOWS_MAGIC_DNS}` | Feature classification |
| `session::attach` | Management session (`CoreSession`) |

### Identify and profiles

`identify` runs the binary with `--version` from its bundle directory, with an empty
environment and a fixed system `PATH`, a 10 s timeout and a 4 KiB output limit, and
parses forms such as `easytier-core 2.7.1-c97f36b8-20261124`,
`2.7.1-v2.7.0-12-gc97f36b8-20261124` or the release's `2.7.1-0d9c52b1-20261115`. A profile matches only the exact version and a
revision of at least seven hex digits that prefixes the profile's full hash; a dirty
(`~`) or git-less build matches nothing. A privileged host refuses a kernel without a
profile (`NoProfile`); a user host may run it lifecycle-only. A profile grants no
trust: only binaries whose SHA-256 is in `etd-host`'s `cores.lock` can be installed or
launched. Both profiles have `deny_all_verified = false`, so a `DenyAll` guard cannot be
planned yet.

### `plan_launch`

Pure: depends only on the `LaunchContext` and the target platform (no clock, file
system or environment), so a committed generation replays to the same plan.

- Checks: the guard is allowed for the privilege and profile (System: `Fence`, or
  `DenyAll` only when verified; User: `Unguarded`, or `LifecycleOnly` without profile);
  the management address is loopback with a fixed port; the interface name is a
  derived `etd-<8 lower-case hex>` name (`etd_sysfx::naming::interface_name`); the
  runtime directory is absolute; a TUN instance has `ipv4_cidr` or DHCP.
- Command line: `-c <run>/config.toml --rpc-portal <addr> --rpc-portal-whitelist
  <addr>/32 --disable-env-parsing --console-log-level info --file-log-dir <run>`, empty
  environment, working directory = the epoch directory. The whitelist is the exact
  portal address, or `255.255.255.255/32` for `DenyAll`. No `NetworkOptions` flag is
  passed, so upstream never merges CLI values into the file.
- TOML: upstream's `Config` schema, with `rpc_portal` never written. Every flag the
  spec controls is explicit. `dev_name` is the derived name on Windows and Linux and is
  omitted on macOS (the system assigns `utunN`). `instance_id` is the contract id when
  it is a UUID, otherwise a UUIDv5 of it. An empty listener list means no listeners.
- Windows adapter GUID: UUIDv5(NAMESPACE_URL, `https://easytier.rs/wintun/` +
  lower-case name), written braced and upper case (`effects::adapter_guid`).
- Readiness: 2 s minimum uptime, then an address on the named interface (Windows,
  Linux), on an interface the kernel holds (macOS), or a listener for `no_tun`.

### Feature classification

| Feature | Verdict |
| --- | --- |
| TUN (`no_tun = false`) | Supported on a privileged host; `Disabled` on a user host |
| `magic_dns` | Windows: `SingleWriter { "windows.magic_dns" }`; macOS: `Disabled` (upstream deletes or takes over `/etc/resolver` files); Linux: Supported; without TUN or privilege nothing is written |
| `public_ipv6_provider` | `Rejected` (unmodelled) on privileged Linux; otherwise Supported |
| peers, listeners, proxy CIDRs, exit nodes, exit node, SOCKS5, port forwards | Supported |

`enforce` turns the first `Disabled` into `FeatureRejected` and all `Rejected` into
`UnmodelledEffects`; `exclusive` lists the single-writer claims.

### Predicted effects (privileged host)

| Platform | Records |
| --- | --- |
| Windows | WinDivert driver (product scope); with TUN: wintun driver (product), wintun adapter, routes via the adapter, 2 program firewall rules (core-binary scope), 8 per-interface firewall rules, 7 Tcpip/Tcpip6/NetBT registry values (restore-if-ours), network-list profile, and with Magic DNS one upstream recovery record (`HKLM\SOFTWARE\EasyTier\MagicDNS`) |
| Linux | TUN, routes via it, and with Magic DNS the systemd-resolved link settings |
| macOS | utun with unknown name, routes via it |
| all, also user hosts | UPnP / NAT-PMP mapping, record-only lease of 300 s |

Each entry in `plan/effects.rs` cites the upstream code that creates it. How the host
records and reclaims these is described in
[`etd-sysfx` docs](../etd-sysfx/docs/ledger-and-reclaim.md) and
[`etd-sysfx-os` platforms](../etd-sysfx-os/docs/platforms.md).

### Secrets

The network secret appears only in the generated file: never on the command line, in
the environment, in `Debug` output (`Settings`, `PlannedFile`), errors, logs or
snapshots. URI userinfo is shown as `***@`. Session errors never carry upstream's
instance error text, which can contain configuration.

### Session

`attach` requires a profile match and a concrete loopback endpoint, then opens
upstream's `StandAloneClient` over a TCP tunnel and requires exactly one kernel
instance. RPCs time out after 6 s. `wait_ready` polls `collect_network_info` every
100 ms until the instance runs and reports node info; `query` maps nodes, routes and
traffic to contract types; `poll_events` reconciles upstream's rolling 20-entry event
list into a cursor history (up to 1024 events) and emits `EventHistoryGap` when entries
were lost between polls.

## Dependencies and boundaries

- **Used by:** `etd-host` only.
- **Depends on:** `etd-contract`, `etd-core-api`, `etd-proc`, `etd-sysfx`, and the
  pinned `easytier-proto` / `easytier-core`.
- **Must not be reachable from:** `etd-ui`, `etd-app`, `etd-client`, or
  `etd-host-core` and its tests. No other crate may depend on `easytier*`.

## Testing

```sh
cargo nextest run -p etd-core-easytier
cargo test --doc -p etd-core-easytier
```

| Test file | Covers |
| --- | --- |
| `plan_snapshots.rs` | `insta` snapshots of command line and TOML (`tests/snapshots/`) for basic, DHCP, full, no-TUN user host, Magic DNS, no-secret specs per platform; no `rpc_portal`, `-c` only into the epoch directory, upstream's loader accepts every file, replay determinism |
| `plan_classify.rs` | Verdicts and refusals, guards per host, deny-all whitelist, invalid specs |
| `plan_effects.rs` | Predicted records per platform, verbatim rule names, scopes |
| `plan_identity.rs` | Derived interface name and Windows GUID against upstream vectors |
| `plan_redaction.rs` | Secret only in the file; `Debug`, errors, logs and snapshots redacted |
| `session_inproc.rs` | Session against an in-process RPC stub over loopback TCP |
| `session_real.rs` | `#[ignore]`: identify, launch, ready and query against the bundled release kernel; needs `ETD_EASYTIER_CORE` (`cargo xtask fetch-cores --target host --github-env ETD_EASYTIER_CORE`); `ci.yml` `check` runs it on all three OSes |
| `src/session/tests.rs`, `src/profiles` | Unit tests over upstream's in-process ring tunnel; profile matching |

`plan_fixtures.rs` and `session_support/` are shared helpers. Update snapshots with
`cargo insta review` after an intended change.

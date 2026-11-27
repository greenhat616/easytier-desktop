# Per-OS adapters

What `etd-sysfx-os` does on each platform: which effect kinds it observes and reclaims,
how it proves ownership before deleting anything, how the management-port fence is
installed and verified, where the boot id comes from, and what it deliberately leaves
alone. The engine that drives these adapters, and the general rule "names locate,
credentials or exclusive containers authorise", are described in
[`etd-sysfx` ledger-and-reclaim.md](../../etd-sysfx/docs/ledger-and-reclaim.md). The
effects themselves are predicted by
[`etd-core-easytier`](../../etd-core-easytier/README.md).

`adapters(&OsConfig)` returns one `OsAdapters` per platform: reclaimers (one per kind),
a sweeper, a boot-id source, an observer and an optional fence. `Process` and
`RuntimeDir` are reclaimed by `etd-host-core`, not here. Every system tool is started
from a fixed system path with a cleared environment and a timeout; no request data is
ever executed as code.

## Summary

| | Windows (`src/windows/`) | Linux (`src/linux/`) | macOS (`src/macos/`) |
| --- | --- | --- | --- |
| Reclaimers | WFP fence, wintun adapter, interface and program firewall rules, registry values, NRPT rule, Magic DNS recovery, network profile, routes, drivers | TUN, systemd-resolved link, routes, nftables fence | utun, routes, PF fence |
| Interface credential | adapter LUID + device instance id | interface index + boot id | interface index + boot id |
| Fence container | WFP provider + sublayer `51e7d002-7bc3-43b9-a795-7b80c196382f` | one nftables table `inet etd_f_<id>_<port>` per fence | PF anchor `com.apple/easytier-desk` |
| Fence identity rule | permit SYSTEM, block everyone else | reject unless socket uid is 0 | block unless user is 0 |
| Dropped-privilege probe | process as `NT AUTHORITY\LocalService` | socket created with fsuid 65534 | `sudo -n -u nobody nc -z` |
| Boot id | UUID in a volatile registry key | `/proc/sys/kernel/random/boot_id` | `sysctl kern.bootsessionuuid` |
| Magic DNS | one upstream recovery record, replayed while no other EasyTier runs | per-link resolve1 settings reverted on the verified link | feature disabled by the planner; `/etc/resolver` untouched |
| Fence available | always offered (installation needs SYSTEM) | always offered (installation needs root) | only when the host runs as root |

## Windows

System queries and changes use native APIs (IP Helper, CfgMgr, WFP, registry, SCM) and
one constant PowerShell script (`system.ps1`) run by `execution.rs` from the system
directory with a fixed environment; the request is JSON passed in an environment
variable, never interpolated into script source.

| Kind | Observed as | Reclaim |
| --- | --- | --- |
| `win.tun` | Adapter by name or derived GUID; present only with an IP interface or a live PnP devnode (phantom table rows ignored). Credential `WinAdapter { luid, device_instance_id }` | Never uninstalled: a live adapter with our credential answers `NotDeletable`, so the record is a candidate that closes once the adapter is gone (whether it can outlive its creator is spike S2) |
| `route` | Routes whose interface is the adapter | Verify only: `Busy` while any remain |
| `win.firewall_rule` | Rule by exact display name and group; credential = rule id. A same-name rule in another group is reported as foreign | Delete by rule id, re-checked in the same script step |
| `win.program_firewall_rule` | Credential = rule id, name, program path, direction, group (core-binary scope) | Delete only if program, direction and group still match |
| `win.registry_value` | Current value (no credential) | Restore-if-ours: put `original` back only while the value equals `ours` |
| `win.nrpt_rule` | Rule key under `DnsPolicyConfig` | Delete by GUID if name and group match |
| `win.network_profile` | Profile by `ProfileName`; credential = profile GUID | Delete by GUID, plus the unmanaged signatures that point to that GUID |
| `win.magic_dns_recovery` | Presence of `HKLM\SOFTWARE\EasyTier\MagicDNS` | Replay upstream's record: delete the listed NRPT rules, restore saved `SearchList` values, delete the record |
| `win.fence_filter` | Filters of the fence in the product sublayer (exclusive container) | Delete the four filters; the sublayer and provider go with the last fence |
| `driver` | wintun / WinDivert service by name (no credential) | Not removed by this crate (see below) |

**Magic DNS gate.** The recovery record is machine-wide and shared with any other
EasyTier installation. Before each mutating stage the reclaimer re-reads the record and
checks that no other EasyTier process runs; the kernel processes of this product are
recognised by the identity of their opened image file inside the protected kernel
store, not by a path prefix. If every running candidate was read and placed, and one is
outside the store, the first gate (before any change) answers `HeldBy` with that
process's name and image, but only while the system still holds every entry the record
lists (each NRPT rule present, each saved `SearchList` different from its original): an
earlier replay interrupted part-way leaves the system short of that, so it must finish.
The record then becomes a conflict, left in place, and closes once the key is gone (the
other EasyTier's own clean-up removes it). A candidate that cannot be read or placed, a
failed enumeration, a changed record, a record whose entries are not all in place or
cannot be read, or a holder that appears once this replay has changed something is
`Busy`, and the engine retries towards quarantine. A
conflict is never replayed: if the other EasyTier never used Magic DNS and exits, our
state stays in the key until the next EasyTier that enables Magic DNS cleans it (our next
start included) or an administrator keeps the record.

**Fence.** Key = UUIDv5(sublayer, `instance:epoch:port`). `install` adds, in one WFP
transaction, four persistent filters at `ALE_AUTH_CONNECT` (IPv4 and IPv6 × permit and
block) for TCP to `127.0.0.1` / `::1` on the port: permit when the connecting user
matches SYSTEM, block otherwise. Filters and containers carry a SYSTEM/Administrators
security descriptor, and a container whose ACL admits an ordinary user is never treated
as exclusive. A port that is already fenced is refused. `verify` requires all four
filters before and after, exactly one listener on the exact address owned by the
expected pid (a wildcard listener is rejected), a successful host connection, and a
refusal (`WSAEACCES`) from a PowerShell probe started with `LogonUserW` as LocalService
(no stored password).

**Boot id.** A random UUID stored as `BootId` in the volatile key
`HKLM\SOFTWARE\EasyTierDesk\Volatile` (proven volatile, ACL SYSTEM + Administrators)
for a privileged host, or under `HKCU` for a user host, where it ends at logoff.

**Sweep.** WFP fences (exclusive, removable), `etd-` adapters, interface firewall rules
and network profiles (derived or prefix candidates), program rules whose program lies
in the kernel store, registry values under re-derived adapter GUIDs, the Magic DNS
record and the wintun / WinDivert drivers (candidates only).

**Not reclaimed.** The wintun adapter and routes are verified, never deleted. Drivers
are product scope; the reclaimer probes them but has no removal path. The UPnP mapping
is record-only. A registry value someone else changed is left as is. Magic DNS is left
in place, as a conflict, while another EasyTier process runs.

## Linux

Snapshots come from `ip -j` (iproute2), mutations of links go through rtnetlink by
interface index, DNS through the resolve1 D-Bus API, fences through `nft`.

| Kind | Observed as | Reclaim |
| --- | --- | --- |
| `linux.tun` | Link by name; credential `UnixInterface { index, boot }` | Only if index and boot id equal the recorded credential and the link is a TUN: `RTM_DELLINK` by index |
| `route` | Routes whose device (or a next hop) is the link | Verify only: `Busy`; the kernel drops them with the link |
| `linux.resolved_link` | resolve1 link settings on the link; credential = the link's credential | `RevertLink` on the credential-checked index (or `SetLinkDNS` for restore-if-ours); no resolve1 service means nothing to revert |
| `linux.fence_rule` | Marked fence table (exclusive container) | Delete the table by handle |

The observer also reads `RuntimeDir` (file identity: device + inode) and `Process`
records for the host, and finds TUN names held by a pid through `/proc/<pid>/fdinfo`.

**Fence.** Table `inet etd_f_<UUIDv5(instance:epoch)>_<port>` with the comment
`easytier-desk rpc fence v1`, an `output` chain at priority -150 and two rules that
reject (TCP reset) connections to `127.0.0.1` / `::1` on the port when `meta skuid != 0`.
Table, chain and rules are one `nft` transaction (`create table` is exclusive); a retry
adopts only a marked table. `install` needs root. `verify` requires the expected live
listener, a host connection, and a refusal from a socket created on a thread whose
fsuid is 65534; the table handle and rules must be unchanged and the rule's packet
counter must have grown. `remove` refuses (`Busy`) while a protected kernel (euid 0,
image inside the kernel store, matched by device and inode) still listens on the port,
and re-scans the listeners before deleting; unrelated listeners are logged and left
running.

**Boot id.** `/proc/sys/kernel/random/boot_id`.

**Sweep.** Runtime directories under a host-owned, non-writable root (exclusive),
`etd-` links with their routes and resolve1 settings (derived or prefix candidates),
and fence tables (exclusive; only when running as root).

**Not reclaimed.** Routes are never deleted by name or destination. `/etc/resolv.conf`
is never rewritten. `/dev/net/tun` is never created or deleted here. Unrelated
listeners on a fenced port are left running.

## macOS

| Kind | Observed as | Reclaim |
| --- | --- | --- |
| `macos.utun` | `utunN` read back by the host; credential `UnixInterface { index, boot }` | Verify only: `Busy` until Darwin destroys the utun after its last control socket closes |
| `route` | Routes through that utun | Verify only, as above |
| `macos.fence_rule` | Rule in the product PF anchor (exclusive container) | Remove the rule and reload the anchor |

A utun or route record whose name was never read back (the kernel died before
readiness) holds no name and no credential. It is reached only after every process
record of the generation is closed; as an independent check, a live utun control
socket held by a process of the kernel's uid that runs one of upstream's helper
programs, or whose `-c` configuration lies in the generation's epoch directory, keeps
it indeterminate. No name is guessed.

Index and boot id can match while the utun already belongs to someone else: unit
numbers are reused. The probe therefore also checks who holds the utun's control
socket. If no holder is a protected kernel of this generation (kernel uid, image in the
kernel store, `-c` configuration not in another epoch directory), the old record counts
as gone and the new owner is left untouched.

**Fence.** Rules `block return out quick on lo0 ... to 127.0.0.1|::1 port = <port>
user != 0 label "etd-<UUIDv5(instance:epoch)>-v4|v6"` in anchor
`com.apple/easytier-desk`, persistence `UntilReboot`. Writers serialise on a lock in
the maintenance directory, and PF is enabled through a product reference token that the
service installer takes and releases (`install_anchor` / `uninstall_anchor`). A label or
port already in use is refused. `verify` requires the expected listener, a host
connection, and a refused `sudo -n -u nobody nc -z` probe whose attempt raised this
rule's label packet counter. Removal checks that no protected kernel listener remains
(image vnode in the kernel store, kernel uid) and leaves unrelated listeners running.

**Boot id.** `sysctl kern.bootsessionuuid`.

**Magic DNS.** Disabled by the planner on a privileged host, because upstream deletes
every `/etc/resolver` file carrying its marker and takes over unmarked files of its
domain. The observer only enumerates `/etc/resolver` for consistency diffs.

**Sweep.** PF fence rules only (exclusive), and only as root.

**Not reclaimed.** utun and routes (Darwin removes them; deleting a route by CIDR could
hit an unrelated LAN), `/etc/resolver`.

## Service and appearance

`service/` installs and removes the host as a system service: copies binaries to an
admin-only location, creates the `easytier-desk` group (Unix), registers SCM /
systemd / launchd, keeps a durable lifecycle journal in a maintenance directory that
survives uninstall, and provides the host and maintenance locks. On macOS it also
takes and releases the PF reference. `service/ci_fixture.rs` exists only with the
`ci-test-fixtures` feature on Windows. `appearance.rs` reads desktop appearance for the
UI (accent colours, dark mode, transparency, Mica support) and on Windows sets the
dark-mode attribute of the application's own windows; it changes no OS setting.

## Privileged tests and CI

All tests below are `#[ignore]`, assert a CI-only environment variable, and run only
with `--profile privileged --run-ignored only` on disposable runners. Never run them on
a developer machine.

| Platform | Test files | Workflow |
| --- | --- | --- |
| Windows | `windows_reclaim.rs`: volatile boot marker, network profile and signature cleanup, registry + NRPT + Magic DNS recovery, firewall reclaim and same-name conflict, real wintun after a kill (`ETD_O1_CORE`, the bundled v2.7.1 release kernel from `cargo xtask fetch-cores`). `windows_fence.rs`: WFP fence as LocalSystem (scheduled task) with a second local account as the denied client | `.github/workflows/o1-windows.yml` (also clippy and unprivileged lib tests) |
| Linux | `linux_reclaim.rs`: real link, route and resolve1, plus runs without resolved and without a system bus. `linux_fence.rs`: fence survives host death, second account, kernel-store image check | `.github/workflows/o2-linux.yml`; it also parses Debian 12 and Fedora 44 `nft` output with the lib's ignored fixture tests and checks the pinned kernel's TUN capability as root, with `CAP_NET_ADMIN`, and without |
| macOS | `macos_reclaim.rs` (utun ownership, verify-only reclaim, unnamed utun records), `macos_fence.rs` (PF fence, host death, second account), `macos_resolver.rs` (rejected Magic DNS keeps foreign resolvers), lib test `missing_image_preserves_foreign_identity` | `.github/workflows/o3-macos.yml` (also the `etd-host` install roundtrip) |
| all | `service/**` through `etd-host`'s `install_roundtrip` | `.github/workflows/ci.yml` job `privileged-install`; job `check` runs the unprivileged tests on all three systems |

The platform workflows run on pushes to their dedicated branches that touch the
platform's files, and on manual dispatch; `ci.yml` runs on every push and pull request.

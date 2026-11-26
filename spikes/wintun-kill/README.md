# S2: where a wintun adapter goes when its owner is killed

**The adapter disappears by itself.** After `TerminateProcess` on
easytier-core, the `Get-NetAdapter` entry, the IP interfaces, addresses,
routes and the live device node were all gone at the first sample after the
process exit was observed (70–93 ms after the kill call), and stayed gone for
5 s. 5/5 hard kills; 3/3 Ctrl+C exits ended in the same state. O1's adapter
reclaimer does **not** have to remove anything to take the adapter off the
network, so S2 does not trigger the "privileged must-test removal" branch.

What stays behind is an inactive record of the device, after a graceful exit
too.

## Evidence

GitHub Actions run [45788082691](https://github.com/greenhat616/easytier-desktop/actions/runs/45788082691)
(commit `b05d76e`, `windows-latest`, Windows 10.0.26100, admin). Core:
`easytier-core 2.7.1-c97f36b8-20261124` with its bundled wintun.dll 0.14.1,
taken from upstream's own CI artifact (digest pinned in the workflow). The
artifact `s2-wintun-kill` holds every sample and the stock-tool listings.

Each run used `--dev-name etd-3f9a1c2e --ipv4 10.144.144.1/24
--manual-routes 10.200.77.0/24`. Before each exit: 1 interface, 10 routes,
2 addresses, device node live.

t = 0 is when the process exit was observed. All 21 samples (every 250 ms,
0–5000 ms, at most 22 ms late) were identical in all 8 runs:

| Object | Before | 0 ms … 5000 ms after exit |
|---|---|---|
| IP interfaces (`GetIpInterfaceTable`) | present | 0 |
| Routes (`GetIpForwardTable2`) | 10 | 0 |
| Unicast addresses | 2 | 0 |
| Device node `SWD\Wintun\{guid}` (`CM_Locate_DevNodeW`) | live | **phantom** (not live) |
| `GetIfTable2` row, same LUID and GUID | 1 | **1**, OperStatus 2 (down) |

| Run | Exit code | Call → exit observed |
|---|---|---|
| kill-1 … kill-5 (`TerminateProcess`) | 1 | 70, 93, 87, 89, 86 ms |
| graceful-1 … 3 (Ctrl+C; time includes starting the helper) | 0 | 825, 627, 611 ms |

Stock tools after 5 s, all 8 runs: `Get-NetAdapter -IncludeHidden` 0,
`Get-NetRoute` 0, `Get-PnpDevice` `Unknown / Present=False`,
`pnputil /enum-devices /class Net` still lists the instance id.

Starting again under the same name after a kill worked every time.

## What O1 should take from this

**1. Decide "the adapter exists" from the right source.** These report a dead
adapter as still there: a `GetIfTable2` row, `pnputil /enum-devices`, and any
device listing that includes non-present devices. Use either of:

- `CM_Locate_DevNodeW(&inst, "SWD\Wintun\{GUID}", CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS`
- an IP interface row for the LUID (`GetIpInterfaceTable`)

The instance id is `SWD\Wintun\` + the upper-case braced
`naming::wintun_guid(name)`; the prediction matched in every run.

**2. LUID and instance id do not tell generations apart.** The instance id is
derived from the name. The LUID was `0x0035008000000000` in all 8 generations
of one name. After that device had been removed, a *different* name got the
same LUID (`etd-ffffffff`). doc#2 v7 uses "LUID and device instance id" as the
creation credential for deletion: that identifies an object, but a later object
with the same name can carry the same values. This needs a decision by the
owner of that rule.

**3. wintun removes phantoms itself.** Creating `etd-00000000` removed the
phantom of the killed `etd-3f9a1c2e`, with its registry keys and interface row
(observed twice in the run above). wintun queues this cleanup after creating or
closing an adapter, for every `SWD\Wintun` node that is not running,
whoever created it
([`api/adapter.c`](https://git.zx2c4.com/wintun/tree/api/adapter.c),
`AdapterCleanupOrphanedDevices`; read on master, behaviour observed with
0.14.1). So a leftover can vanish at any moment: "already absent" must count as
success.

**4. Removing the phantom is optional.** Both calls worked every time they hit
an existing phantom (3 times each over three CI runs):

```
pnputil /remove-device "SWD\Wintun\{5BC25188-8866-52C1-A851-1705F7958F22}"
```

In code, as in `Probe.Uninstall` in [`probe.cs`](probe.cs):

1. `set = SetupDiCreateDeviceInfoList(NULL, NULL)`
2. `SetupDiOpenDeviceInfoW(set, instanceId, NULL, 0, &data)`; error
   `0xE000020B` (`ERROR_NO_SUCH_DEVINST`) means it is already gone
3. `DiUninstallDevice(NULL, set, &data, 0, &needReboot)` (`newdev.dll`);
   `needReboot` was false
4. `SetupDiDestroyDeviceInfoList(set)`

Check that the node is not live first: the same instance id belongs to a
running next generation.

Do not rely on either call to clear the registry. Right after both `pnputil`
removals that were checked, the `Control\Network`, `Tcpip`, `Tcpip6` and
`NetBT` keys and the interface row were gone. After `DiUninstallDevice` they
were gone once and still there twice (checked immediately, in two runs). Keep
the separate registry reclaim step.

**5. Other residue survives every case.** The 8 `EasyTier <name> - …` firewall
rules stayed after kill, graceful exit, wintun's cleanup and both removal
calls. The two program rules for `easytier-core.exe` also stayed after kill and
graceful exit. The registry keys under the adapter GUID were there whenever the
phantom was (and sometimes after `DiUninstallDevice`, see 4). doc#2 v7 already
lists the firewall rules and registry values as persistent effects.

## Scope

One OS image (GitHub `windows-latest`, build 26100) and one wintun version
(0.14.1). One adapter at a time, no peers, so no peer-learned routes (the manual
route stands in for a routed subnet). Reboot, Windows 10 client and ARM64 were
not tested.

## Run it

`.github/workflows/s2-wintun.yml` runs on pushes that touch this directory, and
by `workflow_dispatch`. `run.ps1 -CoreDir <dir with easytier-core.exe and
wintun.dll>` creates and kills real adapters; outside CI it refuses to run
without `-AllowLocal`. It is a PowerShell spike with a small C# probe, so there
is no cargo project.

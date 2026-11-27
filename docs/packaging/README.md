# Packaging

Release packages are built by `cargo xtask dist` (see [`xtask/README.md`](../../xtask/README.md)).
This release builds the Windows MSI (PK3). Linux `.deb`/`.rpm`/Arch packages come with PK4,
the release workflow with PK5; macOS is not packaged this release. The plan is doc#16 v2
in topic#53.

## Two folders

A package owns only its **payload folder**; the service owns its **protected folder**.

| | Windows | Owner |
| --- | --- | --- |
| Payload | `C:\Program Files\EasyTier Desktop\` (`etd-ui.exe`, `etd-host.exe`, `etd-ctl.exe`, `cores\<version>\*`) | Windows Installer: written, replaced and removed with the product |
| Protected | `C:\Program Files\EasyTierDesk\`, state in `C:\ProgramData\EasyTierDesk\`, lock in `C:\ProgramData\EasyTierDesk.maintenance\` | `etd-host`: created by `etd-host install` with its own ACLs, never in the MSI's file tables |

The package runs the payload's `etd-host` to install, upgrade or remove the service. The
kernel files in the payload are only the source `etd-host install`/`upgrade` imports and
verifies against its embedded `cores.lock`; the service never runs them from there.

## Windows MSI

`packaging/windows/Product.wxs.tmpl` is rendered by `cargo xtask dist` and built with
**WiX 7.0.1**: a per-machine MSI, unsigned this release (msg#1395, issue #2: users see an
unknown-publisher warning), with a fixed UpgradeCode for major upgrades and a Start menu
shortcut to `etd-ui.exe`.

### Building

```powershell
dotnet tool install --global wix --version 7.0.1
wix eula accept wix7
wix extension add -g WixToolset.Util.wixext/7.0.1
cargo build --release -p etd-ui -p etd-host -p etd-ctl
cargo xtask fetch-cores --target host
cargo xtask dist        # target\dist\x86_64-pc-windows-msvc\easytier-desktop-<version>-x86_64.msi
```

WiX 6 and later binaries come under the Open Source Maintenance Fee EULA. This project
uses them as a non-commercial open source project and accepts the EULA explicitly:
`wix eula accept wix7` and `wix build -acceptEula wix7` (without it the build fails with
WIX7015). An organization with US$10,000 or more of annual revenue from using WiX that
rebuilds these packages must sponsor the WiX project; see
<https://docs.firegiant.com/wix/osmf/>.

### Installing

```powershell
msiexec /i easytier-desktop-<version>-x86_64.msi /qn /l*v install.log
msiexec /i easytier-desktop-<version>-x86_64.msi /qn ETD_ALLOW_USER=S-1-5-21-...-1001
msiexec /x easytier-desktop-<version>-x86_64.msi /qn
```

`ETD_ALLOW_USER` (optional) enrolls one more account SID as a service administrator,
passed to `etd-host install --allow-user`. By default only LocalSystem and the
Administrators group may use the service.

`etd-ctl.exe` is registered under App Paths
(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\etd-ctl.exe`), which serves
the Run dialog (Win+R) and other ShellExecute callers only. **cmd and PowerShell do not
search App Paths**, and the package does not change `PATH`: in a terminal, run
`"C:\Program Files\EasyTier Desktop\etd-ctl.exe"` or add that folder to `PATH` yourself.

### Custom actions

All four run the payload's `etd-host.exe` through `WixQuietExec` (no console window) as
LocalSystem (`Impersonate="no"`). Each command's output goes to the MSI log
(`/l*v`, lines starting `WixQuietExec`).

| Action | When | Runs | Scheduled |
| --- | --- | --- | --- |
| `InstallHostService` | first install (`NOT Installed AND NOT WIX_UPGRADE_DETECTED`) | `etd-host install [--allow-user <SID>]` | last, before `InstallFinalize` |
| `RollbackHostInstall` | rollback of a first install | `etd-host uninstall` (failure ignored) | before `InstallHostService` |
| `UpgradeHostService` | major upgrade (`WIX_UPGRADE_DETECTED`) | `etd-host upgrade` | last, before `InstallFinalize` |
| `UninstallHostService` | full removal (`REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`) | `etd-host uninstall` | before `RemoveFiles` |

`MajorUpgrade` removes the old product inside the new one's transaction
(`afterInstallInitialize`). That removal sets `UPGRADINGPRODUCTCODE`, so it never runs
`etd-host uninstall`: the ledger, allow list and install key stay. Install and upgrade
run last so that no MSI action after them can fail; a committed `etd-host upgrade` is
therefore never undone by Windows Installer. Undoing it would put the old payload beside
a newer service, and running the old `upgrade` to downgrade could meet a ledger the new
version already migrated.

### What a failed custom action leaves behind

Windows Installer reports error 1603 and rolls back its own changes (payload, shortcut,
App Paths, product registration). What happens to the service:

- **First install fails** (`etd-host install` exits non-zero, for example because
  `C:\Program Files\EasyTierDesk` already exists and is not ours, or the service does
  not report ready in time): `etd-host install` rolls back what it created, using its
  journal, before it exits; `RollbackHostInstall` then runs `etd-host uninstall`, which
  finds nothing to remove and never touches what it did not create (its failure, as
  with a foreign folder, is ignored).
  The machine is as before, except `C:\ProgramData\EasyTierDesk.maintenance\` and its
  `host.lock`, which are kept by design. A foreign `EasyTierDesk` folder is left
  untouched; remove it, then install again.
- **Upgrade fails** (`etd-host upgrade` exits non-zero): `etd-host upgrade` has already
  restored the previous host image, kernel manifest and service registration and
  restarted the previous service (see [`cli-and-install.md`](../../crates/etd-host/docs/cli-and-install.md#upgrade)).
  Windows Installer then restores the previous product and payload. The previous
  version stays installed and running, with its state. Kernel directories the new
  version imported stay in the protected folder until `etd-host remove-core` or
  uninstall. If the restore itself failed, the service stays disabled with the upgrade
  stage recorded: run the new MSI again, or uninstall; both finish the restore first.
- **The machine loses power during an upgrade**: the recorded upgrade stage stops
  any host from starting on a half-replaced image. Install the new MSI again (or
  uninstall): `etd-host upgrade` restores the previous version, then upgrades.
- **Uninstall fails** (`etd-host uninstall` exits non-zero, for example while it waits
  for the service to stop): the product, payload and service registration stay; the
  service may be left disabled with its data, as `etd-host uninstall` reports. Run the
  uninstall again; `etd-host uninstall` resumes from its journal.

## Tests

The privileged workflow's `msi` suite (`etd-testkit --test tier3`, `tests/tier3/package.py`)
builds three test MSIs with `cargo xtask dist` and runs them on a fresh Windows runner: a
refused first install leaves nothing, a first install with `ETD_ALLOW_USER`, a major
upgrade keeping install id, install key and ledger settings, an upgrade whose new host
never serves (rolled back by `etd-host` and by Windows Installer), and an uninstall
compared with the machine before install. Those test packages carry the CI upgrade fault
(`ci-test-fixtures`); release packages must not (PK5 checks the release artifacts).

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
Administrators group may use the service. Only a local or domain account SID is accepted
(`S-1-5-21-<domain>-<RID>`, RID 1000 or above): `etd-host` refuses groups and well-known
SIDs such as Everyone, Users or Administrators, and the package refuses a value with a
quote or a space before any change. It is not a Secure property, so set it from an
elevated prompt; from a non-elevated one Windows Installer drops it, and a standard
user's elevated (policy) install cannot pass it.

A package installs only where no service exists or as an upgrade of an installed
product. If the service is already installed without a matching product (installed with
`etd-host install`, or the product registration was lost), the package refuses before
any change: uninstall it first (`etd-host uninstall`). If you just uninstalled it, restart
Windows first: while any program still holds the service open, Windows keeps it marked
for deletion and the package still finds it. Same-version rebuilds upgrade
(`AllowSameVersionUpgrades`), so a rebuilt package replaces the installed product instead
of installing beside it; ICE61 flags this by design, and `wix build` runs no ICE
validation.

`etd-ctl.exe` is registered under App Paths
(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\etd-ctl.exe`), which serves
the Run dialog (Win+R) and other ShellExecute callers only. **cmd and PowerShell do not
search App Paths**, and the package does not change `PATH`: in a terminal, run
`"C:\Program Files\EasyTier Desktop\etd-ctl.exe"` or add that folder to `PATH` yourself.

### Custom actions

All four run the payload's `etd-host.exe` through `WixQuietExec` (no console window) as
LocalSystem (`Impersonate="no"`). That LocalSystem token lacks SeDebugPrivilege: the
Windows Installer service's RequiredPrivileges omit it. `etd-host uninstall` therefore
reads loaded-driver paths from the kernel module list there, and still fails closed when
a path is incomplete (see the `etd-sysfx-os` README). Each command's output goes to the MSI log
(`/l*v`, lines starting `WixQuietExec`).

| Action | When | Runs | Scheduled |
| --- | --- | --- | --- |
| `InstallHostService` | no service yet (`NOT Installed AND NOT ETD_SERVICE_PRESENT`): a first install, or an upgrade after the service was removed | `etd-host install --owner [ProductCode] [--allow-user <SID>]` | last, before `InstallFinalize` |
| `RollbackHostInstall` | rollback of that install | `etd-host uninstall --only-owner [ProductCode]` (failure ignored) | before `InstallHostService` |
| `UpgradeHostService` | major upgrade over a service (`WIX_UPGRADE_DETECTED AND ETD_SERVICE_PRESENT`) | `etd-host upgrade` | last, before `InstallFinalize` |
| `UninstallHostService` | full removal (`REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE`) | `etd-host uninstall` | before `RemoveFiles` |

`ETD_SERVICE_PRESENT` comes from a registry search for the service's key
(`HKLM\SYSTEM\CurrentControlSet\Services\easytier-desk-host`), whoever installed it; a
launch condition refuses a first install while it is set. `--owner` records the
package's ProductCode in `etd-host`'s journal, and the rollback removes only an
installation recorded with that ProductCode: it can never remove a service this package
did not install.

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
  journal, before it exits; `RollbackHostInstall` then runs
  `etd-host uninstall --only-owner [ProductCode]`, which removes only an installation
  this package recorded and otherwise does nothing (its failure is ignored). A service
  that existed before never reaches this point: the launch condition refuses first.
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
- **Uninstall is rolled back after `etd-host uninstall` succeeded** (a later MSI action
  fails, or the user cancels): `UninstallHostService` has no rollback, so Windows
  Installer restores the product and payload but the service and its data are gone. A
  repair runs no custom action and does not bring the service back. Install the next
  version (or any upgrade package): with no service present it runs `etd-host install`
  instead of `upgrade`. Or uninstall the product and install it again.

## Application icons

The Triad application and tray icon assets live under `packaging/assets/icons/` (documented in [`packaging/assets/README.md`](../../packaging/assets/README.md)):

- **Windows:** `packaging/assets/icons/app.ico` (multi-size 16–256 px) is embedded into `etd-ui.exe` as resource ID `1` (giving Start Menu shortcuts and taskbar pins the Triad icon automatically) and serves as the MSI Add/Remove Programs (`ARPPRODUCTICON`) icon.
- **Linux:** `packaging/assets/icons/hicolor/` provides the freedesktop hicolor PNG sizes (`16x16`–`256x256`) and scalable SVG under `easytier-desktop.{png,svg}`, matching the window `app_id` (`easytier-desktop`).
- **macOS:** `packaging/assets/icons/app.icns` provides the squircle `.icns` bundle icon for future `.app` packaging.

## Tests

The privileged workflow's `msi` suite (`etd-testkit --test tier3`, `tests/tier3/package.py`)
builds four test MSIs with `cargo xtask dist --allow-test-fixtures` and runs them on a
fresh Windows runner: a refused first install leaves nothing; a package over a
CLI-installed service is refused before any change and the service keeps serving; a
first install with `ETD_ALLOW_USER`, recorded as owned by its ProductCode; a same-version
rebuild and a major upgrade, both keeping install id, install key and ledger settings;
an upgrade whose new host never serves (rolled back by `etd-host` and by Windows
Installer); and an uninstall compared with the machine before install. Those test
packages carry the CI upgrade fault (`ci-test-fixtures`) and a debug `etd-ui`; without
`--allow-test-fixtures`, `dist` refuses both, and the workflow checks that it refuses
that `etd-host` (PK5 also checks the release artifacts).

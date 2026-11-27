# Packaging

Release packages are built by `cargo xtask dist` (see [`xtask/README.md`](../../xtask/README.md)).
This release builds the Windows MSI (PK3) and Linux `.deb`/`.rpm`/Arch packages (PK4),
and `.github/workflows/release-package.yml` builds, checks and smoke tests them for a
release (PK5); macOS is not packaged this release. The plan is
doc#16 v2 in topic#53.

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

## Linux packages

`packaging/linux/nfpm.yaml.tmpl` is rendered by `cargo xtask dist` and built with
**nfpm 2.49.0** into three packages from one definition: `easytier-desktop_<v>-1_amd64.deb`,
`easytier-desktop-<v>-1.x86_64.rpm` and `easytier-desktop-<v>-1-x86_64.pkg.tar.zst` (Arch).
They are unsigned this release (the sign hook is a no-op).

| Path | What |
| --- | --- |
| `/usr/lib/easytier-desktop/` | `etd-ui`, `etd-host`, `etd-ctl`, `cores/<version>/easytier-core` (the payload) |
| `/usr/bin/easytier-desktop`, `/usr/bin/etd-ctl` | links into the payload |
| `/usr/share/applications/easytier-desktop.desktop` | desktop entry |
| `/usr/share/icons/hicolor/*/apps/easytier-desktop.{png,svg}` | icons |

No systemd unit is packaged: `etd-host install` writes
`/etc/systemd/system/easytier-desk-host.service`, creates the `easytier-desk` group and the
protected folder `/usr/local/lib/easytier-desk`, and starts the service. State lives in
`/var/lib/easytier-desk`, the maintenance lock in `/var/lib/easytier-desk-maintenance`.

The protected copy under `/usr/local/lib/easytier-desk` is deliberately not owned by the
package: `etd-host` copies its own image there so that the running service never
depends on files the package manager replaces, and only `etd-host uninstall` removes it.
Debian Policy (9.1.2) and the Fedora guidelines forbid a package from creating files
under `/usr/local`, so these packages are fit for distribution from this project but
not for a distribution's own repository: that would need the protected folder moved
(an `etd-host` and sysfx layout change with a migration).

### Building

```sh
cargo build --release -p etd-ui -p etd-host -p etd-ctl
cargo xtask fetch-cores --target host
# nfpm 2.49.0 on PATH (https://github.com/goreleaser/nfpm/releases/tag/v2.49.0)
cargo xtask dist        # target/dist/x86_64-unknown-linux-gnu/*.deb, *.rpm, *.pkg.tar.zst
```

`dist` runs whatever `nfpm` is on `PATH` and checks only that it reports version 2.49.0;
verifying where that binary came from is up to you. CI (the privileged `deb` job, and
PK5's release workflow) downloads the release archive and checks its SHA-256 before
use.

Build on the oldest distribution you support (doc#16 plans Ubuntu 22.04 for PK5): the
binaries need that glibc or newer, and `dist` writes that floor into the packages
(see [Dependencies](#dependencies)).

### Maintainer scripts

`packaging/linux/scripts/maintainer.sh` is rendered once per format and hook. Every hook
runs the payload's `etd-host`; a service is tagged with the owner `easytier-desktop-package`
when the package installs it, and the package upgrades or removes only a service with that
tag.

| Step | deb | rpm | Arch | Runs |
| --- | --- | --- | --- | --- |
| before unpacking a first install | `preinst install` | `%pre` with `1` | none | refuses if the service already exists |
| first install, or its retry | `postinst configure` (no old version) | `%post` with `1` | `post_install` | `etd-host install --owner easytier-desktop-package` |
| upgrade | `postinst configure <old>` | `%post` with `2`+ | `post_upgrade` | `etd-host upgrade --only-owner easytier-desktop-package` |
| full removal | `prerm remove` | `%preun` with `0` | `pre_remove` | `etd-host uninstall --only-owner easytier-desktop-package` |
| the old package during an upgrade | `prerm upgrade` | `%preun` with `1` | (not called) | nothing: the ledger and allow list stay |

- **An upgrade with no service** (it was uninstalled by hand, or systemd was missing when
  the package was installed): the hook runs `etd-host install` instead and says so.
- **A service that already exists** (installed with the CLI): deb and rpm refuse before
  anything is unpacked and name the command to remove it
  (`/usr/local/lib/easytier-desk/etd-host uninstall`). pacman cannot abort from a hook, so
  on Arch `post_install` says plainly that this package will not manage that service,
  prints how to remove it or let the package manage it, and the package's upgrades and
  removal leave it alone.
- **A retried first install** (`dpkg --configure -a` after a configure that stopped once
  the service had registered): `install --owner` again finds an installation recorded
  with the same owner and only starts it. An installation recorded with no owner or
  another one is refused, so the retry fails rather than taking it over.
- **No systemd** (a container): every hook prints a notice and succeeds. On a systemd
  host, run `/usr/lib/easytier-desktop/etd-host install --owner easytier-desktop-package`
  so the package's later upgrades and removal manage that service. Without `--owner` the
  service is ownerless: the hooks leave it alone, and you upgrade and remove it with
  `etd-host` yourself.
- Every hook runs with `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, whatever the package manager
  passed.

### What a failed hook leaves behind

Package managers do not restore files when a script fails, and they differ in what they
record:

| | deb | rpm | Arch |
| --- | --- | --- | --- |
| after a failed install or upgrade hook | the new files unpacked, the package half-configured (`iF`) | the transaction completes: the new files installed, the scriptlet failure reported | the transaction completes: the new files installed, the hook's error printed |
| rerun the hook | `dpkg --configure -a` | none: run the command yourself | none: run the command yourself |

**First install fails** (`etd-host install` exits non-zero). `etd-host install` rolls
back what it created; if its rollback is incomplete it says so, and
`/usr/lib/easytier-desktop/etd-host uninstall --only-owner easytier-desktop-package`
resumes the cleanup. Fix the cause, then
`dpkg --configure -a` on deb, or on rpm and Arch run
`/usr/lib/easytier-desktop/etd-host install --owner easytier-desktop-package`; or remove
the package.

**Upgrade fails** (`etd-host upgrade` exits non-zero). The new payload is in
`/usr/lib/easytier-desktop` but the service still runs from the protected folder.
`etd-host upgrade` ends in one of these states and prints which:

| What `etd-host upgrade` printed | The service | What to do |
| --- | --- | --- |
| `upgrade rolled back` / `upgrade stopped; the previous service was restarted` | the previous version, restored and serving | fix the cause, then rerun the upgrade (below) |
| `…the ledger was (or may have been) migrated by the new version, so the previous host runs diagnostics-only` (or `whether the new version migrated the ledger is unknown`) | the previous version, diagnostics only: networks do not start | rerun the upgrade (below); the new version opens the migrated ledger |
| `…the previous service did not restart` | stopped | rerun the upgrade, or `/usr/local/lib/easytier-desk/etd-host resume-service` (see below) |
| `rollback incomplete…; the service stays disabled` or `an interrupted upgrade could not be restored` | disabled | rerun the upgrade, or `/usr/local/lib/easytier-desk/etd-host uninstall --only-owner easytier-desktop-package` and install again |

`resume-service` only re-enables and starts an installation whose journal records no
upgrade in progress; it refuses while one is recorded (an incomplete rollback or an
interrupted upgrade), and then only rerunning the upgrade or uninstalling helps.

Rerunning the upgrade: `dpkg --configure -a` on deb; on rpm and Arch,
`/usr/lib/easytier-desktop/etd-host upgrade --only-owner easytier-desktop-package`. Until
then the new `etd-ui` and `etd-ctl` talk to the previous host; if their contract versions
differ they report a version mismatch instead of working.

The deb suite exercises only the first row, and only the same build with a CI fault
injected, not one release upgrading to another: it shows dpkg left at `iF`, the previous
service serving, and `dpkg --configure -a` completing the upgrade.

**Removal fails** (`etd-host uninstall` exits non-zero): dpkg and rpm keep the package
installed; run the removal again, `etd-host uninstall` resumes from its journal. pacman
removes the files anyway: run
`/usr/local/lib/easytier-desk/etd-host uninstall --only-owner easytier-desktop-package`.

**Downgrades are not supported.** apt, dnf and pacman will install an older package, but
its postinst runs the older `etd-host upgrade`, which may refuse the ledger the newer
version wrote or leave the host diagnostics-only, and on deb the package stays at `iF`.
Recover by installing the newer package again.

### Dependencies

The Depends lists in `xtask/src/dist/linux.rs` come from the privileged `deb` job,
which prints, per binary, the libraries it links (`ldd`, with the owning Ubuntu package
from `dpkg -S`) and the library names it holds for loading at run time:

| Binary | Links | Loads at run time |
| --- | --- | --- |
| `etd-ui` | glibc, libgcc, libxcb, libxcb-xkb, libxkbcommon, libxkbcommon-x11 | Vulkan, EGL, Wayland client and EGL (renderdoc is an optional debugging hook, not a dependency) |
| `etd-host`, `etd-ctl` | glibc, libgcc | nothing more |

`etd-host` also runs `nft` and `ip` (`nftables`, `iproute2`), and the icons go into
`hicolor-icon-theme`'s folders, so every format depends on that package, which owns them. The deb names are installed
by that job and by the release workflow's Ubuntu 22.04 smoke test; the rpm and Arch names
are installed by its Fedora and Arch Linux container smoke tests.

- **The C library floor:** `dist` reads the highest `GLIBC_x.y` symbol version the three
  binaries need and writes `libc6 (>= x.y)` (deb) and `glibc >= x.y` (rpm), so an older
  distribution refuses the package instead of failing in its postinst. Arch is rolling
  and gets no bound.
- **A Vulkan driver** is recommended, not required (the loader is a dependency):
  deb `Recommends: mesa-vulkan-drivers | vulkan-icd`, rpm `Recommends: mesa-vulkan-drivers`,
  Arch `optdepends` `vulkan-driver`. Without one, `etd-ui` cannot open its window.

## Release workflow

`.github/workflows/release-package.yml` runs on a `v*` tag (which must name the workspace
version) and by hand (`workflow_dispatch`). It builds from the tree alone, with no build
cache:

| Job | Runner | What |
| --- | --- | --- |
| `package-windows` | windows-latest | release binaries, WiX 7.0.1, `cargo xtask dist` → the MSI; its administrative image (`msiexec /a`) must carry no CI test-fixtures marker |
| `package-linux` | **ubuntu-22.04** | release binaries, nfpm 2.49.0 (SHA-256 checked) → deb, rpm and Arch; the C library floor must be 2.35 or older, and the extracted deb, rpm and Arch contents must carry no CI test-fixtures marker |
| `smoke-windows` | windows-latest | `tests/tier3/release.py msi_release`: install, upgrade, uninstall, machine compared with before |
| `smoke-linux` | ubuntu-22.04 | `release.py deb_release`: the same with apt, on the oldest supported Ubuntu |
| `smoke-rpm` | Fedora 43 container | `.github/scripts/rpm-smoke.sh`: scriptlets parse, root-owned files and modes, upgrade, and erasing leaves the file system as before the install (empty folders included); no systemd, so the hooks only print their notice |
| `smoke-arch` | Arch Linux container (`base-20261122.0.629543`, by digest) | `.github/scripts/arch-smoke.sh`: the same for the Arch package with pacman (`.INSTALL` parses, files, upgrade, removal leaves nothing) |
| `checksums` | ubuntu-latest | read-only: the two package artifacts by name, which must hold exactly the four release packages, and `SHA256SUMS.txt` over them |
| `release` | ubuntu-latest | only on a `v*` tag, and the only job with `contents: write`: a **draft** GitHub release with the packages, the sums and an unsigned-package notice, which a maintainer reviews and publishes |

Every action is pinned by commit SHA and the Fedora image by digest; nfpm, the WiX
7.0.1 and WixToolset.Util.wixext 7.0.1 packages (installed through a NuGet
configuration whose only source is the checked folder, and the extracted extension
compared with the package) and the smoke tests' Python dependencies
(`.github/scripts/tier3-requirements.txt`, `pip --require-hashes`) are SHA-256 checked.
A manual run never gets write permission.

The smoke upgrades go to a test-only package of the next patch version (the same
binaries with bytes appended to `etd-host`), which is never published. The packages
are unsigned (issue #2): `dist` runs `--sign-hook none`, and a placeholder step fails
if `ETD_SIGNING_ENABLED` is set.

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

The `deb` suite (`tests/tier3/deb.py`) builds three test packages the same way and runs
them on a fresh Ubuntu runner: a package over a CLI-installed service is refused by its
preinst and the service keeps serving; a retried first install (`dpkg --unpack`, then
`dpkg --configure`) that fails over a CLI-installed service without touching it and
resumes the package's own registered service; a first install with its payload, links,
desktop entry and icons (root-owned, with their modes), recorded as owned by the package; an upgrade keeping install id,
install key and ledger settings; an upgrade whose new host never serves (rolled back by
`etd-host`, the old service keeps serving, dpkg leaves the package half-configured) and
its completion by `dpkg --configure -a`; and a purge compared with the machine before
install. Every hook branch of the three formats, Arch `pre_remove` with a version
argument included, is run against a stub `etd-host` by xtask's unit tests on Linux. The job
also checks that every path in the deb and Arch packages is root's and every folder is 0755.

# etd-host command line, locks and installation

This document follows `src/main.rs` and `src/host.rs` in this crate and the service
installation module of `etd-sysfx-os` (`crates/etd-sysfx-os/src/service/`), which
does the OS work.

## Locks

Two OS file locks, both opened without following symlinks or reparse points and never
deleted (deleting a lock file while someone waits on it would allow a second lock):

| Lock | File | Kind | Held by |
| --- | --- | --- | --- |
| Singleton (host lifetime) | `host.lock` | non-blocking; a second holder gets "host already running; stop it before maintenance" | a running host, and every maintenance command that opens the ledger |
| Maintenance command | `maintenance-command.lock` | blocking | `install`, `upgrade`, `uninstall`, `resume-service`, and `reclaim` / `remove-core` in service mode |

For the service both live in a separate maintenance directory (table below) that
install and uninstall never remove. A user host locks its state directory, and also
the per-user runtime directory when that differs, so two state directories cannot
serve the same user endpoint.

Because the running service holds the singleton lock, `reclaim` and `remove-core` in
service mode refuse until the service is stopped. That makes them the only ledger
writer while they run.

## Directories

Service form (paths come from the OS, never from clients):

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Install dir (host image, `cores/`) | `%ProgramFiles%\EasyTierDesk` | `/usr/local/lib/easytier-desk` | `/Library/Application Support/easytier-desk` |
| State (ledger, logs, repair index) | `%ProgramData%\EasyTierDesk` | `/var/lib/easytier-desk` | `<install>/state` |
| Run dir | `<state>\run` | `<state>/run` | `<state>/run` |
| Endpoint | `\\.\pipe\easytier-desk-host` | `/run/easytier-desk/host.sock` | `<install>/run/host.sock` |
| Maintenance dir | `%ProgramData%\EasyTierDesk.maintenance` | `/var/lib/easytier-desk-maintenance` | `/Library/Application Support/easytier-desk-maintenance` |
| Registration | SCM service `easytier-desk-host` | `/etc/systemd/system/easytier-desk-host.service` | `/Library/LaunchDaemons/easytier-desk-host.plist` |

Windows locations come from Known Folders. User form: state is
`%LOCALAPPDATA%\EasyTierDesk`, `~/Library/Application Support/easytier-desk` or
`$XDG_STATE_HOME/easytier-desk` (default `~/.local/state/easytier-desk`), with `run/`
and `cores/` inside; directories are created private to the user (mode 0700, or a
user-only DACL on Windows).

## `run`

1. Resolve the layout for the form and prepare it. User: refuse an elevated token,
   create the private directories. Service: validate ownership and permissions of the
   installed tree, require that the running image is the installed one, and that it
   runs as LocalSystem (`S-1-5-18`) or root.
2. Take the singleton lock. Service: require the install journal phase `Installed`.
3. Start logging, wire the dependencies (below) and serve until shutdown: Ctrl-C or
   `SIGTERM`, the service manager's stop on Windows, the orchestrator ending (a user
   host whose leases ran out), or the server failing. Shutdown stops instances,
   reclaims, then gives final replies up to 3 s before closing the listener.

On Windows, `run --mode service` enters the SCM dispatcher, which runs the same host.

Dependency wiring (`host::dependencies`): ProcessKit engine with the installed image
as the console-ctrl helper; repair index file and install key; OS adapters from
`etd_sysfx_os::adapters` (on a platform without them, fail-closed stand-ins that
refuse new effects and kernel launches); SQLite ledger `ledger.sqlite3`; kernel store
with the embedded trusted table; reclaim engine with OS reclaimers plus the host's
process and runtime-directory reclaimers; `BackoffPolicy` per instance; port fence for
the service form only.

## `install`

Administrator only. `--allow-user` takes account SIDs on Windows (`S-1-5-21-<domain>-<RID>`
with RID 1000 or above; groups and well-known SIDs are refused) or UIDs on Unix; each
becomes an admin allow-list entry. `--owner <tag>` (1 to 64 letters, digits, braces,
hyphens, underscores or dots) records who installed in the journal, with its first
write; the MSI passes its ProductCode (see `uninstall --only-owner`).

1. Take the maintenance lock. An existing journal must be in phase `Installing` (an
   interrupted install, which is rolled back first); anything else refuses.
2. Take the singleton lock. **Preflight:** refuse if any product directory, the
   group, the unit file or the service registration already exists. Install never
   adopts objects it did not create.
3. Begin the journal. Every resource is recorded as planned before it is created, so
   a rollback removes only what this installation created.
4. Create the directories and copy the running executable into the install
   directory (registration never points at a download directory). The copy is
   read from the running image itself, not from its path (see
   [The running image](#the-running-image)), hashed while it is copied, and the
   installed file must read back with that hash.
   - Windows: install dir with a protected DACL (SYSTEM and Administrators full,
     Users read/execute), state dir for SYSTEM and Administrators only, then `run`
     and `cores`.
   - Unix: install 0755, state 0700, run 0700, cores 0755, socket dir 0755. A free
     GID in 60000..65000 is reserved in the journal, then the
     `easytier-desk` group is created (`groupadd --system` / `dseditgroup`).
5. Install the bundled kernels: for each row of the embedded table, copy
   `<installer dir>/cores/<version>/` into `<cores>/<sha256>/`, hashing inside the
   protected destination, check that the kernel identifies as that version, and write
   the manifest. Every row must have its bundle, so with the current release table
   `install` fails without `<installer dir>/cores/2.7.1/` (stage it with
   `cargo xtask fetch-cores --target host --bundle <installer dir>/cores`).
6. Open the ledger and commit the seed allow list. Windows: LocalSystem and the
   Administrators group as admin. Unix: UID 0 as admin and the `easytier-desk` group
   as control. Plus the `--allow-user` entries.
7. Register:
   - Windows: own-process service, automatic start, LocalSystem, arguments
     `run --mode service`; failure action restart after 2 s, reset after 300 s.
   - Linux: unit file (`Type=simple`, `Restart=on-failure`,
     `RuntimeDirectory=easytier-desk`, `KillMode=control-group`, `Delegate=yes`,
     `WantedBy=multi-user.target`), `systemctl daemon-reload`, `systemctl enable`.
   - macOS: LaunchDaemon plist (`RunAtLoad`, `KeepAlive`) and the pf anchor reference.
8. Journal phase `Installed`, release the singleton lock, start the service and wait
   up to 30 s for an endpoint served by a privileged process from the install
   directory. If that fails, the installation is uninstalled again.

Any failure before `Installed` rolls back the journaled resources; if the rollback
itself fails the message says to retry `uninstall`.

## `upgrade`

Administrator only. Run it from the new installation payload (the new `etd-host`
with its bundled `cores/` beside it), never from the installed image, which it
refuses (also when that cannot be determined). The new image is the running image,
read as described in [The running image](#the-running-image); its embedded kernel
table is the authority for the kernels it brings.

The journal records the upgrade's stage, each written before its step: `Disabling`,
`Replacing`, `Starting`, and `RollingBack` before any restore. Under the maintenance
lock, with the journal at `Installed`:

1. If no stage is recorded, the installed image already has the running image's
   bytes, every bundled kernel is present and verifies, and the manifest is current,
   it removes leftover backups of an earlier upgrade and only starts and verifies the
   service, so a repeated upgrade is harmless.
2. Record `Disabling`, stop and disable the service, and take the singleton lock with
   the same bounded wait as `uninstall`. A `Replacing` or `Starting` stage left by a
   crashed attempt is restored first (below).
3. Record `Replacing`. Copy the image beside the installed one as `etd-host.new`,
   apply the install tree's permissions, check its ownership and that it reads back
   with the hash taken while copying, then rename the installed image to
   `etd-host.prev` and the copy into place.
4. Merge kernels: bundles this build trusts that are missing are verified and
   published as new version directories; the old manifest is saved as
   `upgrade-manifest.json` in the maintenance directory and the new one lists only
   versions the new table trusts. Kernel directories are never deleted: ledger
   records may name them, and `remove-core` or uninstall reclaims them.
5. Refresh the registration: on Unix, if the unit or plist differs from this build's,
   save the installed one as `upgrade-registration` in the maintenance directory
   (temporary file, sync, rename, sync the directory), record its SHA-256 in the
   journal, then replace it (`daemon-reload` on Linux). Only a backup with the
   journal's digest is ever restored, and the digest is cleared with the stage. The
   Windows SCM configuration is the same for every build. Validate the install tree.
   A build accepts its own registration and those listed as earlier builds'
   (`PREVIOUS_UNIT_CONTENTS` in `etd-sysfx-os`): a build that changes the unit must
   list the old content there, so its upgrade can stop the old service and a
   rollback can start it again.
6. Record `Starting`, release the lock and start the service. The new host clears
   the stage itself once its self-check reaches Serving (not diagnostics-only); that
   commits the upgrade. `upgrade` waits for the verified endpoint (30 s) and then for
   the commit (90 s).
7. Delete `.prev`, the saved manifest and the saved registration.

The ledger, the allow list, the repair index with its install key, and the state
and maintenance directories are never touched; the ledger is never rolled back.

- Every restore first records `RollingBack` and clears the stage only when all of
  it is done.
- **Failure before the start** (steps 2 to 5): restore the previous image, manifest
  and registration, remove the kernel directories this attempt published, clear the
  stage and restart the previous service. If the singleton lock cannot be taken
  after the stop, the previous service is restarted as well.
- **The new host does not commit** (step 6): stop it, restore image, manifest and
  registration, keep every kernel directory (the new host may have recorded them),
  clear the stage and restart the previous service. If the new host migrated the
  ledger (its SQLite `user_version` changed, or a write-ahead log is left), the
  previous host can only run diagnostics-only: the error says so and asks to run the
  new upgrade again; if the ledger header cannot be read, it says that a migration is
  unknown. If the new host committed after the wait ended, the upgrade stands.
- **A crash**: the stage stays. A host does not start while `Replacing` or
  `RollingBack` is recorded, and `resume-service`, `reclaim` and `remove-core` refuse
  while any stage is recorded. The next `upgrade` or `uninstall` restores the previous image, manifest
  and registration first (keeping kernel directories). With `Disabling` nothing was
  replaced; the previous host still starts.
- If a restore itself fails, the service stays disabled and the error says to retry
  `upgrade` or `uninstall`.
- **Windows, uninstall after a crash at `Replacing`:** run from the installed image,
  which is then the new one, `uninstall` restores the previous image and parks the
  running one as `etd-host.failed`, which stays mapped until the process exits. It
  counts that image as the installed one, so, as for any uninstall run from the
  installed image, a helper copied from it removes the install directory after the
  process exits (`uninstall --status` reports it). The MSI runs `uninstall` from its
  payload copy, which is never the installed image.

If the upgrade drops the selected kernel version, it says so and names the instances
set to run. Planning then fails with "selected kernel ... is not in this host's
trusted kernel store; select another kernel" until another kernel is selected.

### The running image

`install` and `upgrade` copy the host image from a handle bound to the executable
the process is running, not from its path, which a process of the user who started
the payload could swap after the elevation prompt verified it:

- Linux: `/proc/self/exe`, the executing inode itself; the kernel refuses writes to an
  executing file.
- macOS: the path opened without following a final symlink; its device and inode
  must equal those of the vnode mapped for the host's code
  (`proc_pidinfo(PROC_PIDREGIONPATHINFO)`).
- Windows: the path opened sharing only reads (it cannot be renamed, written or
  deleted while open), not a reparse point, and with the volume serial and file id of
  the file mapped for the host's code (`GetMappedFileNameW`).
- Unix: the file must not be writable by group or others, and its change time and
  size must be unchanged after the copy.

The residual trust is in the payload as the elevating user started it: a payload in
a directory that user owns is theirs to replace before they start it. Installer
packages place the payload in a protected location.

## `uninstall`

Administrator only, under the maintenance lock. The journal advances through
`Disabled`, `Reclaimed`, `Unregistered`, `IpcRemoved`, `GroupRemoved`, `StateRemoved`,
`InstallRemoved`; each step is skipped if already done, so a retry resumes.

1. Stop and disable the service (it holds the singleton lock), then take the lock.
2. **Reclaim:** the ledger must exist. Commit a `PurgeAll` and run
   `reclaim_all(Everything)`. It must leave no open record, candidate, conflict or
   unclosed generation, and no failed sweep; otherwise uninstall stops with the
   service disabled and ownership data kept. Retry `uninstall`, or `resume-service`
   to re-enable the service.
3. Unregister, remove the socket directory (only proven-stale sockets are removed
   first; unknown leftovers make it fail), remove the group (only if its GID matches
   the journal), remove the state directory.
4. Remove the install directory. On Windows the running installed image cannot delete
   itself: it copies itself into the maintenance directory, verifies the copy's hash,
   schedules the copy for deletion at reboot, and starts it as
   `uninstall --wait-parent <pid> --install-id <id>`. That helper waits for the parent
   to exit and finishes the last step. `uninstall --status` reports the phase and the
   helper's outcome; uninstall is complete when the journal is gone. On Windows,
   removal of the install tree refuses (and keeps the journal) while a system driver
   references a kernel bundle in `cores`, or when that cannot be determined.

Without a journal, `uninstall` succeeds only if preflight finds no product resources.

`uninstall --only-owner <tag>` uninstalls only an installation whose journal records
that owner (and the same install id throughout); with no journal or another owner it
removes nothing and succeeds. An installer's rollback uses it so that it never removes
an installation it did not make.

## `reclaim` and `remove-core`

`reclaim` opens the ledger under the singleton lock (plus the maintenance lock in
service mode) and runs `reclaim_all`: scope `Instances`, or `Everything` with
`--purge` (which first commits a `PurgeAll`). It prints the report and fails with
"reclaim incomplete" if anything remains. `--purge` requires `--all`; the scope
otherwise does not depend on `--all`.

`remove-core <version>` runs `ReclaimEngine::reclaim_core` for the kernel's SHA-256,
requires no candidates, conflicts or open core-binary records, clears the selected
default if it pointed at this version, then removes the kernel from the store. In
service mode on Windows removal also refuses while a system driver references the
bundle.

There is no subcommand that adds a kernel to an existing store: kernels come only from
the bundled release table at install time (or a user host's first start).

## `--console-ctrl <pid>`

Hidden. Used only by `etd-proc` to stop a kernel gracefully on Windows: the engine
re-executes the host with this flag, and the process attaches to the kernel's console
and sends one Ctrl-C (`etd_proc::console_ctrl::send_ctrl_c`). It does nothing else
and fails on other platforms.

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
| Maintenance command | `maintenance-command.lock` | blocking | `install`, `upgrade`, `uninstall`, `resume-service`, `reclaim` / `remove-core` in service mode, and every elevated session entry (`run` until it holds the singleton lock, both `reclaim` forms) |

For the service both live in a separate maintenance directory (table below) that
install and uninstall never remove. A user host locks its state directory, and also
the per-user runtime directory when that differs, so two state directories cannot
serve the same user endpoint.

Because the running service holds the singleton lock, `reclaim` and `remove-core` in
service mode refuse until the service is stopped. That makes them the only ledger
writer while they run.

The elevated session host uses the service's maintenance directory and so the same
two locks: at most one privileged host (service or one user's session) runs at a
time. Every privileged entry takes the maintenance lock first, checks inside it, then
takes the singleton lock. A session host releases the maintenance lock once it holds
the singleton lock, so `install` then fails at once on the singleton lock ("host
already running") instead of waiting.

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

Elevated session form (Windows only): everything under
`%ProgramData%\EasyTierDesk.session\<SID>` (`<SID>` from the host's own token):
`state\` (ledger, logs, repair index), `run\`, `cores\` and `profile\`, which
the kernel's and the system workers' profile variables point at. Endpoint
`\\.\pipe\easytier-desk-session-<SID>`; maintenance directory and locks as the
service's. `EasyTierDesk.session` and each `<SID>` root are created with the same
protected descriptor as the service directories (owner SYSTEM or Administrators,
only SYSTEM and Administrators granted). Every start verifies the whole per-user tree:
access control, no reparse point, no file with a second hard link. A directory that
exists but does not conform is refused, never repaired or adopted; the same check
runs before another user's root is read, reclaimed or removed.

Windows machine locations (`%ProgramData%`, `%ProgramFiles%`) are read from HKLM's
64-bit view (the profile list's `ProgramData`, `ProgramFilesDir`), with only
`%SystemDrive%` expanded, to the drive of the Windows directory; no shell API and no
environment is involved. The user host's `%LOCALAPPDATA%` is the Known Folder,
through shell32 loaded from System32 for that call only, and only for an unelevated
token: an elevated process (install, uninstall, reclaim, an elevated `doctor` or
`--mode user` command, the service) is refused before the shell is asked, so no
user-redirectable folder is ever resolved with administrator rights. User form: state is
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

## `run --mode elevated-session`

Windows only (refused elsewhere); the command takes no directory or path option.
Before any directory or lock, the token must be elevated (`TokenElevation`), at
integrity High or above, and not SYSTEM. On Windows every command first restricts the
DLL search path to System32 (`SetDefaultDllDirectories`), and `etd-host.exe` links
with `/DEPENDENTLOADFLAG:0x800`.

1. Take the maintenance lock. Inside it: refuse if the service is registered (in any
   state) or its state directory exists; create the missing protected session
   directories and verify the per-user tree, which must include `profile\` (an
   existing tree is verified whole before anything is created in it); change
   the working directory to the `<SID>` root.
2. Still inside it, take the singleton lock (a running privileged host makes this
   fail as "host already running"), then reconcile machine-wide (below). Then the kernel
   store: on first start the bundled kernels beside the host image are copied into
   `<SID>\cores` and hashed there; when this build's table changed they are merged
   again (no SHA directory is deleted, so kernels open records name stay).
3. Release the maintenance lock and serve as the service does, with the fence, the
   owner-only session pipe, mode `ELEVATED_SESSION` and the kernel's profile variables
   (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `HOMEDRIVE`/`HOMEPATH`) set to
   `<SID>\profile`. Ctrl-C, `ReleaseLease` (stop), the lease grace (30 s with no
   lease holder) or the end of the Windows session stop it. A hidden top-level window
   hears the session end. `WM_QUERYENDSESSION` only marks the end as held
   (`ShutdownBlockReasonCreate`): another program may still veto the logoff, and a
   vetoed one (`WM_ENDSESSION` with FALSE) leaves the host running. `WM_ENDSESSION`
   with TRUE starts the normal shutdown and holds the end until the host has
   released its lock, within the stop's worst case. The trade-off: the cleanup
   starts later, when the end is certain, not when it is first asked.

Machine-wide reconciliation opens every other verified `<SID>` ledger read-only and
refuses (exit 5) if any open record there blocks. The user's own ledger never
blocks; its self-check reclaims it.

- A record that ended with a reboot since never blocks (`UntilReboot` or
  `WithProcess`, written in another boot).
- Instance records block: a normal exit closes them, so open ones are a crashed
  session's leftovers.
- Outside instance scope only two reviewed classes are ignored, because every host
  re-ensures them and none deletes them:
  1. product `Driver` records of the shared `WinDivert` / `wintun` services whose
     observed image path is in the system driver directory or inside a verified
     `<SID>\cores` (a store is removed only after the driver-reference check). Without
     an observation only a `Planned` record (never loaded by that root's kernels) or
     a `Conflict` one (another program's) is ignored;
  2. kernel-binary `WinProgramFirewallRule` records in our firewall group whose
     program path lies inside that root's own `<SID>\cores`.
  Only a program rule never observed rests on its planned name. An observed one needs
  readable evidence of the actual program (the read-back key, the credential's
  program, or a conflict's found detail): every piece present must be readable and
  inside, and at least one must be present; otherwise it blocks.
- Paths count as inside a store only if both are plain local-drive paths (no `..`,
  `.`, doubled separators, streams, device or UNC forms) and, canonicalised (case,
  short names), the store is an ancestor by components and by file identity.
- Everything else blocks: other kinds, names, groups or paths, scopes this build does
  not know, a ledger that cannot be read, and a root with no ledger whose `state\` or
  `run\` is not empty (a host got that far; ownership unknown). `reclaim --all-users`
  (with or without `--purge`) and `install` refuse such a root too, name it and leave
  it untouched; an administrator who has confirmed it holds nothing needed deletes
  it.

Lease holders are only connections whose client process image, read from a handle
opened on the client pid at accept and kept for the connection's life, is the
`etd-ui.exe` beside the host image. That does not authenticate the UI: any program of
the same user at that path counts; protecting the path is the installer's job
(accepted risk, issue #2). The CLI and other clients can operate the host but do not
keep it alive.

Refusals exit with their own codes so the UI can tell them apart:

| Exit code | Meaning |
| --- | --- |
| 3 | The service is registered, or its uninstall is unfinished (state directory left) |
| 4 | A session directory exists but does not conform; left untouched |
| 5 | Other users' sessions left open records; run `reclaim --mode elevated-session --all-users` |
| 6 | The session pipe name is taken by another process |
| 1 | Any other failure, including a token that is not an elevated administrator |

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
2. Take the singleton lock (so no elevated session host runs). Drain the elevated
   sessions: reclaim and purge every verified `%ProgramData%\EasyTierDesk.session\<SID>`
   root, then remove `EasyTierDesk.session`; a candidate, conflict or non-conforming
   directory refuses the install with the report. **Preflight:** refuse if any
   product directory, the group, the unit file or the service registration already
   exists. Install never adopts objects it did not create.
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
"reclaim incomplete" if anything remains. `--all` is the required explicit switch
for `--purge` (`reclaim --all --purge`, as the uninstaller calls it); without
`--purge` it changes nothing, and every instance is reclaimed either way.

`reclaim --mode elevated-session` takes the session entry's locks (maintenance, the
service checks, then the singleton lock) and reclaims the current user's own root.
With `--all-users` it reclaims every verified `<SID>` root; with `--all --purge` it
purges them all and then removes `EasyTierDesk.session` (what an app uninstaller
calls). `--all-users` does not depend on the caller's token: it runs as LocalSystem
(the MSI) or as an elevated administrator, and takes only the shared locks. Before
anything is removed, every `<SID>\cores` passes the same driver-reference check as the
service's uninstall; a reference, or a check that cannot decide, keeps every root
and fails. `--all-users` is refused with any other mode. `remove-core` is not
available for the session mode.

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

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
| Maintenance command | `maintenance-command.lock` | blocking | `install`, `uninstall`, `resume-service`, and `reclaim` / `remove-core` in service mode |

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

Administrator only. `--allow-user` takes numeric SIDs (Windows) or UIDs (Unix); each
becomes an admin allow-list entry.

1. Take the maintenance lock. An existing journal must be in phase `Installing` (an
   interrupted install, which is rolled back first); anything else refuses.
2. Take the singleton lock. **Preflight:** refuse if any product directory, the
   group, the unit file or the service registration already exists. Install never
   adopts objects it did not create.
3. Begin the journal. Every resource is recorded as planned before it is created, so
   a rollback removes only what this installation created.
4. Create the directories and copy the running executable into the install
   directory (registration never points at a download directory).
   - Windows: install dir with a protected DACL (SYSTEM and Administrators full,
     Users read/execute), state dir for SYSTEM and Administrators only, then `run`
     and `cores`.
   - Unix: install 0755, state 0700, run 0700, cores 0755, socket dir 0755; the image
     is copied from `/proc/self/exe` (Linux) or the canonical current executable
     (macOS). A free GID in 60000..65000 is reserved in the journal, then the
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

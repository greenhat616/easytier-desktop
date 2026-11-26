# etd-proc

Host-side library for kernel process lifecycle. It defines the process abstractions the
host core is written against (spawn into a containment, identity that survives PID
reuse, liveness verdicts, verified kill, marker sweep, restart policy) and provides the
only real implementation, a wrapper around the `processkit` crate. It is the only
workspace crate allowed to depend on `processkit`, and one of the three allowed to use
system binding crates (`windows`, `libc`, `nix`).

## Public surface

Frozen (`engine`, `model`, `restart`; see the module docs in `src/lib.rs`):

- `ProcessEngine`: `spawn`, `liveness`, `kill_verified`, `find_marked`.
- `ProcessHandle`: `identity`, `containment`, `take_events` (once), `stop(grace)`,
  `kill`, `wait`.
- Model: `Command`, `ProcessIdentity` (pid + opaque start token + image path),
  `ProcessMarker` (image root + command-line root, for processes without a record),
  `Liveness` (`Same`, `Reused`, `Gone`, `Uncertain`), `Containment` (`JobObject`,
  `CgroupV2`, `ProcessGroup`), `KillOutcome`, `Exit` / `ExitCause`, `ProcessEvent`,
  `ProcessError`. `Liveness` and `KillOutcome` are deliberately exhaustive.
- `Clock`, `RestartPolicy`, `RestartDecision` and the constants `BACKOFF_INITIAL`
  (1 s), `GIVE_UP_WINDOW` (5 min), `GIVE_UP_AFTER` (5).

Not frozen:

- `processkit_engine::ProcessKitEngine`: the engine. `new()`, or
  `with_console_helper(path)` to name the executable that implements `--console-ctrl`.
- `backoff::{BackoffPolicy, SystemClock}`: the restart policy and the real clock.
- `console_ctrl::send_ctrl_c(pid)`: body of the host's hidden `--console-ctrl <pid>`
  entry point (Windows only; an error elsewhere).
- `trusted_system_root()` (Windows): the Windows directory from
  `GetSystemWindowsDirectoryW`, never from `SystemRoot`/`windir`.

## Behaviour

- **Identity.** A start token comes from the OS process start time (on Linux prefixed
  with the boot ID, since start ticks restart at boot). The engine reads the identity
  right after the spawn; if it cannot, or the image differs from the requested
  executable, it kills the containment, confirms it empty and fails the spawn
  (`ExitedBeforeIdentity` is an abnormal exit the host feeds to its restart policy).
- **Liveness.** No process: `Gone`. Different start token: `Reused`. Same token and
  same canonical image: `Same`. Anything that cannot be read: `Uncertain`. A missing
  `/proc` entry is cross-checked with `kill(pid, 0)` before saying `Gone`.
  `Uncertain` is never treated as dead; a quarantined containment always answers
  `Uncertain`.
- **Kill.** Never by PID alone. A handle the engine still holds is killed through its
  own containment. An orphan (no live handle) is killed only after re-verifying the
  identity: on Windows and Linux through a process handle / pidfd opened before the
  checks, only if it runs as the host's user and has no descendant outside
  containment (the one exception is the system `conhost.exe` of that very process,
  checked by image, parent and creation time). On macOS, which has no race-free
  process pin, the orphan must first be found with `find_marked`; all marker
  criteria are re-checked immediately before `SIGKILL`, leaving a narrow
  verify-to-signal window on that platform only. Other platforms answer `Uncertain`.
- **Marker sweep.** `find_marked` matches processes of the host's user whose image is
  under `exe_root` and whose arguments reference a path under `cmdline_root`. A live
  candidate whose fields cannot be observed is an error, not a skip. It walks
  processes, not threads (on Linux a thread is never a candidate of its own); a
  zombie is skipped unless it is a thread-group leader whose other threads still run.
- **Exit and cleanup.** Each handle emits output chunks (at most 16 KiB each; dropped
  with a warning if the consumer lags) and exactly one terminal event: `Exited` or
  `CleanupUncertain`. After any root exit the containment is killed and must be
  observed empty within 5 s; otherwise the event is `CleanupUncertain`, the
  containment is kept in a process-wide tombstone, and a later `kill_verified` on the
  same identity retries the confirmation. `ExitCause` is `Exited` (the process ended
  on its own; the only cause `Exit::abnormal` counts), `Stopped` or `Killed`.
- **Graceful stop.** Unix: `SIGTERM` to the containment, tree kill after `grace`.
  Windows: the engine re-executes the host as `--console-ctrl <pid>` (2 s timeout,
  null stdio). The helper attaches to the kernel's hidden console, refuses unless the
  console holds exactly the helper and the target, ignores Ctrl-C itself and sends
  one `CTRL_C_EVENT`. Never call `send_ctrl_c` inside the ordinary host process.
- **Restart policy** (`BackoffPolicy`). Non-abnormal exits: `Stay`. Abnormal exits in
  a rolling 5-minute window: restart after 1 s, 2 s, 4 s, 8 s; the fifth gives up
  ("five abnormal exits within five minutes"). Giving up is sticky until `reset()`,
  which the host calls on a manual retry.

## Platform notes

- **Windows:** every child is spawned with `CREATE_NO_WINDOW` (processkit's
  `create_no_window()` for kernels, `creation_flags(0x0800_0000)` for the helper);
  a test in `xtask/src/spawn_flags.rs` checks this rule across `crates/`.
  Containment is a job object.
- **Child environment:** every child starts from an empty environment. The engine
  owns `PATH` and, on Windows, `SystemRoot`/`windir`; a caller value for these is
  dropped with a warning (matched case-insensitively on Windows). Unix `PATH` is
  `/usr/bin:/bin:/usr/sbin:/sbin` (upstream calls `ip`, `route`, `ifconfig` by bare
  name). Windows `PATH` is `System32`, the Windows directory, `System32\Wbem` and
  `System32\WindowsPowerShell\v1.0`, all under `trusted_system_root()`; if that
  directory cannot be read the spawn fails.
- **Parent death:** kernels are started with processkit's `kill_on_parent_death()`.
  On Linux the parent-death signal is bound to the thread that forks, so each spawn
  runs on its own long-lived `etd-process` thread that owns the child for its whole
  life. The tests assert that killing the host kills the kernel on Windows and Linux;
  on macOS the kernel survives and the next host start finds it by marker sweep.
- **Linux:** containment is a cgroup v2 subtree when available, else a process group;
  liveness pins use `pidfd_open`.
- **macOS:** containment is a process group.

## Dependencies and boundaries

- **Used by:** `etd-host-core`, `etd-host`, `etd-core-api`, `etd-core-easytier`,
  `etd-testkit`.
- **Depends on:** no workspace crate (`etd-testkit` as a dev-dependency only).
- **Must not:** be bypassed; no other crate may depend on `processkit`.

## Testing

```sh
cargo nextest run -p etd-proc
cargo nextest run -p etd-testkit --test real_process --test console_ctrl
```

The crate's own tests are unit tests: backoff windows, the child environment rules,
minimal-process filters, the console-host exception and cleanup/quarantine audits.
Real-process scenarios (graceful stop, fast exit, tree kill on timeout, PID reuse,
orphan pinning, parent death) and the Windows Ctrl-C helper run against the
`fake-core` binary in `etd-testkit`; they are unprivileged. See
[../etd-testkit/README.md](../etd-testkit/README.md) and
[docs/testing/README.md](../../docs/testing/README.md).

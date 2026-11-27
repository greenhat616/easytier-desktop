//! ProcessKit adapter. All backend types remain private to this module.
#[cfg(windows)]
use crate::console_host;
use crate::{identity, parent_death, *};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock, Weak},
    task::{Context, Poll},
    time::Duration,
};
use sysinfo::{ProcessStatus, ProcessesToUpdate};
use tokio::{
    io::AsyncWrite,
    sync::{mpsc, oneshot, watch},
};

/// Stateless facade; live containment registry is shared by facade instances.
#[derive(Default, Clone)]
pub struct ProcessKitEngine {
    console_helper: Option<PathBuf>,
    /// Appended to every launch's own environment (see [`Self::with_env`]).
    extra_env: Vec<(OsString, OsString)>,
}

impl ProcessKitEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the re-executed host for ordinary process integration tests.
    /// The executable must implement the same --console-ctrl entry point.
    pub fn with_console_helper(executable: PathBuf) -> Self {
        Self {
            console_helper: Some(executable),
            extra_env: Vec::new(),
        }
    }

    /// Variables the composition root adds to every kernel launch (the
    /// elevated session host's profile variables). They join the launch's
    /// own extra environment; engine-owned variables still win.
    pub fn with_env(mut self, env: Vec<(OsString, OsString)>) -> Self {
        self.extra_env = env;
        self
    }
}

#[derive(Clone)]
enum RegistryEntry {
    Live(Weak<Live>),
    // Keep the actual containment alive until a later verified cleanup.
    // Across host restart the durable generation ledger owns quarantine.
    Quarantined(Arc<processkit::ProcessGroup>),
}
type Registry = Mutex<HashMap<ProcessIdentity, RegistryEntry>>;
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
fn marker_registry() -> &'static Mutex<HashMap<ProcessIdentity, ProcessMarker>> {
    static MARKERS: OnceLock<Mutex<HashMap<ProcessIdentity, ProcessMarker>>> = OnceLock::new();
    MARKERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn registry_entry(id: &ProcessIdentity) -> Option<RegistryEntry> {
    registry().lock().unwrap().get(id).cloned()
}

async fn retry_quarantine(
    id: ProcessIdentity,
    group: Arc<processkit::ProcessGroup>,
) -> Result<KillOutcome, ProcessError> {
    let proof_id = id.clone();
    let proof_group = group.clone();
    let confirmed = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok::<_, std::io::Error>(
            runtime.block_on(confirm_empty(&proof_group)).is_ok()
                && matches!(liveness(&proof_id), Liveness::Gone | Liveness::Reused),
        )
    })
    .await
    .map_err(|e| ProcessError::CleanupUncertain(e.to_string()))??;
    if !confirmed {
        return Ok(KillOutcome::Uncertain);
    }
    let mut registry = registry().lock().unwrap();
    if matches!(registry.get(&id), Some(RegistryEntry::Quarantined(current)) if Arc::ptr_eq(current, &group))
    {
        registry.remove(&id);
    }
    Ok(KillOutcome::Gone)
}
struct Live {
    requests: mpsc::Sender<Request>,
    terminal: watch::Receiver<Option<Terminal>>,
}
type Terminal = Result<Exit, String>;
struct Request {
    grace: Option<Duration>,
    reply: oneshot::Sender<Result<Exit, ProcessError>>,
}
impl Live {
    async fn wait(&self) -> Exit {
        let mut rx = self.terminal.clone();
        if let Ok(terminal) = rx.wait_for(Option::is_some).await
            && let Some(Ok(exit)) = &*terminal
        {
            return exit.clone();
        }
        // Interrupted worker is not proof of death. The frozen wait API
        // cannot represent an error; never fabricate an exit.
        std::future::pending().await
    }
    async fn request(&self, grace: Option<Duration>) -> Result<Exit, ProcessError> {
        if let Some(terminal) = self.terminal.borrow().clone() {
            return terminal.map_err(ProcessError::CleanupUncertain);
        }
        let (reply, response) = oneshot::channel();
        if self.requests.send(Request { grace, reply }).await.is_ok()
            && let Ok(result) = response.await
        {
            return result;
        }
        let mut rx = self.terminal.clone();
        let terminal = rx.wait_for(Option::is_some).await.map_err(|_| {
            ProcessError::CleanupUncertain("worker ended without confirmed cleanup".into())
        })?;
        terminal
            .clone()
            .unwrap()
            .map_err(ProcessError::CleanupUncertain)
    }
}
struct Handle {
    id: ProcessIdentity,
    containment: Containment,
    live: Arc<Live>,
    events: Option<mpsc::Receiver<ProcessEvent>>,
    _cancel: oneshot::Sender<()>,
}
#[async_trait]
impl ProcessHandle for Handle {
    fn identity(&self) -> &ProcessIdentity {
        &self.id
    }
    fn containment(&self) -> Containment {
        self.containment
    }
    fn take_events(&mut self) -> Option<mpsc::Receiver<ProcessEvent>> {
        self.events.take()
    }
    async fn stop(&self, grace: Duration) -> Result<Exit, ProcessError> {
        self.live.request(Some(grace)).await
    }
    async fn kill(&self) -> Result<Exit, ProcessError> {
        self.live.request(None).await
    }
    async fn wait(&self) -> Exit {
        self.live.wait().await
    }
}

/// Start-token checks never degrade to PID-only identity.
fn read_token(pid: u32) -> Result<Option<String>, ProcessError> {
    #[cfg(windows)]
    let _pin = match identity::Pin::open(pid, false) {
        Ok(pin) if pin.gone() => return Ok(None),
        Ok(pin) => Some(pin),
        Err(_) => None, // process_info distinguishes access denied from no process
    };
    let info = match processkit::process_info(pid) {
        Ok(info) => info,
        Err(error) => {
            // The proc snapshot can race a reap (e.g. ENOENT). An independent
            // negative existence observation establishes exit; other errors
            // remain unobservable rather than being silently skipped.
            #[cfg(unix)]
            if identity::pid_absent(pid).unwrap_or(false) {
                return Ok(None);
            }
            #[cfg(windows)]
            if _pin.as_ref().is_some_and(|pin| pin.gone()) {
                return Ok(None);
            }
            return Err(ProcessError::Enumeration(error.to_string()));
        }
    };
    match info {
        None => {
            // A hidepid mount can make /proc look absent even when a PID
            // exists. Consult a separate existence oracle before saying gone.
            #[cfg(target_os = "linux")]
            if !identity::pid_absent(pid)? {
                return Err(ProcessError::Enumeration(
                    "live PID is not visible in /proc".into(),
                ));
            }
            Ok(None)
        }
        Some(info) => Ok(Some(identity::token(info.start_time().ok_or_else(
            || ProcessError::Enumeration("missing start token".into()),
        )?)?)),
    }
}
fn inspect(pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
    let Some(start_token) = read_token(pid)? else {
        return Ok(None);
    };
    let pids = [identity::pid(pid)];
    let snapshot = identity::snapshot(ProcessesToUpdate::Some(&pids))?;
    let process = snapshot
        .process(pids[0])
        .ok_or_else(|| ProcessError::Enumeration("process disappeared during inspection".into()))?;
    if read_token(pid)?.as_ref() != Some(&start_token) {
        return Err(ProcessError::Enumeration(
            "process changed during inspection".into(),
        ));
    }
    if matches!(
        process.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        return Ok(None);
    }
    let exe = identity::normalized(
        process
            .exe()
            .ok_or_else(|| ProcessError::Enumeration("missing image path".into()))?,
    )?;
    Ok(Some(ProcessIdentity {
        pid,
        start_token,
        exe,
    }))
}
fn liveness(id: &ProcessIdentity) -> Liveness {
    match read_token(id.pid) {
        Ok(None) => return Liveness::Gone,
        Ok(Some(token)) if token != id.start_token => return Liveness::Reused,
        Ok(Some(_)) => {}
        Err(_) => return Liveness::Uncertain,
    }
    match inspect(id.pid) {
        Ok(None) => Liveness::Gone,
        Ok(Some(current)) if current.start_token != id.start_token => Liveness::Reused,
        Ok(Some(current)) if identity::normalized(&id.exe).is_ok_and(|exe| exe == current.exe) => {
            Liveness::Same
        }
        _ => Liveness::Uncertain,
    }
}

/// For a candidate, a missing criterion is unknown, not a negative match.
/// A positive mismatch in any independently observed criterion excludes it.
fn match_criteria(
    owner: Option<bool>,
    image: Option<bool>,
    argv: Option<bool>,
) -> Result<bool, ProcessError> {
    let fields = [owner, image, argv];
    if fields.contains(&Some(false)) {
        return Ok(false);
    }
    if fields.contains(&None) {
        return Err(ProcessError::Enumeration(
            "candidate marker fields are unobservable".into(),
        ));
    }
    Ok(true)
}

fn candidate_matches(
    process: &sysinfo::Process,
    own: &sysinfo::Uid,
    marker: &ProcessMarker,
) -> Result<bool, ProcessError> {
    if matches!(
        process.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        match identity::leader_threads(process.pid().as_u32()) {
            identity::LeaderThreads::Alone => return Ok(false),
            // Verified like any live candidate (its image is unreadable now).
            identity::LeaderThreads::Siblings => {}
            identity::LeaderThreads::Unknown => {
                return Err(ProcessError::Enumeration(
                    "zombie process: live threads cannot be ruled out".into(),
                ));
            }
        }
    }
    let owner = process.user_id().map(|user| user == own);
    #[cfg(windows)]
    let owner =
        owner.or_else(|| identity::query_access_denied(process.pid().as_u32()).then_some(false));
    match_criteria(
        owner,
        process.exe().and_then(|exe| {
            let exe = identity::normalized(exe).ok()?;
            let root = identity::normalized(&marker.exe_root).ok()?;
            Some(exe.starts_with(root))
        }),
        (!process.cmd().is_empty()).then(|| {
            process
                .cmd()
                .iter()
                .skip(1)
                .any(|arg| identity::under(Path::new(arg), &marker.cmdline_root))
        }),
    )
}
fn marked(marker: &ProcessMarker) -> Result<Vec<ProcessIdentity>, ProcessError> {
    // Listed before the snapshot: a PID missing from the later snapshot has
    // either exited meanwhile or was dropped by sysinfo as uninspectable.
    #[cfg(target_os = "macos")]
    let listed = identity::all_pids()
        .map_err(|e| ProcessError::Enumeration(format!("kernel PID list: {e}")))?;
    let snapshot = identity::snapshot(ProcessesToUpdate::All)?;
    let own = snapshot
        .process(identity::pid(std::process::id()))
        .and_then(|p| p.user_id())
        .ok_or_else(|| ProcessError::Enumeration("cannot determine host user".into()))?;
    let mut found = Vec::new();
    for process in snapshot.processes().values() {
        found.extend(marked_candidate(process, own, marker)?);
    }
    #[cfg(target_os = "macos")]
    for pid in listed {
        // PID 0 is kernel_task (see identity::minimal_process).
        if pid != 0 && snapshot.process(identity::pid(pid)).is_none() {
            found.extend(unlisted_candidate(pid, own, marker)?);
        }
    }
    found.sort_by_key(|id| id.pid);
    Ok(found)
}

/// Verify one snapshot entry. `Ok(None)` only for a positive mismatch or a
/// confirmed exit; an unobservable live candidate is an error, never a skip.
fn marked_candidate(
    process: &sysinfo::Process,
    own: &sysinfo::Uid,
    marker: &ProcessMarker,
) -> Result<Option<ProcessIdentity>, ProcessError> {
    // Both passes use the same tri-state predicate. A positive mismatch
    // is a negative candidate; a missing field is not. Kernel-defined
    // minimal processes are exempt because they cannot execute our core.
    if identity::minimal_process(process)
        || matches!(candidate_matches(process, own, marker), Ok(false))
    {
        return Ok(None);
    }
    let pid = process.pid().as_u32();
    let candidate_error = |error: ProcessError| {
        ProcessError::Enumeration(format!(
            "marker candidate PID {pid} ({:?}): {error}",
            process.name()
        ))
    };
    // On platforms with an object/descriptor handle, keep that object
    // pinned throughout candidate verification (including owner & argv).
    #[cfg(any(windows, target_os = "linux"))]
    let pin = match identity::Pin::open(pid, false) {
        Ok(pin) => pin,
        Err(error) => {
            if read_token(pid).map_err(candidate_error)?.is_none() {
                return Ok(None);
            }
            return Err(candidate_error(ProcessError::Enumeration(
                error.to_string(),
            )));
        }
    };
    let Some(token) = read_token(pid).map_err(candidate_error)? else {
        return Ok(None);
    };
    let pids = [identity::pid(pid)];
    let fresh = identity::snapshot(ProcessesToUpdate::Some(&pids))?;
    let Some(p) = fresh.process(pids[0]) else {
        if read_token(pid).map_err(candidate_error)?.is_none() {
            return Ok(None);
        }
        return Err(ProcessError::Enumeration(
            "candidate disappeared from snapshot but is not confirmed exited".into(),
        ));
    };
    match candidate_matches(p, own, marker) {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) => {
            if read_token(pid).map_err(candidate_error)?.is_none() {
                return Ok(None);
            }
            return Err(candidate_error(error));
        }
    }
    let current = match inspect(pid) {
        Ok(current) => current,
        Err(error) => {
            if read_token(pid)?.is_none() {
                return Ok(None);
            }
            return Err(error);
        }
    };
    let Some(current) = current else {
        return Ok(None);
    };
    if current.start_token != token || !identity::under(&current.exe, &marker.exe_root) {
        return Err(ProcessError::Enumeration(
            "candidate identity changed during marker sweep".into(),
        ));
    }
    #[cfg(any(windows, target_os = "linux"))]
    if pin.gone() {
        return Ok(None);
    }
    Ok(Some(current))
}

/// A kernel-listed PID that the full sysinfo snapshot omitted (it drops a
/// PID whose image and argv are both unreadable: a zombie, or an exiting or
/// exec'ing process). Absence from the snapshot is not absence of the
/// process: only exit, zombie state or another owner excludes it; a live
/// same-user process is re-observed and verified like any candidate.
#[cfg(target_os = "macos")]
fn unlisted_candidate(
    pid: u32,
    own: &sysinfo::Uid,
    marker: &ProcessMarker,
) -> Result<Option<ProcessIdentity>, ProcessError> {
    const ATTEMPTS: usize = 20;
    // Name the process so H1's notice tells the user what blocks the sweep.
    let mut name = String::from("name unavailable");
    let mut reason = String::from("not observed");
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        match identity::bsd_state(pid) {
            Ok(None) => return Ok(None),
            Ok(Some(state)) if state.zombie || state.ruid != **own => return Ok(None),
            Ok(Some(state)) => name = state.name,
            Err(error) => {
                reason = error.to_string();
                continue;
            }
        }
        let pids = [identity::pid(pid)];
        let fresh = identity::snapshot(ProcessesToUpdate::Some(&pids))?;
        if let Some(process) = fresh.process(pids[0]) {
            return marked_candidate(process, own, marker);
        }
        reason = "live same-user process whose image and argv stay unreadable".into();
    }
    Err(ProcessError::Enumeration(format!(
        "PID {pid} ({name}) is missing from the process snapshot: {reason}"
    )))
}
/// The children of a process that is about to be, or has just been, killed.
#[derive(Default)]
struct Children {
    /// Possible descendants outside any verified containment.
    blocking: Vec<u32>,
    /// The target's own console host (see `console_host`), pinned.
    #[cfg(windows)]
    console_hosts: Vec<(u32, identity::Pin)>,
}

#[cfg(windows)]
fn start_time_of(token: &str) -> Option<u64> {
    token.parse().ok()
}

/// Whether any live process is a child of `parent`; `None` when a candidate
/// cannot be read.
#[cfg(windows)]
fn has_children(snapshot: &sysinfo::System, parent: u32, parent_created: u64) -> Option<bool> {
    for p in snapshot.processes().values() {
        if p.parent() != Some(identity::pid(parent))
            || matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead)
        {
            continue;
        }
        match read_token(p.pid().as_u32()) {
            Ok(None) => {}
            // An older process names an earlier holder of the PID.
            Ok(Some(token)) => {
                if start_time_of(&token)? >= parent_created {
                    return Some(true);
                }
            }
            Err(_) => return None,
        }
    }
    Some(false)
}

/// Pins `pid` and returns the pin if it is the console host of `id`. The caller
/// holds a pin on `id`. The child's facts are read while it is pinned.
#[cfg(windows)]
fn pin_console_host(
    snapshot: &sysinfo::System,
    id: &ProcessIdentity,
    parent_created: u64,
    pid: u32,
    token: &str,
) -> Option<identity::Pin> {
    let system_image = console_host::system_image().ok()?;
    let pin = identity::Pin::open(pid, true).ok()?;
    if read_token(pid).ok()??.as_str() != token {
        return None;
    }
    let created = start_time_of(token);
    let observed = console_host::Observed {
        image: pin.image().ok().and_then(|image| image.canonicalize().ok()),
        parent: identity::snapshot(ProcessesToUpdate::Some(&[identity::pid(pid)]))
            .ok()?
            .process(identity::pid(pid))
            .and_then(|p| p.parent())
            .map(|parent| parent.as_u32()),
        created,
        has_children: created.and_then(|created| has_children(snapshot, pid, created)),
    };
    console_host::is_console_host_of(&observed, id.pid, parent_created, &system_image)
        .then_some(pin)
}

/// A console host normally exits with its client; this does not wait for that.
#[cfg(windows)]
fn end_console_hosts(parent: u32, hosts: &[(u32, identity::Pin)]) {
    for (pid, pin) in hosts {
        if pin.gone() {
            continue;
        }
        match pin.stop() {
            Ok(()) => tracing::info!(parent, pid, "ended the console host of a killed orphan"),
            Err(error) if pin.gone() => {
                tracing::debug!(parent, pid, %error, "console host had already exited");
            }
            Err(error) => {
                tracing::warn!(parent, pid, %error, "could not end a killed orphan's console host");
            }
        }
    }
}

/// A stale Windows PPID is not ancestry: a real child cannot predate
/// its parent. Unreadable candidate metadata is an uncertainty, not absence.
fn possible_children(
    snapshot: &sysinfo::System,
    id: &ProcessIdentity,
) -> Result<Children, ProcessError> {
    let mut children = Children::default();
    for p in snapshot.processes().values() {
        if p.parent() != Some(identity::pid(id.pid))
            || matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead)
        {
            continue;
        }
        let pid = p.pid().as_u32();
        let Some(token) = read_token(pid)? else {
            continue;
        };
        #[cfg(windows)]
        {
            let child_time: u64 = token
                .parse()
                .map_err(|_| ProcessError::Enumeration("invalid child creation time".into()))?;
            let parent_time: u64 = id
                .start_token
                .parse()
                .map_err(|_| ProcessError::Enumeration("invalid parent creation time".into()))?;
            if child_time < parent_time {
                continue;
            }
            if let Some(pin) = pin_console_host(snapshot, id, parent_time, pid, &token) {
                children.console_hosts.push((pid, pin));
                continue;
            }
            // It may have exited while it was being examined.
            if read_token(pid)?.is_none() {
                continue;
            }
        }
        #[cfg(not(windows))]
        let _ = token;
        children.blocking.push(pid);
    }
    Ok(children)
}

fn verify_marked_identity(
    id: &ProcessIdentity,
    marker: &ProcessMarker,
) -> Result<bool, ProcessError> {
    let all = identity::snapshot(ProcessesToUpdate::Some(&[
        identity::pid(id.pid),
        identity::pid(std::process::id()),
    ]))?;
    let own = all
        .process(identity::pid(std::process::id()))
        .and_then(|p| p.user_id())
        .ok_or_else(|| ProcessError::Enumeration("cannot determine host user".into()))?;
    let p = all
        .process(identity::pid(id.pid))
        .ok_or_else(|| ProcessError::Enumeration("candidate missing from snapshot".into()))?;
    Ok(candidate_matches(p, own, marker)? && liveness(id) == Liveness::Same)
}

enum OrphanDomain {
    #[cfg(unix)]
    ProcessGroup(i32),
    #[cfg(target_os = "linux")]
    Cgroup(PathBuf),
}

#[cfg(target_os = "linux")]
fn linux_orphan_domain(pid: u32) -> io::Result<OrphanDomain> {
    if let Some(path) = identity::cgroup_v2(pid)?
        && let Some(domain) = identity::processkit_cgroup(&path)
    {
        return Ok(OrphanDomain::Cgroup(domain));
    }
    Ok(OrphanDomain::ProcessGroup(identity::process_group(pid)?))
}

/// Post-termination enumeration. A Unix descendant can be reparented before
/// this snapshot; a newly observed same-user process in the old group (or
/// matching the marker) is possible residual work, not proof of absence.
fn orphan_recheck(
    before: &sysinfo::System,
    id: &ProcessIdentity,
    marker: Option<&ProcessMarker>,
    domain: Option<OrphanDomain>,
) -> Result<KillOutcome, ProcessError> {
    let after = identity::snapshot(ProcessesToUpdate::All)?;
    if !possible_children(&after, id)?.blocking.is_empty() {
        return Ok(KillOutcome::Uncertain);
    }
    #[cfg(unix)]
    {
        let uid = before
            .process(identity::pid(id.pid))
            .and_then(|p| p.user_id())
            .ok_or_else(|| ProcessError::Enumeration("missing orphan owner".into()))?;
        for p in after.processes().values() {
            if p.pid() == identity::pid(id.pid)
                || matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead)
            {
                continue;
            }
            let same_marker = marker.is_some_and(|m| {
                p.user_id().is_none_or(|owner| owner == uid)
                    && p.exe().is_some_and(|exe| identity::under(exe, &m.exe_root))
                    && p.cmd()
                        .iter()
                        .skip(1)
                        .any(|arg| identity::under(Path::new(arg), &m.cmdline_root))
            });
            let existed = before
                .process(p.pid())
                .is_some_and(|old| old.start_time() == p.start_time());
            #[cfg(target_os = "linux")]
            if let Some(OrphanDomain::Cgroup(root)) = &domain {
                // The old cgroup is the containment credential, not the
                // inherited UI/host pgid. Check every live member including
                // already-reparented descendants from before the snapshot.
                if identity::minimal_process(p) {
                    continue;
                }
                match identity::cgroup_v2(p.pid().as_u32()) {
                    Ok(Some(path)) if path.starts_with(root) => return Ok(KillOutcome::Uncertain),
                    Ok(_) => {}
                    Err(_) if read_token(p.pid().as_u32())?.is_none() => continue,
                    Err(_) => return Ok(KillOutcome::Uncertain),
                }
                if !existed && same_marker {
                    return Ok(KillOutcome::Uncertain);
                }
                continue;
            }
            if existed {
                continue;
            }
            if same_marker {
                return Ok(KillOutcome::Uncertain);
            }
            if p.user_id().is_some_and(|owner| owner != uid) {
                continue;
            }
            let pid = p.pid().as_u32();
            // No signals are sent during this independent observation.
            let same_group = match identity::process_group(pid) {
                Ok(g) => {
                    matches!(&domain, Some(OrphanDomain::ProcessGroup(expected)) if g == *expected)
                }
                Err(_) => {
                    if read_token(pid)?.is_none() {
                        continue;
                    }
                    return Ok(KillOutcome::Uncertain);
                }
            };
            if same_group {
                return Ok(KillOutcome::Uncertain);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (before, marker, domain);
    Ok(KillOutcome::Killed)
}

/// Orphan: pin before verification and signal only via that pin on
/// Windows/Linux. A disappeared/reused root without its recorded containment
/// is not proof that the previous tree was drained.
#[cfg(any(windows, target_os = "linux"))]
fn kill_orphan(
    id: &ProcessIdentity,
    marker: Option<&ProcessMarker>,
) -> Result<KillOutcome, ProcessError> {
    if id.pid == std::process::id() || id.pid == 0 {
        return Ok(KillOutcome::Uncertain);
    }
    let pin = match identity::Pin::open(id.pid, true) {
        Ok(pin) => pin,
        Err(_) => return Ok(KillOutcome::Uncertain),
    };
    if liveness(id) != Liveness::Same || pin.gone() {
        return Ok(KillOutcome::Uncertain);
    }
    if let Some(marker) = marker
        && !verify_marked_identity(id, marker)?
    {
        return Ok(KillOutcome::Uncertain);
    }
    let before = identity::snapshot(ProcessesToUpdate::All)?;
    let owner = before
        .process(identity::pid(id.pid))
        .and_then(|p| p.user_id());
    let host = before
        .process(identity::pid(std::process::id()))
        .and_then(|p| p.user_id());
    if owner.is_none() || owner != host {
        return Ok(KillOutcome::Uncertain);
    }
    let children = possible_children(&before, id)?;
    if !children.blocking.is_empty() {
        tracing::warn!(
            parent = id.pid,
            children = ?children.blocking,
            "orphan descendants lack verified containment"
        );
        return Ok(KillOutcome::Uncertain);
    }
    #[cfg(target_os = "linux")]
    let domain = Some(linux_orphan_domain(id.pid)?);
    #[cfg(windows)]
    let domain = None;
    if pin.gone() || liveness(id) != Liveness::Same {
        return Ok(KillOutcome::Uncertain);
    }
    if let Some(marker) = marker
        && !verify_marked_identity(id, marker)?
    {
        return Ok(KillOutcome::Uncertain);
    }
    if let Err(e) = pin.stop() {
        return match liveness(id) {
            Liveness::Same => Err(ProcessError::Signal(e.to_string())),
            _ => Ok(KillOutcome::Uncertain),
        };
    }
    for _ in 0..100 {
        if pin.gone() {
            let outcome = orphan_recheck(&before, id, marker, domain)?;
            #[cfg(windows)]
            if outcome == KillOutcome::Killed {
                end_console_hosts(id.pid, &children.console_hosts);
            }
            return Ok(outcome);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(KillOutcome::Uncertain)
}

/// Human ruling: macOS lacks a race-free process pin. Verify all marker
/// criteria immediately before signaling; the narrow verify-to-signal TOCTOU
/// remains on this platform only. Never signal a foreign process group.
#[cfg(target_os = "macos")]
fn kill_orphan(
    id: &ProcessIdentity,
    marker: Option<&ProcessMarker>,
) -> Result<KillOutcome, ProcessError> {
    let Some(marker) = marker else {
        return Ok(KillOutcome::Uncertain);
    };
    if id.pid == std::process::id() || id.pid == 0 || liveness(id) != Liveness::Same {
        return Ok(KillOutcome::Uncertain);
    }
    let before = identity::snapshot(ProcessesToUpdate::All)?;
    let group = identity::process_group(id.pid)?;
    let own_group = group == i32::try_from(id.pid).map_err(io::Error::other)?;
    let children = possible_children(&before, id)?.blocking;
    if !children.is_empty() {
        if !own_group {
            return Ok(KillOutcome::Uncertain);
        }
        for child in children {
            if identity::process_group(child).ok() != Some(group) {
                return Ok(KillOutcome::Uncertain);
            }
        }
    }
    // No await or enumeration between final identity observation and signal.
    if !verify_marked_identity(id, marker)? {
        return Ok(KillOutcome::Uncertain);
    }
    if identity::process_group(id.pid)? != group
        || read_token(id.pid)?.as_ref() != Some(&id.start_token)
    {
        return Ok(KillOutcome::Uncertain);
    }
    identity::signal_verified_orphan(id.pid, own_group)?;
    for _ in 0..100 {
        if matches!(liveness(id), Liveness::Gone | Liveness::Reused)
            && (!own_group || identity::group_absent(group)?)
        {
            return orphan_recheck(
                &before,
                id,
                Some(marker),
                Some(OrphanDomain::ProcessGroup(group)),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(KillOutcome::Uncertain)
}
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn kill_orphan(
    _: &ProcessIdentity,
    _: Option<&ProcessMarker>,
) -> Result<KillOutcome, ProcessError> {
    Ok(KillOutcome::Uncertain)
}
#[async_trait]
impl ProcessEngine for ProcessKitEngine {
    async fn spawn(&self, mut cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        cmd.env.extend(self.extra_env.iter().cloned());
        let (ready, receiver) = oneshot::channel();
        let helper = self.console_helper.clone();
        parent_death::worker(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(run(cmd, ready, helper)),
                Err(error) => {
                    let _ = ready.send(Err(ProcessError::Io(error)));
                }
            }
        })?;
        let handle = receiver
            .await
            .map_err(|_| ProcessError::Signal("process worker failed during spawn".into()))??;
        Ok(Box::new(handle))
    }
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        if matches!(registry_entry(id), Some(RegistryEntry::Quarantined(_))) {
            return Liveness::Uncertain;
        }
        let query = id.clone();
        let result = tokio::task::spawn_blocking(move || liveness(&query))
            .await
            .unwrap_or(Liveness::Uncertain);
        let live = match registry_entry(id) {
            Some(RegistryEntry::Quarantined(_)) => return Liveness::Uncertain,
            Some(RegistryEntry::Live(live)) => live.upgrade(),
            _ => None,
        };
        if let Some(live) = live {
            match &*live.terminal.borrow() {
                Some(Ok(_)) => {}
                Some(Err(_)) => return Liveness::Uncertain,
                None if result != Liveness::Same => return Liveness::Uncertain,
                None => {}
            }
        }
        result
    }
    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        let live = match registry_entry(id) {
            Some(RegistryEntry::Quarantined(group)) => {
                return retry_quarantine(id.clone(), group).await;
            }
            Some(RegistryEntry::Live(live)) => live.upgrade(),
            None => None,
        };
        if let Some(live) = live {
            // The exact registered identity owns a private containment;
            // root liveness alone cannot prove the group is drained.
            return match live.request(None).await {
                Ok(exit) if exit.cause == ExitCause::Exited => Ok(KillOutcome::Gone),
                Ok(_) => Ok(KillOutcome::Killed),
                Err(ProcessError::CleanupUncertain(_)) => Ok(KillOutcome::Uncertain),
                Err(error) => Err(error),
            };
        }
        let marker = marker_registry().lock().unwrap().get(id).cloned();
        let id = id.clone();
        tokio::task::spawn_blocking(move || kill_orphan(&id, marker.as_ref()))
            .await
            .map_err(|e| ProcessError::Signal(e.to_string()))?
    }
    async fn find_marked(
        &self,
        marker: &ProcessMarker,
    ) -> Result<Vec<ProcessIdentity>, ProcessError> {
        let query = marker.clone();
        let found = tokio::task::spawn_blocking(move || marked(&query))
            .await
            .map_err(|e| ProcessError::Enumeration(e.to_string()))??;
        let mut bindings = marker_registry().lock().unwrap();
        bindings.retain(|_, existing| existing != marker);
        for id in &found {
            bindings.insert(id.clone(), marker.clone());
        }
        Ok(found)
    }
}

/// Bounded best-effort log stream. Reserve the terminal event slot; a slow
/// log consumer must not stall kernel execution or exit observation.
struct EventWriter {
    tx: mpsc::Sender<ProcessEvent>,
    stderr: bool,
    dropped: bool,
}
impl AsyncWrite for EventWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = bytes.len().min(16 * 1024);
        let event = if self.stderr {
            ProcessEvent::Stderr(bytes[..n].to_vec())
        } else {
            ProcessEvent::Stdout(bytes[..n].to_vec())
        };
        if self.tx.try_send(event).is_err() && !self.dropped {
            self.dropped = true;
            tracing::warn!("process log consumer lagged; dropping output chunks");
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn containment(group: &processkit::ProcessGroup) -> Result<Containment, ProcessError> {
    match group.mechanism() {
        processkit::Mechanism::JobObject => Ok(Containment::JobObject),
        processkit::Mechanism::CgroupV2 => Ok(Containment::CgroupV2),
        processkit::Mechanism::ProcessGroup => Ok(Containment::ProcessGroup),
        _ => Err(ProcessError::Containment(
            "unsupported containment mechanism".into(),
        )),
    }
}

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Signal success is not an empty-containment observation. Reap the root
/// before using this bounded confirmation (process-group leaders may be
/// zombies until waited). Never publish Exited on a failed membership probe.
async fn confirm_empty(group: &processkit::ProcessGroup) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
    loop {
        let result = group.kill_all().and_then(|()| group.members());
        let reason = match result {
            Ok(members) if members.is_empty() => return Ok(()),
            Ok(members) => format!("containment still has {} tracked members", members.len()),
            Err(error) => error.to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(reason);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn rollback_started(
    group: &processkit::ProcessGroup,
    running: processkit::RunningProcess,
) -> Result<Exit, ProcessError> {
    let mut wait = std::pin::pin!(running.wait());
    let deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
    let outcome = loop {
        tokio::select! {
            biased;
            result = &mut wait => break result,
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if tokio::time::Instant::now() >= deadline { return Err(ProcessError::CleanupUncertain("startup rollback could not observe root exit".into())); }
                if let Err(error) = group.kill_all() { tracing::warn!(%error, "startup rollback signal failed"); }
            }
        }
    };
    confirm_empty(group)
        .await
        .map_err(ProcessError::CleanupUncertain)?;
    match outcome {
        Ok(outcome) => Ok(Exit {
            code: outcome.code(),
            signal: outcome.signal(),
            cause: ExitCause::Exited,
        }),
        Err(error) => Err(ProcessError::CleanupUncertain(format!(
            "rollback wait did not observe an exit: {error}"
        ))),
    }
}
/// Which environment rules apply. Only the host's variant is built outside
/// tests; the unit tests check both on every host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum EnvPlatform {
    Unix,
    Windows,
}

impl EnvPlatform {
    #[cfg(windows)]
    const HOST: Self = Self::Windows;
    #[cfg(not(windows))]
    const HOST: Self = Self::Unix;
}

/// Fixed search path for children on Unix hosts. Upstream easytier-core
/// shells out to system tools (`ifconfig`, `route`, `ip`) by bare name.
const UNIX_CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Windows search path, each entry relative to the Windows directory
/// reported by the OS (`trusted_system_root`).
const WINDOWS_CHILD_PATH: [&str; 4] = [
    r"\System32",
    "",
    r"\System32\Wbem",
    r"\System32\WindowsPowerShell\v1.0",
];

/// Builds the complete child environment. The engine starts every child
/// from an empty environment and owns a small set of variables: `PATH` (a
/// fixed trusted search path, never the host's own) and, on Windows,
/// `SystemRoot`/`windir`. A caller-supplied value for an owned variable is
/// dropped with a warning rather than rejected: the engine's value is the
/// one the child must see, so honoring the rest of the command is safe, and
/// a stray inherited key must not turn into a kernel that cannot start.
fn compose_env(
    platform: EnvPlatform,
    extra: Vec<(OsString, OsString)>,
    // Windows only: the OS-reported Windows directory.
    system_root: Option<OsString>,
) -> Result<Vec<(OsString, OsString)>, String> {
    let owned: &[&str] = match platform {
        EnvPlatform::Unix => &["PATH"],
        EnvPlatform::Windows => &["PATH", "SystemRoot", "windir"],
    };
    let is_owned = |key: &OsStr| {
        let key = key.to_string_lossy();
        owned.iter().any(|name| match platform {
            EnvPlatform::Unix => key == *name,
            EnvPlatform::Windows => key.eq_ignore_ascii_case(name),
        })
    };
    let mut env: Vec<_> = extra
        .into_iter()
        .filter(|(key, _)| {
            let keep = !is_owned(key);
            if !keep {
                tracing::warn!(
                    key = %key.to_string_lossy(),
                    "ignoring engine-owned variable in launch command environment"
                );
            }
            keep
        })
        .collect();
    match platform {
        EnvPlatform::Unix => env.push(("PATH".into(), UNIX_CHILD_PATH.into())),
        EnvPlatform::Windows => {
            let root = system_root
                .filter(|root| !root.is_empty())
                .ok_or_else(|| "Windows system directory is unavailable".to_owned())?;
            let mut path = OsString::new();
            for (index, suffix) in WINDOWS_CHILD_PATH.iter().enumerate() {
                if index > 0 {
                    path.push(";");
                }
                path.push(&root);
                path.push(suffix);
            }
            env.push(("SystemRoot".into(), root.clone()));
            env.push(("windir".into(), root));
            env.push(("PATH".into(), path));
        }
    }
    Ok(env)
}

async fn launch(
    cmd: Command,
    tx: &mpsc::Sender<ProcessEvent>,
) -> Result<
    (
        processkit::ProcessGroup,
        processkit::RunningProcess,
        ProcessIdentity,
        Containment,
    ),
    ProcessError,
> {
    let executable = identity::normalized(&cmd.executable).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            ProcessError::NotFound(cmd.executable.clone())
        } else {
            e.into()
        }
    })?;
    let group =
        processkit::ProcessGroup::new().map_err(|e| ProcessError::Containment(e.to_string()))?;
    let kind = containment(&group)?;
    // The Windows directory comes from the OS, never from this host's own
    // (caller-controlled) SystemRoot/windir environment.
    #[cfg(windows)]
    let system_root = match crate::trusted_system_root() {
        Ok(root) => Some(root),
        Err(error) => {
            tracing::warn!(%error, "Windows system directory is unavailable");
            None
        }
    };
    #[cfg(not(windows))]
    let system_root = None;
    let env = compose_env(EnvPlatform::HOST, cmd.env, system_root).map_err(|message| {
        ProcessError::Spawn {
            executable: executable.clone(),
            message,
        }
    })?;
    let mut backend = processkit::Command::new(&executable)
        .args(cmd.args)
        .env_clear()
        .envs(env)
        .create_no_window()
        .kill_on_parent_death()
        .stdout_raw_tee(EventWriter {
            tx: tx.clone(),
            stderr: false,
            dropped: false,
        })
        .stderr_raw_tee(EventWriter {
            tx: tx.clone(),
            stderr: true,
            dropped: false,
        });
    if let Some(cwd) = cmd.cwd {
        backend = backend.current_dir(cwd);
    }
    let running = match group.start(&backend).await {
        Ok(running) => running,
        Err(error) => {
            confirm_empty(&group)
                .await
                .map_err(ProcessError::CleanupUncertain)?;
            return Err(ProcessError::Spawn {
                executable: executable.clone(),
                message: error.to_string(),
            });
        }
    };
    let inspected = running.pid().map(inspect);
    let id = match inspected {
        Some(Ok(Some(id))) => id,
        other => {
            tracing::warn!(
                ?other,
                "identity unavailable for launched child; rolling back"
            );
            let exit = rollback_started(&group, running).await?;
            return Err(ProcessError::ExitedBeforeIdentity(exit));
        }
    };
    if id.exe != executable {
        let _ = rollback_started(&group, running).await?;
        return Err(ProcessError::Containment(
            "spawned image doesn't match executable".into(),
        ));
    }
    Ok((group, running, id, kind))
}

#[cfg(windows)]
async fn graceful(
    _group: &processkit::ProcessGroup,
    id: &ProcessIdentity,
    helper_executable: Option<&Path>,
) -> Result<(), ProcessError> {
    let _pin = identity::Pin::open(id.pid, false)?;
    if liveness(id) != Liveness::Same {
        return Err(ProcessError::Signal(
            "console target identity changed".into(),
        ));
    }
    let mut helper = tokio::process::Command::new(match helper_executable {
        Some(path) => path.to_owned(),
        None => std::env::current_exe()?,
    });
    helper
        .args(["--console-ctrl", &id.pid.to_string()])
        .creation_flags(0x0800_0000)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = tokio::time::timeout(Duration::from_secs(2), helper.status())
        .await
        .map_err(|_| ProcessError::Timeout)??;
    if status.success() {
        Ok(())
    } else {
        Err(ProcessError::Signal("console helper failed".into()))
    }
}
#[cfg(not(windows))]
async fn graceful(
    group: &processkit::ProcessGroup,
    _id: &ProcessIdentity,
    _helper: Option<&Path>,
) -> Result<(), ProcessError> {
    group
        .signal(processkit::Signal::Term)
        .map_err(|e| ProcessError::Signal(e.to_string()))
}

async fn run(
    cmd: Command,
    ready: oneshot::Sender<Result<Handle, ProcessError>>,
    helper: Option<PathBuf>,
) {
    let (tx, events) = mpsc::channel(257);
    let terminal = tx
        .clone()
        .reserve_owned()
        .await
        .expect("receiver still owned");
    let (group, running, id, containment) = match launch(cmd, &tx).await {
        Ok(result) => result,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let (requests, mut rx) = mpsc::channel::<Request>(8);
    let (terminal_tx, terminal_rx) = watch::channel(None);
    let (cancel, mut cancelled) = oneshot::channel();
    let live = Arc::new(Live {
        requests,
        terminal: terminal_rx,
    });
    let registered = {
        let mut registry = registry().lock().unwrap();
        registry.retain(|_, entry| match entry {
            RegistryEntry::Live(live) => live.strong_count() != 0,
            _ => true,
        });
        if let std::collections::hash_map::Entry::Vacant(slot) = registry.entry(id.clone()) {
            slot.insert(RegistryEntry::Live(Arc::downgrade(&live)));
            true
        } else {
            false
        }
    };
    if !registered {
        let result = rollback_started(&group, running).await;
        let reason = result.err().map_or_else(
            || "process identity collides with an existing containment".into(),
            |error| error.to_string(),
        );
        let _ = ready.send(Err(ProcessError::CleanupUncertain(reason)));
        return;
    }
    // Keep the containment discoverable even if its public handle was
    // dropped. The handle's cancellation sender, not registry Arc count,
    // requests cleanup. A cancelled spawn follows the same path.
    let _ = ready.send(Ok(Handle {
        id: id.clone(),
        containment,
        live: live.clone(),
        events: Some(events),
        _cancel: cancel,
    }));
    let mut wait = std::pin::pin!(running.wait());
    let mut cause = ExitCause::Exited;
    let mut grace_deadline = None;
    let mut hard_deadline = None;
    let mut closed = false;
    let mut pending = Vec::new();
    #[cfg(any(windows, target_os = "linux"))]
    let root_pin = identity::Pin::open(id.pid, false)
        .ok()
        .filter(|_| read_token(id.pid).ok().flatten().as_ref() == Some(&id.start_token));
    let root_exited = || {
        #[cfg(any(windows, target_os = "linux"))]
        if let Some(pin) = &root_pin {
            return pin.gone();
        }
        matches!(liveness(&id), Liveness::Gone | Liveness::Reused)
    };
    let mut probe = tokio::time::interval(Duration::from_millis(100));
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let outcome = loop {
        tokio::select! {
            biased;
            outcome = &mut wait => break Some(outcome),
            _ = &mut cancelled, if !closed => {
                closed = true;
                if !root_exited() { cause = ExitCause::Killed; }
                grace_deadline = None;
                hard_deadline.get_or_insert(tokio::time::Instant::now() + CLEANUP_TIMEOUT);
                if let Err(error) = group.kill_all() { tracing::warn!(%error, "drop cleanup signal failed"); }
            }
            _ = probe.tick() => {
                let now = tokio::time::Instant::now();
                if hard_deadline.is_some_and(|deadline| now >= deadline) {
                    break None;
                }
                let root_gone = root_exited();
                if grace_deadline.is_some_and(|deadline| now >= deadline) {
                    if !root_gone { cause = ExitCause::Killed; }
                    grace_deadline = None;
                    hard_deadline.get_or_insert(now + CLEANUP_TIMEOUT);
                }
                if root_gone {
                    grace_deadline = None;
                    hard_deadline.get_or_insert(now + CLEANUP_TIMEOUT);
                }
                if hard_deadline.is_some() && let Err(error) = group.kill_all() {
                    tracing::warn!(%error, "containment cleanup signal failed");
                }
            }
            request = rx.recv() => {
                let Some(request) = request else { break None; };
                let hard = root_exited() || request.grace.is_none() || hard_deadline.is_some();
                let result = if hard {
                    if !root_exited() && request.grace.is_none() { cause = ExitCause::Killed; }
                    grace_deadline = None;
                    hard_deadline.get_or_insert(tokio::time::Instant::now() + CLEANUP_TIMEOUT);
                    group.kill_all().map_err(|e| ProcessError::Signal(e.to_string()))
                } else if cause == ExitCause::Exited {
                    let grace = request.grace.unwrap();
                    cause = ExitCause::Stopped;
                    let start = tokio::time::Instant::now();
                    if tokio::time::timeout(grace, graceful(&group, &id, helper.as_deref())).await.is_ok_and(|r| r.is_ok()) {
                        grace_deadline = Some(start + grace);
                        Ok(())
                    } else {
                        cause = ExitCause::Killed;
                        hard_deadline.get_or_insert(tokio::time::Instant::now() + CLEANUP_TIMEOUT);
                        group.kill_all().map_err(|e| ProcessError::Signal(e.to_string()))
                    }
                } else { Ok(()) };
                // Per-request reply: a transient error on this operation is
                // not sticky state inherited by a later retry.
                match result {
                    Ok(()) => pending.push(request.reply),
                    Err(error) => { let _ = request.reply.send(Err(error)); }
                }
            }
        }
    };
    // A natural root outcome does not itself prove descendant teardown.
    let result: Terminal = match outcome {
        None => Err("bounded cleanup could not confirm root exit and containment".into()),
        Some(outcome) => match confirm_empty(&group).await {
            Err(error) => Err(error),
            Ok(()) => match outcome {
                Ok(outcome) => Ok(Exit {
                    code: outcome.code(),
                    signal: outcome.signal(),
                    cause,
                }),
                Err(error) if root_exited() => {
                    tracing::warn!(%error, "wait failed after containment cleanup");
                    // Confirmed cleanup, but an unrequested observation
                    // failure must count against the restart policy.
                    Ok(Exit {
                        code: None,
                        signal: None,
                        cause: ExitCause::Exited,
                    })
                }
                Err(error) => Err(format!(
                    "wait failed and root death is not independently confirmed: {error}"
                )),
            },
        },
    };
    // Send exactly one terminal notification. Uncertainty is neither Exited
    // nor proof of root death, and the frozen wait() cannot manufacture Exit.
    let group = if result.is_err() {
        // Install the strong tombstone before the terminal event is visible.
        // Dropping the public handle/worker cannot discard this proof anchor.
        registry()
            .lock()
            .unwrap()
            .insert(id.clone(), RegistryEntry::Quarantined(Arc::new(group)));
        None
    } else {
        Some(group)
    };
    terminal_tx.send_replace(Some(result.clone()));
    for reply in pending {
        let _ = reply.send(result.clone().map_err(ProcessError::CleanupUncertain));
    }
    terminal.send(match result {
        Ok(exit) => ProcessEvent::Exited(exit),
        Err(reason) => ProcessEvent::CleanupUncertain(reason),
    });
    drop(group);
    drop(live);
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn missing_marker_metadata_is_not_a_negative_match() {
        assert!(match_criteria(None, None, None).is_err());
        assert!(match_criteria(Some(true), None, Some(true)).is_err());
        assert!(match_criteria(None, Some(true), Some(true)).is_err());
        assert!(match_criteria(Some(true), Some(true), None).is_err());
        assert!(!match_criteria(None, Some(false), None).unwrap());
        assert!(match_criteria(Some(true), Some(true), Some(true)).unwrap());
    }

    /// A leader that left with a raw `exit` while another thread runs is the
    /// zombie entry of a live process: the sweep must not exclude it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_leader_with_a_live_thread_stays_a_candidate() {
        const HELPER: &str = "import ctypes, os, threading, time\n\
threading.Thread(target=time.sleep, args=(60,)).start()\n\
nr = {'x86_64': 60, 'aarch64': 93}[os.uname().machine]\n\
ctypes.CDLL(None).syscall(nr, 0)\n";
        // no-window: Linux only
        let mut child = std::process::Command::new("python3")
            .args(["-c", HELPER])
            .spawn()
            .unwrap();
        let pid = child.id();
        let is_zombie = || {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    let (_, rest) = stat.rsplit_once(')')?;
                    Some(rest.trim_start().starts_with('Z'))
                })
                == Some(true)
        };
        // Bounded wait for the helper's leader to exit (an observation loop).
        let zombie = (0..500).any(|_| {
            is_zombie() || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                false
            }
        });
        let outcome = std::panic::catch_unwind(|| {
            assert!(zombie, "the helper's leader never became a zombie");
            assert_eq!(
                identity::leader_threads(pid),
                identity::LeaderThreads::Siblings
            );
            let pids = [identity::pid(pid)];
            let snapshot = identity::snapshot(ProcessesToUpdate::Some(&pids)).unwrap();
            let process = snapshot.process(pids[0]).unwrap();
            assert_eq!(process.status(), ProcessStatus::Zombie);
            let own = process.user_id().unwrap().clone();
            let dir = tempfile::tempdir().unwrap();
            let marker = ProcessMarker {
                exe_root: "/usr".into(),
                cmdline_root: dir.path().into(),
            };
            assert!(candidate_matches(process, &own, &marker).is_err());
            assert!(marked_candidate(process, &own, &marker).is_err());
        });
        // SAFETY: signals our own child; SIGKILL ends every thread of it.
        unsafe { libc::kill(i32::try_from(pid).unwrap(), libc::SIGKILL) };
        child.wait().unwrap();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    /// sysinfo drops an unreaped zombie from its macOS snapshot (no image or
    /// argv). The kernel-list reconciliation must classify it as exited, not
    /// fail the sweep, while still listing every live PID it reconciles.
    #[cfg(target_os = "macos")]
    #[test]
    fn unreaped_zombie_missing_from_snapshot_is_not_a_live_candidate() {
        // no-window: macOS only
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        // Block until the child has exited, but leave it unreaped (WNOWAIT).
        // SAFETY: siginfo_t is plain old data; waitid only writes into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waits on our own child; WNOWAIT keeps it a zombie.
        let rc =
            unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        // Observed on macOS CI: the short BSD info flavor reports an
        // unreaped zombie as ESRCH, so either answer must exclude it.
        assert!(
            identity::bsd_state(pid)
                .unwrap()
                .is_none_or(|state| state.zombie)
        );
        assert!(identity::all_pids().unwrap().contains(&std::process::id()));
        let snapshot = identity::snapshot(ProcessesToUpdate::All).unwrap();
        let own = snapshot
            .process(identity::pid(std::process::id()))
            .and_then(|p| p.user_id())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let marker = ProcessMarker {
            exe_root: std::env::current_exe().unwrap().parent().unwrap().into(),
            cmdline_root: dir.path().into(),
        };
        assert!(unlisted_candidate(pid, own, &marker).unwrap().is_none());
        assert!(marked(&marker).unwrap().is_empty());
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn quarantine_survives_worker_and_handle_drop_until_group_is_confirmed() {
        // A valid positive PID outside supported PID allocator ranges; no
        // signal to it is ever issued. The tombstone holds our empty group.
        let id = ProcessIdentity {
            pid: 2_000_000_000,
            start_token: "test-quarantine".into(),
            exe: "absent-test-process".into(),
        };
        assert_eq!(liveness(&id), Liveness::Gone);
        let group = Arc::new(processkit::ProcessGroup::new().unwrap());
        let weak = Arc::downgrade(&group);
        registry()
            .lock()
            .unwrap()
            .insert(id.clone(), RegistryEntry::Quarantined(group.clone()));
        drop(group);
        let engine = ProcessKitEngine::new();
        assert!(weak.upgrade().is_some());
        assert_eq!(engine.liveness(&id).await, Liveness::Uncertain);
        assert_eq!(engine.kill_verified(&id).await.unwrap(), KillOutcome::Gone);
        assert_eq!(engine.liveness(&id).await, Liveness::Gone);
        // Confirmation is delivered to H1 for durable closure; the old
        // process-local tombstone is not retained indefinitely.
        assert!(registry_entry(&id).is_none());
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Uncertain
        );
        assert!(weak.upgrade().is_none());
        registry().lock().unwrap().remove(&id);
    }

    #[tokio::test]
    async fn empty_group_without_root_death_keeps_quarantine() {
        let id = inspect(std::process::id()).unwrap().unwrap();
        let group = Arc::new(processkit::ProcessGroup::new().unwrap());
        registry()
            .lock()
            .unwrap()
            .insert(id.clone(), RegistryEntry::Quarantined(group));
        let engine = ProcessKitEngine::new();
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Uncertain
        );
        assert_eq!(engine.liveness(&id).await, Liveness::Uncertain);
        assert!(matches!(
            registry_entry(&id),
            Some(RegistryEntry::Quarantined(_))
        ));
        registry().lock().unwrap().remove(&id);
    }

    #[tokio::test]
    async fn a_failed_request_does_not_poison_a_new_request() {
        let (requests, mut rx) = mpsc::channel::<Request>(2);
        let (terminal_tx, terminal) = watch::channel(None);
        let live = Live { requests, terminal };
        let exit = Exit {
            code: Some(0),
            signal: None,
            cause: ExitCause::Killed,
        };
        let result = exit.clone();
        let worker = tokio::spawn(async move {
            let first = rx.recv().await.unwrap();
            first
                .reply
                .send(Err(ProcessError::Signal("transient".into())))
                .unwrap();
            let second = rx.recv().await.unwrap();
            terminal_tx.send_replace(Some(Ok(result.clone())));
            second.reply.send(Ok(result)).unwrap();
        });
        assert!(matches!(
            live.request(None).await,
            Err(ProcessError::Signal(_))
        ));
        assert_eq!(live.request(None).await.unwrap(), exit);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn startup_rollback_reaps_already_exited_child() {
        let group = processkit::ProcessGroup::new().unwrap();
        let running = group
            .start(
                &processkit::Command::new(std::env::current_exe().unwrap())
                    .arg("--help")
                    .create_no_window(),
            )
            .await
            .unwrap();
        // Let the ordinary test harness exit; rollback must acquire its
        // real exit status rather than returning a generic spawn error.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let exit = rollback_started(&group, running).await.unwrap();
        assert_eq!(exit.code, Some(0));
        assert!(exit.abnormal());
        assert!(group.members().unwrap().is_empty());
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    fn pairs(env: &[(OsString, OsString)]) -> Vec<(String, String)> {
        env.iter()
            .map(|(k, v)| (k.to_string_lossy().into(), v.to_string_lossy().into()))
            .collect()
    }

    fn var(key: &str, value: &str) -> (OsString, OsString) {
        (key.into(), value.into())
    }

    #[test]
    fn unix_child_gets_the_fixed_system_path() {
        let env = compose_env(EnvPlatform::Unix, vec![var("RUST_LOG", "info")], None).unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("RUST_LOG".into(), "info".into()),
                ("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()),
            ]
        );
    }

    #[test]
    fn unix_command_path_cannot_override_the_engine_path() {
        let env = compose_env(
            EnvPlatform::Unix,
            vec![var("PATH", "/tmp/evil"), var("A", "1")],
            Some("ignored".into()),
        )
        .unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("A".into(), "1".into()),
                ("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()),
            ]
        );
    }

    #[test]
    fn unix_variable_names_stay_case_sensitive() {
        let env = compose_env(EnvPlatform::Unix, vec![var("Path", "x")], None).unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("Path".into(), "x".into()),
                ("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()),
            ]
        );
    }

    #[test]
    fn windows_child_path_is_built_from_system_root() {
        let env = compose_env(
            EnvPlatform::Windows,
            vec![var("RUST_LOG", "info")],
            Some(r"C:\Windows".into()),
        )
        .unwrap();
        assert_eq!(
            pairs(&env),
            [
                ("RUST_LOG".into(), "info".into()),
                ("SystemRoot".into(), r"C:\Windows".into()),
                ("windir".into(), r"C:\Windows".into()),
                (
                    "PATH".into(),
                    r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0"
                        .into()
                ),
            ]
        );
    }

    #[test]
    fn windows_command_cannot_override_owned_variables_in_any_case() {
        let env = compose_env(
            EnvPlatform::Windows,
            vec![
                var("Path", r"C:\evil"),
                var("path", r"C:\evil"),
                var("SYSTEMROOT", r"C:\evil"),
                var("WinDir", r"C:\evil"),
                var("A", "1"),
            ],
            Some(r"C:\Windows".into()),
        )
        .unwrap();
        let env = pairs(&env);
        assert_eq!(env[0], ("A".into(), "1".into()));
        assert_eq!(env.len(), 4);
        assert!(env.iter().all(|(_, v)| !v.contains("evil")));
    }

    /// The root is the OS-reported Windows directory, whatever this
    /// process's own SystemRoot says.
    #[cfg(windows)]
    #[test]
    fn host_windows_root_comes_from_the_os() {
        let root = crate::trusted_system_root().unwrap();
        assert!(Path::new(&root).join("System32").is_dir(), "{root:?}");
        let env = compose_env(EnvPlatform::HOST, Vec::new(), Some(root.clone())).unwrap();
        let path = &env.iter().find(|(k, _)| k == "PATH").unwrap().1;
        let first = path.to_string_lossy().split(';').next().unwrap().to_owned();
        assert_eq!(Path::new(&first), Path::new(&root).join("System32"));
    }

    #[test]
    fn windows_without_system_root_fails_closed() {
        assert!(compose_env(EnvPlatform::Windows, Vec::new(), None).is_err());
        assert!(compose_env(EnvPlatform::Windows, Vec::new(), Some(OsString::new())).is_err());
    }
}

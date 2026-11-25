//! ProcessKit adapter. All backend types remain private to this module.
use crate::{identity, parent_death, *};
use async_trait::async_trait;
use std::{
    collections::HashMap,
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
        }
    }
}

type Registry = Mutex<HashMap<ProcessIdentity, Weak<Live>>>;
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
struct Live {
    requests: mpsc::Sender<Request>,
    exit: watch::Receiver<Option<Exit>>,
    failure: watch::Receiver<Option<String>>,
}
struct Request {
    grace: Option<Duration>,
    ack: oneshot::Sender<Result<(), ProcessError>>,
}
impl Live {
    async fn wait(&self) -> Exit {
        let mut rx = self.exit.clone();
        if let Ok(exit) = rx.wait_for(Option::is_some).await {
            return exit.clone().unwrap();
        }
        // Interrupted worker is not proof of death. The frozen wait API
        // cannot represent an error; never fabricate an exit.
        std::future::pending().await
    }
    async fn request(&self, grace: Option<Duration>) -> Result<Exit, ProcessError> {
        if let Some(exit) = self.exit.borrow().clone() {
            return Ok(exit);
        }
        let (ack, response) = oneshot::channel();
        let mut failure = self.failure.clone();
        if self.requests.send(Request { grace, ack }).await.is_ok() {
            tokio::select! {
                biased;
                response = response => if let Ok(result) = response { result?; },
                error = failure.wait_for(Option::is_some) => {
                    if let Ok(error) = error { return Err(ProcessError::Signal(error.clone().unwrap())); }
                }
            }
        }
        let mut rx = self.exit.clone();
        tokio::select! {
            biased;
            exit = rx.wait_for(Option::is_some) => {
                let exit = exit.map_err(|_| ProcessError::Signal("worker ended without confirmed exit".into()))?;
                Ok(exit.clone().unwrap())
            }
            error = failure.wait_for(Option::is_some) => {
                Err(ProcessError::Signal(error.map(|e| e.clone().unwrap()).unwrap_or_else(|_| "worker ended without confirmed exit".into())))
            }
        }
    }
}
struct Handle {
    id: ProcessIdentity,
    containment: Containment,
    live: Arc<Live>,
    events: Option<mpsc::Receiver<ProcessEvent>>,
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
    let info =
        processkit::process_info(pid).map_err(|e| ProcessError::Enumeration(e.to_string()))?;
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
fn marked(marker: &ProcessMarker) -> Result<Vec<ProcessIdentity>, ProcessError> {
    let snapshot = identity::snapshot(ProcessesToUpdate::All)?;
    let own = snapshot
        .process(identity::pid(std::process::id()))
        .and_then(|p| p.user_id())
        .ok_or_else(|| ProcessError::Enumeration("cannot determine host user".into()))?;
    let mut found = Vec::new();
    for process in snapshot.processes().values() {
        let cmd_matches = process
            .cmd()
            .iter()
            .skip(1)
            .any(|arg| identity::under(Path::new(arg), &marker.cmdline_root));
        let Some(exe) = process.exe() else {
            if cmd_matches && (process.user_id().is_none() || process.user_id() == Some(own)) {
                return Err(ProcessError::Enumeration(
                    "cannot inspect possible marked image".into(),
                ));
            }
            continue;
        };
        if !identity::under(exe, &marker.exe_root) {
            continue;
        }
        if process.user_id() != Some(own) {
            if process.user_id().is_none() && (cmd_matches || process.cmd().is_empty()) {
                return Err(ProcessError::Enumeration(
                    "cannot determine candidate user".into(),
                ));
            }
            continue;
        }
        if process.cmd().is_empty() {
            return Err(ProcessError::Enumeration(
                "cannot inspect candidate command line".into(),
            ));
        }
        if !cmd_matches {
            continue;
        }
        let pid = process.pid().as_u32();
        // On platforms with an object/descriptor handle, keep that object
        // pinned throughout candidate verification (including owner & argv).
        #[cfg(any(windows, target_os = "linux"))]
        let pin = match identity::Pin::open(pid, false) {
            Ok(pin) => pin,
            Err(error) => {
                if read_token(pid)?.is_none() {
                    continue;
                }
                return Err(ProcessError::Enumeration(error.to_string()));
            }
        };
        let Some(token) = read_token(pid)? else {
            continue;
        };
        let pids = [identity::pid(pid)];
        let fresh = identity::snapshot(ProcessesToUpdate::Some(&pids))?;
        let Some(p) = fresh.process(pids[0]) else {
            continue;
        };
        if p.user_id() != Some(own)
            || !p
                .exe()
                .is_some_and(|exe| identity::under(exe, &marker.exe_root))
            || !p
                .cmd()
                .iter()
                .skip(1)
                .any(|arg| identity::under(Path::new(arg), &marker.cmdline_root))
        {
            continue;
        }
        if let Some(current) = inspect(pid)?
            && current.start_token == token
            && identity::under(&current.exe, &marker.exe_root)
        {
            #[cfg(any(windows, target_os = "linux"))]
            if pin.gone() {
                continue;
            }
            found.push(current);
        }
    }
    found.sort_by_key(|id| id.pid);
    Ok(found)
}
fn verdict(value: Liveness) -> KillOutcome {
    match value {
        Liveness::Same | Liveness::Uncertain => KillOutcome::Uncertain,
        Liveness::Reused => KillOutcome::Reused,
        Liveness::Gone => KillOutcome::Gone,
    }
}

/// Orphan: pin before verification, signal only via pin. If descendants
/// lack a containment credential, quarantine instead of guessing ownership.
#[cfg(any(windows, target_os = "linux"))]
fn kill_orphan(id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
    if id.pid == std::process::id() || id.pid == 0 {
        return Ok(KillOutcome::Uncertain);
    }
    let pin = match identity::Pin::open(id.pid, true) {
        Ok(pin) => pin,
        Err(_) => return Ok(verdict(liveness(id))),
    };
    let state = liveness(id);
    if state != Liveness::Same {
        return Ok(verdict(state));
    }
    if pin.gone() {
        return Ok(KillOutcome::Gone);
    }
    let snapshot = identity::snapshot(ProcessesToUpdate::All)?;
    let owner = snapshot
        .process(identity::pid(id.pid))
        .and_then(|p| p.user_id());
    let host = snapshot
        .process(identity::pid(std::process::id()))
        .and_then(|p| p.user_id());
    if owner.is_none() || owner != host {
        return Ok(KillOutcome::Uncertain);
    }
    let descendants: Vec<_> = snapshot
        .processes()
        .values()
        .filter(|p| p.parent() == Some(identity::pid(id.pid)))
        .map(|p| p.pid().as_u32())
        .collect();
    if !descendants.is_empty() {
        // Without the original group we cannot prove that a descendant
        // cannot fork during a multi-process sweep. Preserve the parent
        // identity so the operator can resolve the entire quarantined tree.
        for child in descendants {
            let child_pin = identity::Pin::open(child, false).ok();
            let token = read_token(child).ok().flatten();
            let verified = child_pin.as_ref().is_some_and(|pin| !pin.gone())
                && token.is_some()
                && identity::snapshot(ProcessesToUpdate::Some(&[identity::pid(child)]))
                    .ok()
                    .and_then(|s| s.process(identity::pid(child)).and_then(|p| p.parent()))
                    == Some(identity::pid(id.pid))
                && read_token(child).ok().flatten() == token;
            tracing::warn!(
                parent = id.pid,
                child,
                ?token,
                verified,
                "orphan descendant has no verified containment"
            );
        }
        return Ok(KillOutcome::Uncertain);
    }
    if let Err(e) = pin.stop() {
        return match liveness(id) {
            Liveness::Same => Err(ProcessError::Signal(e.to_string())),
            other => Ok(verdict(other)),
        };
    }
    for _ in 0..100 {
        if pin.gone() {
            return Ok(KillOutcome::Killed);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(KillOutcome::Uncertain)
}
#[cfg(not(any(windows, target_os = "linux")))]
fn kill_orphan(id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
    Ok(verdict(liveness(id)))
}

#[async_trait]
impl ProcessEngine for ProcessKitEngine {
    async fn spawn(&self, cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
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
        let mut registry = registry().lock().unwrap();
        registry.retain(|_, live| live.strong_count() != 0);
        registry.insert(handle.id.clone(), Arc::downgrade(&handle.live));
        Ok(Box::new(handle))
    }
    async fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        let id = id.clone();
        tokio::task::spawn_blocking(move || liveness(&id))
            .await
            .unwrap_or(Liveness::Uncertain)
    }
    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        let live = registry().lock().unwrap().get(id).and_then(Weak::upgrade);
        if let Some(live) = live {
            let state = self.liveness(id).await;
            if state != Liveness::Same {
                return Ok(verdict(state));
            }
            live.request(None).await?;
            return Ok(KillOutcome::Killed);
        }
        let id = id.clone();
        tokio::task::spawn_blocking(move || kill_orphan(&id))
            .await
            .map_err(|e| ProcessError::Signal(e.to_string()))?
    }
    async fn find_marked(
        &self,
        marker: &ProcessMarker,
    ) -> Result<Vec<ProcessIdentity>, ProcessError> {
        let marker = marker.clone();
        tokio::task::spawn_blocking(move || marked(&marker))
            .await
            .map_err(|e| ProcessError::Enumeration(e.to_string()))?
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
    let mut backend = processkit::Command::new(&executable)
        .args(cmd.args)
        .env_clear()
        .envs(cmd.env)
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
    let running = group
        .start(&backend)
        .await
        .map_err(|e| ProcessError::Spawn {
            executable: executable.clone(),
            message: e.to_string(),
        })?;
    let pid = running
        .pid()
        .ok_or_else(|| ProcessError::Containment("backend did not provide PID".into()))?;
    let id = inspect(pid)?.ok_or_else(|| ProcessError::Spawn {
        executable: executable.clone(),
        message: "child exited before identity was captured".into(),
    })?;
    if id.exe != executable {
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
    let (exit_tx, exit) = watch::channel(None);
    let (failure_tx, failure) = watch::channel(None);
    let live = Arc::new(Live {
        requests,
        exit,
        failure,
    });
    if ready
        .send(Ok(Handle {
            id: id.clone(),
            containment,
            live,
            events: Some(events),
        }))
        .is_err()
    {
        return;
    }
    let mut wait = std::pin::pin!(running.wait());
    let mut cause = ExitCause::Exited;
    let mut deadline = None;
    let mut closed = false;
    // The backend wait drains output after reaping the root. A surviving
    // grandchild can still own the output pipe: independently watch the
    // root and tear down the known containment once its leader exits.
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
    let mut probe = tokio::time::interval(Duration::from_millis(250));
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut root_cleaned = false;
    let outcome = loop {
        tokio::select! {
            biased;
            outcome = &mut wait => break outcome,
            request = rx.recv(), if !closed => {
                let Some(request) = request else {
                    closed = true;
                    cause = ExitCause::Killed;
                    if let Err(error) = group.kill_all() {
                        tracing::error!(%error, "drop cleanup failed; retrying");
                        deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                    }
                    continue;
                };
                let result = match request.grace {
                    _ if root_exited() => group.kill_all().map_err(|e| ProcessError::Signal(e.to_string())),
                    Some(grace) if cause == ExitCause::Exited => {
                        cause = ExitCause::Stopped;
                        let start = tokio::time::Instant::now();
                        if tokio::time::timeout(grace, graceful(&group, &id, helper.as_deref())).await.is_ok_and(|r| r.is_ok()) {
                            deadline = Some(start + grace);
                            Ok(())
                        } else {
                            cause = ExitCause::Killed;
                            group.kill_all().map_err(|e| ProcessError::Signal(e.to_string()))
                        }
                    }
                    Some(_) => Ok(()),
                    None => {
                        cause = ExitCause::Killed;
                        deadline = None;
                        group.kill_all().map_err(|e| ProcessError::Signal(e.to_string()))
                    }
                };
                match &result {
                    Ok(()) => { failure_tx.send_replace(None); }
                    Err(error) => {
                        failure_tx.send_replace(Some(error.to_string()));
                        if cause == ExitCause::Killed { deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1)); }
                    }
                }
                let _ = request.ack.send(result);
            }
            () = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await } else { std::future::pending().await } } => {
                if !root_exited() { cause = ExitCause::Killed; }
                deadline = None;
                match group.kill_all() {
                    Ok(()) => { failure_tx.send_replace(None); }
                    Err(error) => {
                        tracing::error!(%error, "failed to kill process tree");
                        failure_tx.send_replace(Some(error.to_string()));
                        deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                    }
                }
            }
            _ = probe.tick(), if !root_cleaned => {
                if root_exited() {
                    match group.kill_all() {
                        Ok(()) => { root_cleaned = true; deadline = None; failure_tx.send_replace(None); }
                        Err(error) => {
                            tracing::error!(%error, "cannot confirm descendant cleanup");
                            failure_tx.send_replace(Some(error.to_string()));
                        }
                    }
                }
            }
        }
    };
    // Root wait alone is not proof of containment cleanup.
    while let Err(error) = group.kill_all() {
        tracing::error!(%error, "tree cleanup not confirmed; retrying");
        failure_tx.send_replace(Some(error.to_string()));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    drop(group);
    let exit = match outcome {
        Ok(outcome) => Exit {
            code: outcome.code(),
            signal: outcome.signal(),
            cause,
        },
        Err(error) => {
            tracing::error!(%error, "process wait failed");
            failure_tx.send_replace(Some(error.to_string()));
            loop {
                match liveness(&id) {
                    Liveness::Gone | Liveness::Reused => {
                        break Exit {
                            code: None,
                            signal: None,
                            cause: ExitCause::Killed,
                        };
                    }
                    _ => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
        }
    };
    exit_tx.send_replace(Some(exit.clone()));
    terminal.send(ProcessEvent::Exited(exit));
}

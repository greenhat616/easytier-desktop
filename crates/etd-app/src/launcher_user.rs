//! [`crate::HostLauncher`] for the user host (UI starts `etd-host` as a child
//! process) and for connecting to an installed service. Owned by A1.
//!
//! A host counts as reachable only after the connector verified the server
//! process. If something else answers on the endpoint, nothing is started
//! and nothing is sent to it.
//!
//! The user host outlives the launcher on purpose: it ends through its lease,
//! not when the UI drops a handle. Installing the service needs elevation and
//! is not done here: [`LaunchError::NotInstalled`] lets the UI offer it. The
//! elevated session form (Windows) is added with
//! [`LocalHostLauncher::with_session`]; see [`crate::launcher_session`].
use crate::{
    HostLauncher, HostTarget, LaunchError, SessionRefusal,
    launcher_session::{
        SESSION_HOST_ARGS, SessionParts, StartedProcess, refusal_of, start_elevated,
    },
};
use async_trait::async_trait;
use etd_contract::HostMode;
use etd_ipc::{
    Connector, Endpoint, SERVICE_PIPE_NAME, SERVICE_SOCKET_PATH, ServerExpectation,
    ServerRequirement,
};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, watch},
    time::{Instant, sleep, timeout},
};

/// Command line of the user host.
pub const USER_HOST_ARGS: [&str; 3] = ["run", "--mode", "user"];

/// Makes a connector that enforces one [`ServerExpectation`].
pub trait ConnectorFactory: Send + Sync {
    fn connector(&self, expectation: &ServerExpectation) -> Arc<dyn Connector>;
}

/// The real named-pipe / Unix-socket connectors.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalConnectors;

impl ConnectorFactory for LocalConnectors {
    fn connector(&self, expectation: &ServerExpectation) -> Arc<dyn Connector> {
        Arc::new(etd_ipc::platform::LocalConnector {
            expectation: expectation.clone(),
        })
    }
}

fn directory_of(program: &Path) -> PathBuf {
    program.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// The installed service host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHostConfig {
    /// Installed `etd-host` binary; its presence means "installed".
    pub program: PathBuf,
    pub endpoint: Endpoint,
    pub expectation: ServerExpectation,
}

impl ServiceHostConfig {
    /// The service at its well-known endpoint, installed as `program`.
    pub fn standard(program: PathBuf) -> Self {
        let endpoint = if cfg!(windows) {
            Endpoint::NamedPipe(SERVICE_PIPE_NAME.into())
        } else {
            Endpoint::UnixSocket(SERVICE_SOCKET_PATH.into())
        };
        let expectation = ServerExpectation {
            exe_dir: directory_of(&program),
            requirement: ServerRequirement::Service,
        };
        Self {
            program,
            endpoint,
            expectation,
        }
    }

    fn target(&self) -> HostTarget {
        HostTarget {
            mode: HostMode::Service,
            endpoint: self.endpoint.clone(),
            expectation: self.expectation.clone(),
        }
    }
}

/// The user host started as a child of the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHostConfig {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub endpoint: Endpoint,
    pub expectation: ServerExpectation,
}

impl UserHostConfig {
    /// The current user's endpoint and the standard command line.
    pub fn standard(program: PathBuf) -> io::Result<Self> {
        let user = etd_ipc::platform::current_user()?;
        let endpoint = user_endpoint(&user)?;
        let expectation = ServerExpectation {
            exe_dir: directory_of(&program),
            requirement: ServerRequirement::CurrentUser,
        };
        Ok(Self {
            program,
            args: USER_HOST_ARGS.iter().map(OsString::from).collect(),
            endpoint,
            expectation,
        })
    }

    fn target(&self) -> HostTarget {
        HostTarget {
            mode: HostMode::User,
            endpoint: self.endpoint.clone(),
            expectation: self.expectation.clone(),
        }
    }
}

#[cfg(windows)]
fn user_endpoint(user: &etd_ipc::OsUserId) -> io::Result<Endpoint> {
    match user {
        etd_ipc::OsUserId::WindowsSid(sid) => Ok(Endpoint::NamedPipe(format!(
            r"\\.\pipe\easytier-desk-user-{sid}"
        ))),
        _ => Err(io::Error::other("the current user has no SID")),
    }
}

#[cfg(target_os = "linux")]
fn user_endpoint(_: &etd_ipc::OsUserId) -> io::Result<Endpoint> {
    Ok(Endpoint::UnixSocket(
        etd_ipc::platform::user_runtime_dir().join("host.sock"),
    ))
}

#[cfg(target_os = "macos")]
fn user_endpoint(_: &etd_ipc::OsUserId) -> io::Result<Endpoint> {
    Ok(Endpoint::UnixSocket(
        etd_ipc::platform::user_runtime_dir()?.join("host.sock"),
    ))
}

/// Creates the private directory of a user socket if it is missing. An
/// existing directory is left alone; the connector judges it.
fn prepare_endpoint_directory(endpoint: &Endpoint) -> io::Result<()> {
    #[cfg(unix)]
    if let Endpoint::UnixSocket(path) = endpoint
        && let Some(directory) = path.parent()
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let _ = endpoint;
    Ok(())
}

/// A host process this launcher started.
pub trait SpawnedHost: Send {
    /// How the process ended, or `None` while it runs.
    fn try_exit(&mut self) -> io::Result<Option<String>>;
}

pub trait HostSpawner: Send + Sync {
    fn spawn(&self, config: &UserHostConfig) -> io::Result<Box<dyn SpawnedHost>>;
}

/// Starts the host with no console and no pipes to the UI.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSpawner;

struct TokioChild(tokio::process::Child);

impl SpawnedHost for TokioChild {
    fn try_exit(&mut self) -> io::Result<Option<String>> {
        Ok(self.0.try_wait()?.map(|status| status.to_string()))
    }
}

impl HostSpawner for TokioSpawner {
    fn spawn(&self, config: &UserHostConfig) -> io::Result<Box<dyn SpawnedHost>> {
        use std::process::Stdio;
        let mut command = tokio::process::Command::new(&config.program);
        command
            .args(&config.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        Ok(Box::new(TokioChild(command.spawn()?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LauncherTimings {
    /// How long a started (or installed) host may take to answer. Its
    /// startup self-check runs before it listens.
    pub startup: Duration,
    pub poll: Duration,
    /// Limit for one connection attempt.
    pub connect: Duration,
}

impl Default for LauncherTimings {
    fn default() -> Self {
        Self {
            startup: Duration::from_secs(20),
            poll: Duration::from_millis(100),
            connect: Duration::from_secs(2),
        }
    }
}

enum Reach {
    Verified,
    Absent,
    /// Verification failed or access was refused.
    Refused(String),
}

pub struct LocalHostLauncher {
    service: Option<ServiceHostConfig>,
    user: Option<UserHostConfig>,
    connectors: Arc<dyn ConnectorFactory>,
    spawner: Arc<dyn HostSpawner>,
    timings: LauncherTimings,
    /// The user host this launcher started. The lock also serializes
    /// `ensure`, so two callers cannot start two hosts.
    child: Mutex<Option<Box<dyn SpawnedHost>>>,
    session: Option<Arc<SessionLauncher>>,
}

impl LocalHostLauncher {
    /// `None` disables a host form.
    pub fn new(service: Option<ServiceHostConfig>, user: Option<UserHostConfig>) -> Self {
        Self::with_parts(
            service,
            user,
            Arc::new(LocalConnectors),
            Arc::new(TokioSpawner),
            LauncherTimings::default(),
        )
    }

    pub fn with_parts(
        service: Option<ServiceHostConfig>,
        user: Option<UserHostConfig>,
        connectors: Arc<dyn ConnectorFactory>,
        spawner: Arc<dyn HostSpawner>,
        timings: LauncherTimings,
    ) -> Self {
        Self {
            service,
            user,
            connectors,
            spawner,
            timings,
            child: Mutex::new(None),
            session: None,
        }
    }

    /// Also offer the elevated session form.
    pub fn with_session(mut self, parts: SessionParts) -> Self {
        self.session = Some(Arc::new(SessionLauncher {
            parts,
            connectors: self.connectors.clone(),
            timings: self.timings,
            child: Mutex::new(None),
            pending: std::sync::Mutex::new(None),
        }));
        self
    }

    async fn reach(&self, endpoint: &Endpoint, expectation: &ServerExpectation) -> Reach {
        // The Unix connector reports a socket that does not exist as refused;
        // nothing is listening there, so a host may be started.
        if let Endpoint::UnixSocket(path) = endpoint
            && matches!(
                std::fs::symlink_metadata(path),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
        {
            return Reach::Absent;
        }
        let connector = self.connectors.connector(expectation);
        match timeout(self.timings.connect, connector.connect(endpoint)).await {
            Ok(Ok(_)) => Reach::Verified,
            Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                Reach::Refused(error.to_string())
            }
            Ok(Err(_)) | Err(_) => Reach::Absent,
        }
    }

    async fn ensure_service(&self) -> Result<HostTarget, LaunchError> {
        let config = self.service.as_ref().ok_or(LaunchError::NotInstalled)?;
        let deadline = Instant::now() + self.timings.startup;
        loop {
            match self.reach(&config.endpoint, &config.expectation).await {
                Reach::Verified => return Ok(config.target()),
                Reach::Refused(reason) => return Err(refused(&reason)),
                Reach::Absent => {}
            }
            if !installed(&config.program)? {
                return Err(LaunchError::NotInstalled);
            }
            if Instant::now() >= deadline {
                return Err(LaunchError::Timeout);
            }
            sleep(self.timings.poll).await;
        }
    }

    async fn ensure_user(&self) -> Result<HostTarget, LaunchError> {
        let config = self
            .user
            .as_ref()
            .ok_or(LaunchError::Unsupported(HostMode::User))?;
        let mut child = self.child.lock().await;
        prepare_endpoint_directory(&config.endpoint)
            .map_err(|error| LaunchError::Io(format!("cannot prepare the endpoint: {error}")))?;
        match self.reach(&config.endpoint, &config.expectation).await {
            Reach::Verified => return Ok(config.target()),
            Reach::Refused(reason) => return Err(refused(&reason)),
            Reach::Absent => {}
        }
        // A host we started that is still running is only slow: wait for it
        // instead of starting a second one.
        let running = match child.as_mut() {
            Some(process) => process.try_exit().map_err(launch_io)?.is_none(),
            None => false,
        };
        if !running {
            *child = Some(
                self.spawner
                    .spawn(config)
                    .map_err(|error| LaunchError::Spawn(error.to_string()))?,
            );
        }
        let deadline = Instant::now() + self.timings.startup;
        loop {
            sleep(self.timings.poll).await;
            let exit = match child.as_mut() {
                Some(process) => process.try_exit().map_err(launch_io)?,
                None => None,
            };
            match self.reach(&config.endpoint, &config.expectation).await {
                // Also covers a host that exited because another one already
                // holds the user's lock and now answers.
                Reach::Verified => return Ok(config.target()),
                Reach::Refused(reason) => return Err(refused(&reason)),
                Reach::Absent => {}
            }
            if let Some(status) = exit {
                *child = None;
                return Err(LaunchError::Spawn(format!(
                    "the host exited during start-up ({status})"
                )));
            }
            if Instant::now() >= deadline {
                // Not killed: it may be reclaiming leftovers of an earlier
                // run, and the next call picks it up.
                return Err(LaunchError::Timeout);
            }
        }
    }
}

impl LocalHostLauncher {
    /// doc#13 #choose: the service whenever it is installed (never a session
    /// host beside it), else the session launch: see [`SessionLauncher`].
    async fn ensure_session(&self) -> Result<HostTarget, LaunchError> {
        let session = self
            .session
            .as_ref()
            .ok_or(LaunchError::Unsupported(HostMode::ElevatedSession))?;
        if let Some(service) = &self.service
            && installed(&service.program)?
        {
            return self.ensure_service().await;
        }
        outcome(session.join_or_start()).await
    }
}

type LaunchOutcome = Result<HostTarget, LaunchError>;

/// Starts and finds the elevated session host.
///
/// A launch runs as its own task, not in the caller's future: the UAC
/// consent call blocks until the user answers and cannot be cancelled, so a
/// Connect or probe that the bridge abandons must not lose the answer or
/// free the way for a second prompt. Every `ensure(ElevatedSession)` and
/// `probe` while a launch is pending waits for that same launch and gets its
/// outcome; only a Connect after it resolved starts a new one.
struct SessionLauncher {
    parts: SessionParts,
    connectors: Arc<dyn ConnectorFactory>,
    timings: LauncherTimings,
    /// The session host started last. Only launch tasks touch it, one at a
    /// time.
    child: Mutex<Option<Box<dyn StartedProcess>>>,
    /// The launch in progress: its outcome once it resolved.
    pending: std::sync::Mutex<Option<watch::Receiver<Option<LaunchOutcome>>>>,
}

impl SessionLauncher {
    /// The launch still in progress, if any.
    fn pending(&self) -> Option<watch::Receiver<Option<LaunchOutcome>>> {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.as_ref().filter(|rx| in_progress(rx)).cloned()
    }

    /// Joins the launch in progress, or starts one.
    fn join_or_start(self: &Arc<Self>) -> watch::Receiver<Option<LaunchOutcome>> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rx) = pending.as_ref().filter(|rx| in_progress(rx)) {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        let launcher = self.clone();
        tokio::spawn(async move {
            let outcome = launcher.launch().await;
            tx.send_replace(Some(outcome));
        });
        *pending = Some(rx.clone());
        rx
    }

    async fn reach(&self) -> SessionReach {
        let config = &self.parts.config;
        let connector = self.connectors.connector(&config.expectation);
        match timeout(self.timings.connect, connector.connect(&config.endpoint)).await {
            Ok(Ok(_)) => SessionReach::Verified,
            Ok(Err(error)) if no_such_pipe(&error) => SessionReach::Absent,
            Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                SessionReach::Occupied
            }
            Ok(Err(error)) => SessionReach::Unverified(error.to_string()),
            Err(_) => {
                SessionReach::Unverified(format!("no answer within {:?}", self.timings.connect))
            }
        }
    }

    /// A running session host, else start one: one UAC prompt from an
    /// unelevated administrator, a direct start from an elevated UI,
    /// `Unsupported` for a standard account.
    async fn launch(&self) -> LaunchOutcome {
        let config = &self.parts.config;
        let mut child = self.child.lock().await;
        match self.reach().await {
            SessionReach::Verified => return Ok(config.target()),
            SessionReach::Occupied => return Err(occupied()),
            // Fail closed: something may be there, so no second host.
            SessionReach::Unverified(reason) => return Err(unverified(&reason)),
            SessionReach::Absent => {}
        }
        let running = match child.as_mut() {
            Some(process) => process.exit_code().map_err(launch_io)?.is_none(),
            None => false,
        };
        if !running {
            let (starter, program) = (self.parts.starter.clone(), config.program.clone());
            let started = tokio::task::spawn_blocking(move || {
                start_elevated(starter.as_ref(), &program, &SESSION_HOST_ARGS)
            })
            .await
            .map_err(|error| LaunchError::Io(error.to_string()))??;
            *child = Some(started);
        }
        let deadline = Instant::now() + self.timings.startup;
        let mut last_unverified = None;
        loop {
            sleep(self.timings.poll).await;
            let exit = match child.as_mut() {
                Some(process) => process.exit_code().map_err(launch_io)?,
                None => None,
            };
            match self.reach().await {
                SessionReach::Verified => return Ok(config.target()),
                SessionReach::Occupied => return Err(occupied()),
                // Our host may be busy accepting: keep waiting, and report
                // it if it never verifies.
                SessionReach::Unverified(reason) => last_unverified = Some(reason),
                SessionReach::Absent => {}
            }
            if let Some(code) = exit {
                *child = None;
                return Err(match refusal_of(code) {
                    Some(refusal) => LaunchError::SessionRefused(refusal),
                    None => LaunchError::Spawn(format!(
                        "the host exited during start-up (exit code {code})"
                    )),
                });
            }
            if Instant::now() >= deadline {
                // Not killed: it may be reclaiming an earlier run's leftovers.
                return Err(last_unverified.map_or(LaunchError::Timeout, |r| unverified(&r)));
            }
        }
    }
}

/// What answers on the session pipe. Only "no such pipe" counts as absent.
enum SessionReach {
    Verified,
    Absent,
    /// Something answered that is not this user's elevated host.
    Occupied,
    /// Something may be there but could not be verified (busy, no answer in
    /// time, any other error).
    Unverified(String),
}

/// `ERROR_FILE_NOT_FOUND` from opening the pipe (or a plain `NotFound`
/// without an OS code).
fn no_such_pipe(error: &io::Error) -> bool {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    match error.raw_os_error() {
        Some(code) => code == ERROR_FILE_NOT_FOUND,
        None => error.kind() == io::ErrorKind::NotFound,
    }
}

fn in_progress(rx: &watch::Receiver<Option<LaunchOutcome>>) -> bool {
    // A closed channel without an outcome is a launch task that was torn
    // down (runtime shutdown): not in progress.
    rx.borrow().is_none() && rx.has_changed().is_ok()
}

async fn outcome(mut rx: watch::Receiver<Option<LaunchOutcome>>) -> LaunchOutcome {
    match rx.wait_for(Option::is_some).await {
        Ok(done) => done
            .clone()
            .unwrap_or_else(|| Err(LaunchError::Io("no launch outcome".into()))),
        Err(_) => Err(LaunchError::Io(
            "the session host launch was interrupted".into(),
        )),
    }
}

fn occupied() -> LaunchError {
    LaunchError::SessionRefused(SessionRefusal::EndpointOccupied)
}

fn unverified(reason: &str) -> LaunchError {
    LaunchError::Io(format!(
        "the session host's endpoint could not be verified, so no host was started: {reason}"
    ))
}

fn refused(reason: &str) -> LaunchError {
    LaunchError::Io(format!(
        "the host endpoint failed verification or refused access: {reason}"
    ))
}

fn launch_io(error: io::Error) -> LaunchError {
    LaunchError::Io(error.to_string())
}

fn installed(program: &Path) -> Result<bool, LaunchError> {
    program.try_exists().map_err(launch_io)
}

#[async_trait]
impl HostLauncher for LocalHostLauncher {
    /// The service when it answers or is installed, else a session host or a
    /// user host that is already running. Never starts anything.
    async fn probe(&self) -> Result<Option<HostTarget>, LaunchError> {
        if let Some(service) = &self.service {
            match self.reach(&service.endpoint, &service.expectation).await {
                Reach::Verified => return Ok(Some(service.target())),
                Reach::Refused(reason) => return Err(refused(&reason)),
                Reach::Absent => {
                    if installed(&service.program)? {
                        return Ok(Some(service.target()));
                    }
                }
            }
        }
        if let Some(session) = &self.session {
            // A launch in progress (a UAC prompt may be open): its outcome.
            if let Some(pending) = session.pending() {
                return outcome(pending).await.map(Some);
            }
            match session.reach().await {
                SessionReach::Verified => return Ok(Some(session.parts.config.target())),
                SessionReach::Occupied => return Err(occupied()),
                SessionReach::Unverified(reason) => return Err(unverified(&reason)),
                SessionReach::Absent => {}
            }
        }
        if let Some(user) = &self.user {
            match self.reach(&user.endpoint, &user.expectation).await {
                Reach::Verified => return Ok(Some(user.target())),
                Reach::Refused(reason) => return Err(refused(&reason)),
                Reach::Absent => {}
            }
        }
        Ok(None)
    }

    async fn ensure(&self, want: HostMode) -> Result<HostTarget, LaunchError> {
        match want {
            HostMode::Service => self.ensure_service().await,
            HostMode::User => self.ensure_user().await,
            HostMode::ElevatedSession => self.ensure_session().await,
            other => Err(LaunchError::Unsupported(other)),
        }
    }
}

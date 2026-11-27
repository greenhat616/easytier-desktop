//! The elevated session host (doc#13 #choose #sequence #lifetime), Windows
//! only: `etd-host run --mode elevated-session`, started through one UAC
//! prompt when the UI runs unelevated, or directly when the UI is already
//! elevated, and reached on `\\.\pipe\easytier-desk-session-<SID>` with the
//! current-user-elevated identity check.
//!
//! The OS side (token elevation, `ShellExecuteEx runas`, the inheritance-free
//! direct start) is behind [`ElevationStarter`], implemented by the UI with
//! `etd-sysfx-os`; this module holds the decisions. Nothing here prompts on
//! its own: only [`crate::HostLauncher::ensure`] for the session form, which
//! the user's Connect triggers, starts a host.
use crate::{HostTarget, LaunchError, SessionRefusal};
use etd_contract::HostMode;
use etd_ipc::{Endpoint, ServerExpectation, ServerRequirement};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Command line of the elevated session host.
pub const SESSION_HOST_ARGS: [&str; 3] = ["run", "--mode", "elevated-session"];
/// Command line that reclaims the current user's session leftovers.
pub const RECLAIM_ARGS: [&str; 3] = ["reclaim", "--mode", "elevated-session"];
/// Command line that reclaims every user's session leftovers.
pub const RECLAIM_ALL_USERS_ARGS: [&str; 4] =
    ["reclaim", "--mode", "elevated-session", "--all-users"];

/// The session host's exit code for each refusal (etd-host `SessionRefusal`).
pub fn refusal_of(exit_code: u32) -> Option<SessionRefusal> {
    match exit_code {
        3 => Some(SessionRefusal::ServiceInstalled),
        4 => Some(SessionRefusal::NotConforming),
        5 => Some(SessionRefusal::OtherUsersLeftovers),
        6 => Some(SessionRefusal::EndpointOccupied),
        _ => None,
    }
}

/// The elevated session host started by the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedSessionConfig {
    /// Absolute path of the sibling `etd-host` executable.
    pub program: PathBuf,
    pub endpoint: Endpoint,
    pub expectation: ServerExpectation,
}

impl ElevatedSessionConfig {
    /// The current user's session endpoint. Windows only.
    pub fn standard(program: PathBuf) -> io::Result<Self> {
        let user = etd_ipc::platform::current_user()?;
        let endpoint = session_endpoint(&user)?;
        let expectation = ServerExpectation {
            exe_dir: program.parent().map(Path::to_path_buf).unwrap_or_default(),
            requirement: ServerRequirement::CurrentUserElevated,
        };
        Ok(Self {
            program,
            endpoint,
            expectation,
        })
    }

    pub fn target(&self) -> HostTarget {
        HostTarget {
            mode: HostMode::ElevatedSession,
            endpoint: self.endpoint.clone(),
            expectation: self.expectation.clone(),
        }
    }
}

fn session_endpoint(user: &etd_ipc::OsUserId) -> io::Result<Endpoint> {
    match user {
        etd_ipc::OsUserId::WindowsSid(sid) if cfg!(windows) => Ok(Endpoint::NamedPipe(format!(
            r"\\.\pipe\easytier-desk-session-{sid}"
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the elevated session host exists on Windows only",
        )),
    }
}

/// The elevation of the UI's own token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiElevation {
    /// A split-token administrator running unelevated: one UAC prompt.
    Limited,
    /// Already elevated ("Run as administrator", or UAC off).
    Elevated,
    /// A standard account: the session form is not offered (msg#1408).
    Standard,
}

/// A process started through an [`ElevationStarter`].
pub trait StartedProcess: Send {
    /// The exit code once it has ended, `None` while it runs.
    fn exit_code(&mut self) -> io::Result<Option<u32>>;
}

#[derive(Debug)]
pub enum StartError {
    /// The user declined the UAC prompt.
    Cancelled,
    Failed(io::Error),
}

/// Starts programs elevated. Implementations take an absolute program and
/// fixed arguments, open no window and pass no handles.
pub trait ElevationStarter: Send + Sync {
    fn elevation(&self) -> io::Result<UiElevation>;
    /// `runas` through the UAC consent prompt. Blocks until it was answered.
    fn start_with_consent(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError>;
    /// From an elevated UI: no inherited handles, a minimal environment.
    fn start_direct(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<Box<dyn StartedProcess>, StartError>;
}

/// Start `program` elevated the way the session host is started (doc#13
/// #choose): one UAC prompt from an unelevated administrator, a direct start
/// from an elevated UI, nothing for a standard account. Blocks while the
/// prompt is shown; call it on a blocking worker.
pub fn start_elevated(
    starter: &dyn ElevationStarter,
    program: &Path,
    args: &[&str],
) -> Result<Box<dyn StartedProcess>, LaunchError> {
    let elevation = starter
        .elevation()
        .map_err(|error| LaunchError::Io(format!("cannot read this process's token: {error}")))?;
    let started = match elevation {
        UiElevation::Limited => starter.start_with_consent(program, args),
        UiElevation::Elevated => starter.start_direct(program, args),
        UiElevation::Standard => return Err(LaunchError::Unsupported(HostMode::ElevatedSession)),
    };
    started.map_err(|error| match error {
        StartError::Cancelled => LaunchError::ElevationDenied,
        StartError::Failed(error) => LaunchError::Spawn(error.to_string()),
    })
}

/// The session form of [`crate::launcher_user::LocalHostLauncher`].
#[derive(Clone)]
pub struct SessionParts {
    pub config: ElevatedSessionConfig,
    pub starter: Arc<dyn ElevationStarter>,
}

/// `etd-host reclaim --mode elevated-session [--all-users]` started the same
/// way as the host (one UAC prompt when unelevated) and waited for up to
/// `limit`. Runs no instance (doc#13 #lifetime "clean up leftovers").
/// Blocking: call it off the UI thread.
pub fn reclaim_session_leftovers(
    starter: &dyn ElevationStarter,
    program: &Path,
    all_users: bool,
    limit: Duration,
) -> Result<(), LaunchError> {
    let args: &[&str] = if all_users {
        &RECLAIM_ALL_USERS_ARGS
    } else {
        &RECLAIM_ARGS
    };
    let mut process = start_elevated(starter, program, args)?;
    let deadline = std::time::Instant::now() + limit;
    loop {
        match process
            .exit_code()
            .map_err(|error| LaunchError::Io(error.to_string()))?
        {
            Some(0) => return Ok(()),
            Some(code) => {
                return Err(match refusal_of(code) {
                    Some(refusal) => LaunchError::SessionRefused(refusal),
                    None => LaunchError::Spawn(format!(
                        "the clean-up did not finish (exit code {code}); system changes may remain"
                    )),
                });
            }
            None if std::time::Instant::now() >= deadline => return Err(LaunchError::Timeout),
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// The first-run choice in simple mode (doc#13 #choose): install the system
/// service, or ask for administrator permission each time the user connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostChoice {
    Service,
    ElevatedSession,
}

impl HostChoice {
    fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::ElevatedSession => "elevated-session",
        }
    }
}

/// Where the [`HostChoice`] is kept: one word in a file beside the profile
/// library. A missing or unreadable file means "not chosen yet".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChoiceFile {
    path: PathBuf,
}

impl HostChoiceFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `host-choice` beside the default `profiles.toml`.
    pub fn default_path() -> Option<PathBuf> {
        crate::profiles_toml::TomlProfileStore::default_path()
            .and_then(|profiles| profiles.parent().map(|dir| dir.join("host-choice")))
    }

    pub fn load(&self) -> Option<HostChoice> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        [HostChoice::Service, HostChoice::ElevatedSession]
            .into_iter()
            .find(|choice| text.trim() == choice.as_str())
    }

    pub fn save(&self, choice: HostChoice) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&self.path, choice.as_str())
    }
}

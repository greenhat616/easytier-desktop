//! Composition root helpers: real gRPC client factory (`GrpcHostClient` + `LocalConnector`),
//! elevation-aware `LocalHostLauncher` (with the elevated session form on Windows),
//! `TomlProfileStore`, the service installation command and the session clean-up.

use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use async_trait::async_trait;
use etd_app::launcher_session::CleanupError;
use etd_app::{
    AppServices, HostClientFactory, HostLauncher, HostTarget, LaunchError, ProfileStore,
    launcher_session::{ElevationStarter, UiElevation},
    launcher_user::{LocalHostLauncher, ServiceHostConfig, UserHostConfig},
    profiles_toml::TomlProfileStore,
};
use etd_client::{
    HostClient,
    grpc::{ClientOptions, GrpcHostClient},
};
use etd_contract::HostMode;
use etd_ipc::{OsUserId, platform::LocalConnector};
use etd_sysfx_os::service::{NativeServiceManager, ServiceManager};

/// Marker phrase used when an elevated process refuses to start a user-mode host.
pub const ELEVATED_USER_HOST_MESSAGE: &str =
    "an elevated process cannot start a user host; use the installed system service instead";

/// Real [`HostClientFactory`] wired to [`GrpcHostClient`] + [`LocalConnector`].
#[derive(Debug, Clone, Default)]
pub struct LocalGrpcClientFactory {
    options: ClientOptions,
}

impl LocalGrpcClientFactory {
    pub fn new(options: ClientOptions) -> Self {
        Self { options }
    }
}

impl HostClientFactory for LocalGrpcClientFactory {
    fn connect(&self, target: &HostTarget) -> Arc<dyn HostClient> {
        let connector = Arc::new(LocalConnector {
            expectation: target.expectation.clone(),
        });
        Arc::new(GrpcHostClient::new(
            connector,
            target.endpoint.clone(),
            self.options.clone(),
        ))
    }
}

/// Wraps a [`HostLauncher`] and refuses [`HostMode::User`] when the UI runs with
/// elevated privileges, matching `etd-host`'s security boundary so the UI can
/// immediately offer the system service instead. The elevated session form
/// stays available to an elevated UI (started directly, doc#13 #choose).
pub struct ElevatedAwareLauncher {
    inner: Arc<dyn HostLauncher>,
    elevated: bool,
}

impl ElevatedAwareLauncher {
    pub fn new(inner: Arc<dyn HostLauncher>, elevated: bool) -> Self {
        Self { inner, elevated }
    }

    pub fn is_elevated(&self) -> bool {
        self.elevated
    }
}

#[async_trait]
impl HostLauncher for ElevatedAwareLauncher {
    async fn probe(&self) -> Result<Option<HostTarget>, LaunchError> {
        self.inner.probe().await
    }

    async fn ensure(&self, want: HostMode) -> Result<HostTarget, LaunchError> {
        if self.elevated && want == HostMode::User {
            return Err(LaunchError::Spawn(ELEVATED_USER_HOST_MESSAGE.to_owned()));
        }
        self.inner.ensure(want).await
    }
}

/// Returns whether the current desktop UI process is running with elevated privileges.
pub fn is_process_elevated() -> bool {
    NativeServiceManager.entry_is_elevated().unwrap_or(false)
}

/// Platform filename of the bundled host executable.
pub fn host_binary_name() -> &'static str {
    if cfg!(windows) {
        "etd-host.exe"
    } else {
        "etd-host"
    }
}

/// Sibling `etd-host` binary located alongside the current `etd-ui` executable.
pub fn sibling_host_binary() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(host_binary_name())))
}

/// Expected protected path of an installed service `etd-host` executable.
pub fn installed_service_binary() -> Option<PathBuf> {
    etd_sysfx_os::service::installed_host_dir()
        .ok()
        .map(|dir| dir.join(host_binary_name()))
}

/// Constructs the real [`TomlProfileStore`] at the user's configuration directory.
pub fn default_profile_store() -> io::Result<Arc<dyn ProfileStore>> {
    let path = TomlProfileStore::default_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine user configuration directory for profiles.toml",
        )
    })?;
    Ok(Arc::new(TomlProfileStore::new(path)))
}

/// Builds the production [`AppServices`] (`GrpcHostClient + LocalConnector`,
/// elevation-aware `LocalHostLauncher`, `TomlProfileStore`).
pub fn build_local_services() -> io::Result<(AppServices, bool)> {
    let elevated = is_process_elevated();
    let service = installed_service_binary().map(ServiceHostConfig::standard);
    let user = if elevated {
        None
    } else {
        sibling_host_binary().and_then(|program| UserHostConfig::standard(program).ok())
    };
    let mut local_launcher = LocalHostLauncher::new(service, user);
    if let Some(session) = session_parts() {
        local_launcher = local_launcher.with_session(session);
    }
    let local_launcher = Arc::new(local_launcher);
    let launcher: Arc<dyn HostLauncher> =
        Arc::new(ElevatedAwareLauncher::new(local_launcher, elevated));
    let profiles = default_profile_store()?;
    let clients: Arc<dyn HostClientFactory> = Arc::new(LocalGrpcClientFactory::default());
    Ok((
        AppServices {
            clients,
            launcher,
            profiles,
        },
        elevated,
    ))
}

/// The elevated session form: Windows, with the sibling `etd-host`.
fn session_parts() -> Option<etd_app::launcher_session::SessionParts> {
    #[cfg(windows)]
    {
        let program = sibling_host_binary()?;
        let config = etd_app::launcher_session::ElevatedSessionConfig::standard(program).ok()?;
        Some(etd_app::launcher_session::SessionParts {
            config,
            starter: Arc::new(WindowsElevationStarter),
            choice: etd_app::launcher_session::HostChoiceFile::default_path()
                .map(etd_app::launcher_session::HostChoiceFile::new),
        })
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The main window's HWND while it is open: the owner of UAC prompts, so they
/// come to the foreground. 0 while there is none.
#[cfg(windows)]
static PROMPT_OWNER: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

#[cfg(windows)]
fn prompt_owner() -> Option<std::num::NonZeroIsize> {
    std::num::NonZeroIsize::new(PROMPT_OWNER.load(std::sync::atomic::Ordering::Relaxed))
}

/// Records `window` as the owner of UAC prompts (Windows; elsewhere nothing).
pub fn set_prompt_owner(window: &gpui_kit::Window) {
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        if let Ok(handle) = HasWindowHandle::window_handle(window)
            && let RawWindowHandle::Win32(handle) = handle.as_raw()
        {
            PROMPT_OWNER.store(handle.hwnd.get(), std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[cfg(not(windows))]
    let _ = window;
}

/// The main window is gone: prompts have no owner.
pub fn clear_prompt_owner() {
    #[cfg(windows)]
    PROMPT_OWNER.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// The elevation of this UI process, `None` where there is no session form.
pub fn ui_elevation() -> Option<UiElevation> {
    #[cfg(windows)]
    {
        WindowsElevationStarter.elevation().ok()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// [`ElevationStarter`] on `etd-sysfx-os`: `ShellExecuteEx runas` with
/// `SW_HIDE` (the OS creates the process; no environment or handle control),
/// or, from an elevated UI, `CreateProcessW` without inherited handles and
/// with a minimal environment.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsElevationStarter;

#[cfg(windows)]
struct StartedHost(etd_sysfx_os::windows::elevation::HostProcess);

#[cfg(windows)]
impl etd_app::launcher_session::StartedProcess for StartedHost {
    fn exit_code(&mut self) -> io::Result<Option<u32>> {
        self.0.exit_code()
    }
}

#[cfg(windows)]
impl ElevationStarter for WindowsElevationStarter {
    fn elevation(&self) -> io::Result<UiElevation> {
        use etd_sysfx_os::windows::elevation::{Elevation, elevation};
        Ok(match elevation()? {
            Elevation::Limited => UiElevation::Limited,
            Elevation::Elevated => UiElevation::Elevated,
            Elevation::Standard => UiElevation::Standard,
        })
    }

    fn start_with_consent(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<
        Box<dyn etd_app::launcher_session::StartedProcess>,
        etd_app::launcher_session::StartError,
    > {
        use etd_sysfx_os::windows::elevation::{ERROR_CANCELLED, start_with_consent};
        start_with_consent(prompt_owner(), program, args)
            .map(|process| Box::new(StartedHost(process)) as _)
            .map_err(|error| {
                if error.raw_os_error() == Some(ERROR_CANCELLED) {
                    etd_app::launcher_session::StartError::Cancelled
                } else {
                    etd_app::launcher_session::StartError::Failed(error)
                }
            })
    }

    fn start_direct(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<
        Box<dyn etd_app::launcher_session::StartedProcess>,
        etd_app::launcher_session::StartError,
    > {
        etd_sysfx_os::windows::elevation::start_direct(program, args)
            .map(|process| Box::new(StartedHost(process)) as _)
            .map_err(etd_app::launcher_session::StartError::Failed)
    }
}

/// Cleans up what a crashed elevated session host left behind (doc#13
/// #lifetime): `etd-host reclaim --mode elevated-session [--all-users]`,
/// started like the session host (one UAC prompt when unelevated).
pub trait SessionCleaner: Send + Sync {
    /// Blocking until any prompt is answered; called on a thread of its own
    /// ([`etd_app::launcher_session::on_own_thread`]).
    fn clean_up(&self, all_users: bool) -> Result<(), CleanupError>;
}

/// The sibling `etd-host`, Windows only.
pub struct PlatformSessionCleaner {
    starter: Option<Arc<dyn ElevationStarter>>,
    program: Option<PathBuf>,
}

impl PlatformSessionCleaner {
    pub fn detect() -> Self {
        #[cfg(windows)]
        let starter: Option<Arc<dyn ElevationStarter>> = Some(Arc::new(WindowsElevationStarter));
        #[cfg(not(windows))]
        let starter: Option<Arc<dyn ElevationStarter>> = None;
        Self {
            starter,
            program: sibling_host_binary(),
        }
    }
}

impl SessionCleaner for PlatformSessionCleaner {
    fn clean_up(&self, all_users: bool) -> Result<(), CleanupError> {
        let (Some(starter), Some(program)) = (&self.starter, &self.program) else {
            return Err(CleanupError::Unsupported);
        };
        etd_app::launcher_session::reclaim_session_leftovers(
            starter.as_ref(),
            program,
            all_users,
            std::time::Duration::from_secs(300),
        )
    }
}

/// Injectable service installer invoked when the user accepts the UI's offer to
/// install the system service (`NotInstalled` or elevated user-host refusal).
pub trait ServiceInstaller: Send + Sync {
    /// Human-readable command shown in the UI for transparency / manual fallback.
    fn command_preview(&self) -> String;

    /// Runs `etd-host install --allow-user <current-user>` (blocking; called on a
    /// background executor off the GPUI UI thread).
    fn install(&self) -> Result<(), String>;
}

/// Real platform service installer that runs the sibling `etd-host install`.
#[derive(Debug, Clone)]
pub struct PlatformServiceInstaller {
    host_binary: Option<PathBuf>,
    allow_user: Option<String>,
    elevated: bool,
}

impl PlatformServiceInstaller {
    pub fn detect() -> Self {
        let host_binary = sibling_host_binary();
        let allow_user = current_user_allow_arg().ok();
        let elevated = is_process_elevated();
        Self {
            host_binary,
            allow_user,
            elevated,
        }
    }

    pub fn with_parts(
        host_binary: Option<PathBuf>,
        allow_user: Option<String>,
        elevated: bool,
    ) -> Self {
        Self {
            host_binary,
            allow_user,
            elevated,
        }
    }

    fn resolved_args(&self) -> Result<(PathBuf, Vec<String>), String> {
        let binary = self
            .host_binary
            .clone()
            .filter(|path| path.exists())
            .ok_or_else(|| {
                format!(
                    "could not locate {} next to the UI executable",
                    host_binary_name()
                )
            })?;
        let mut args = vec!["install".to_owned()];
        if let Some(user) = &self.allow_user {
            args.push("--allow-user".to_owned());
            args.push(user.clone());
        }
        Ok((binary, args))
    }
}

impl ServiceInstaller for PlatformServiceInstaller {
    fn command_preview(&self) -> String {
        let bin = self
            .host_binary
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| host_binary_name().to_owned());
        let allow = self
            .allow_user
            .as_deref()
            .map(|u| format!(" --allow-user {u}"))
            .unwrap_or_default();
        if cfg!(windows) {
            format!("\"{bin}\" install{allow}")
        } else {
            format!("sudo \"{bin}\" install{allow}")
        }
    }

    fn install(&self) -> Result<(), String> {
        let (binary, args) = self.resolved_args()?;
        if self.elevated {
            return run_direct(&binary, &args);
        }
        run_elevated(&binary, &args)
    }
}

fn current_user_allow_arg() -> io::Result<String> {
    match etd_ipc::platform::current_user()? {
        OsUserId::WindowsSid(sid) => Ok(sid),
        OsUserId::UnixUid(uid) => Ok(uid.to_string()),
        _ => Err(io::Error::other("unsupported OS user identifier")),
    }
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run_direct(binary: &Path, args: &[String]) -> Result<(), String> {
    let mut command = Command::new(binary);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, CREATE_NO_WINDOW);
    let output = command
        .args(args)
        .output()
        .map_err(|error| format!("failed to launch {}: {error}", binary.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        Err(format!("service install exited with {}", output.status))
    } else {
        Err(stderr)
    }
}

#[cfg(windows)]
fn run_elevated(binary: &Path, args: &[String]) -> Result<(), String> {
    fn ps_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }
    let file_path = ps_quote(&binary.to_string_lossy());
    let arg_list = args
        .iter()
        .map(|arg| ps_quote(arg))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "$p = Start-Process -FilePath {file_path} -ArgumentList @({arg_list}) -Verb RunAs -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode"
    );
    let mut command = Command::new("powershell.exe");
    std::os::windows::process::CommandExt::creation_flags(&mut command, CREATE_NO_WINDOW);
    let output = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|error| format!("failed to invoke UAC elevation prompt: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.is_empty() {
            Err(format!(
                "elevated service install failed ({})",
                output.status
            ))
        } else {
            Err(stderr)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_elevated(binary: &Path, args: &[String]) -> Result<(), String> {
    // no-window: Linux only
    let mut cmd = Command::new("pkexec");
    cmd.arg(binary).args(args);
    let output = cmd.output().map_err(|error| {
        format!(
            "failed to invoke pkexec ({error}); run manually: sudo \"{}\" {}",
            binary.display(),
            args.join(" ")
        )
    })?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.is_empty() {
            Err(format!("pkexec install failed ({})", output.status))
        } else {
            Err(stderr)
        }
    }
}

#[cfg(target_os = "macos")]
fn run_elevated(binary: &Path, args: &[String]) -> Result<(), String> {
    fn sh_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
    let mut parts = vec![sh_quote(&binary.to_string_lossy())];
    parts.extend(args.iter().map(|arg| sh_quote(arg)));
    let shell_cmd = parts.join(" ");
    let escaped_for_as = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped_for_as}\" with administrator privileges");
    // no-window: macOS only
    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|error| format!("failed to invoke administrator prompt: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.is_empty() {
            Err(format!("administrator install failed ({})", output.status))
        } else {
            Err(stderr)
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn run_elevated(binary: &Path, args: &[String]) -> Result<(), String> {
    Err(format!(
        "automatic elevation is unavailable on this platform; run manually: \"{}\" {}",
        binary.display(),
        args.join(" ")
    ))
}

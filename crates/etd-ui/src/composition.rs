//! Composition root helpers: real gRPC client factory (`GrpcHostClient` + `LocalConnector`),
//! elevation-aware `LocalHostLauncher`, `TomlProfileStore`, and service installation command.

use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use async_trait::async_trait;
use etd_app::{
    AppServices, HostClientFactory, HostLauncher, HostTarget, LaunchError, ProfileStore,
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
/// immediately offer the system service instead.
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
    let local_launcher = Arc::new(LocalHostLauncher::new(service, user));
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

fn run_direct(binary: &Path, args: &[String]) -> Result<(), String> {
    let output = Command::new(binary)
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
        "$p = Start-Process -FilePath {file_path} -ArgumentList @({arg_list}) -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
    );
    let output = Command::new("powershell.exe")
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

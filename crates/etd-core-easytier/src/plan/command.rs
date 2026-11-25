//! Command line of `easytier-core` (c97f36b, `easytier/src/core.rs`).
//!
//! Only process-level options go on the command line: the configuration
//! file, the management portal and logging. Any `NetworkOptions` flag would
//! make upstream merge CLI values into the file (`can_merge`), so none is
//! passed; the environment is left empty for the same reason (every option
//! also reads an `ET_*` variable).
use etd_core_api::ManagementGuard;
use etd_proc::Command;
use std::{ffi::OsString, net::SocketAddr, path::Path};

/// Name of the generated configuration inside the epoch directory.
pub const CONFIG_FILE: &str = "config.toml";

/// Whitelist entry no TCP client can come from: the limited-broadcast
/// address is never a connection source, so the management hook
/// (`easytier-core/src/management/rpc_server_hook.rs`) rejects every
/// client. An empty list cannot be expressed on the command line.
pub const DENY_ALL_WHITELIST: &str = "255.255.255.255/32";

/// Console log level; the host captures stdout and stderr.
const CONSOLE_LOG_LEVEL: &str = "info";

/// The management whitelist for a guard: the exact loopback address the
/// portal listens on (tighter than upstream's default 127.0.0.0/8 + ::1),
/// or nothing at all for deny-all.
pub fn whitelist(guard: ManagementGuard, management: SocketAddr) -> String {
    match guard {
        ManagementGuard::DenyAll => DENY_ALL_WHITELIST.to_owned(),
        _ => match management.ip() {
            std::net::IpAddr::V4(ip) => format!("{ip}/32"),
            std::net::IpAddr::V6(ip) => format!("{ip}/128"),
        },
    }
}

pub fn command(
    binary: &Path,
    runtime_dir: &Path,
    management: SocketAddr,
    guard: ManagementGuard,
) -> Command {
    let config = runtime_dir.join(CONFIG_FILE);
    let args: Vec<OsString> = vec![
        "-c".into(),
        config.into_os_string(),
        // Full address: a bare port would bind 0.0.0.0 (`parse_rpc_portal`).
        "--rpc-portal".into(),
        management.to_string().into(),
        "--rpc-portal-whitelist".into(),
        whitelist(guard, management).into(),
        // `${VAR}` in the file must stay literal.
        "--disable-env-parsing".into(),
        "--console-log-level".into(),
        CONSOLE_LOG_LEVEL.into(),
        // The file logger is reloadable and is created even when off; keep
        // `easytier.log` inside the epoch directory.
        "--file-log-dir".into(),
        runtime_dir.as_os_str().to_owned(),
    ];
    Command {
        executable: binary.to_owned(),
        args,
        env: Vec::new(),
        cwd: Some(runtime_dir.to_owned()),
    }
}

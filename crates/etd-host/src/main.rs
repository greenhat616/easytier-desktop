//! The host binary: composition root (HR).
//!
//! CLI notes (frozen rule, F0): maintenance subcommands that change the
//! kernel store (install or remove a kernel version) and `reclaim --all
//! --purge` run only with the service stopped. They take the machine-wide
//! singleton lock themselves, so they are the only ledger writer; if the
//! lock is held they refuse and tell the administrator to stop the service.
//! Removing a kernel: `ReclaimEngine::reclaim_core`, then
//! `CoreStore::remove` only if no core-binary record is pending.

mod host;
mod storage;
mod unavailable;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use etd_contract::HostMode;
use std::process::ExitCode;

/// How long a finished host waits for blocking work still running in its
/// runtime (a system query past its own deadline) before exiting anyway.
const RUNTIME_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Parser)]
#[command(
    name = "etd-host",
    version,
    about = "EasyTier Desktop host",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[arg(long, hide = true)]
    console_ctrl: Option<u32>,
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
enum Mode {
    User,
    Service,
}
impl From<Mode> for HostMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::User => Self::User,
            Mode::Service => Self::Service,
        }
    }
}

#[derive(Subcommand)]
enum Action {
    /// Run a local authenticated host.
    Run {
        #[arg(long, value_enum, default_value = "user")]
        mode: Mode,
    },
    /// Install the system service (requires administrator privileges).
    Install {
        #[arg(long, value_name = "SID_OR_UID")]
        allow_user: Vec<String>,
    },
    /// Stop, reclaim and remove the installed service.
    Uninstall {
        /// Report the durable uninstall phase and deferred worker outcome.
        #[arg(long, conflicts_with_all = ["wait_parent", "install_id"])]
        status: bool,
        #[arg(long, hide = true, requires = "install_id")]
        wait_parent: Option<u32>,
        #[arg(long, hide = true, requires = "wait_parent")]
        install_id: Option<String>,
    },
    /// Re-enable a service disabled by an incomplete uninstall (before reclaim finished).
    ResumeService,
    /// Check and reclaim ownership records while the host is stopped.
    Reclaim {
        #[arg(long, value_enum, default_value = "service")]
        mode: Mode,
        #[arg(long)]
        all: bool,
        #[arg(long, requires = "all")]
        purge: bool,
    },
    /// Read-only diagnostic information (no special privileges required).
    Doctor,
    /// Remove a stored kernel after reclaiming its binary-scoped records.
    RemoveCore {
        version: String,
        #[arg(long, value_enum, default_value = "service")]
        mode: Mode,
    },
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("etd-host: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<()> {
    if let Some(pid) = cli.console_ctrl {
        return etd_proc::console_ctrl::send_ctrl_c(pid).context("console helper failed");
    }
    let Some(command) = cli.command else {
        bail!("a command is required; see --help")
    };
    #[cfg(windows)]
    if matches!(
        &command,
        Action::Run {
            mode: Mode::Service
        }
    ) {
        return etd_sysfx_os::service::dispatch_service(|stop| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(host::run_until(HostMode::Service, Some(stop)));
            // Dropping a runtime waits for every blocking task without
            // limit; one stuck in a system call must not keep the service
            // from reporting STOPPED.
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
            result.map_err(|error| std::io::Error::other(format!("{error:#}")))
        })
        .context("Windows service dispatcher");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match command {
        Action::Doctor => host::doctor(),
        Action::Run { mode } => {
            let result = runtime.block_on(host::run(mode.into()));
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
            result
        }
        Action::Reclaim { mode, all, purge } => {
            runtime.block_on(host::reclaim(mode.into(), all, purge))
        }
        Action::RemoveCore { mode, version } => {
            runtime.block_on(host::remove_core(mode.into(), &version))
        }
        Action::Install { allow_user } => runtime.block_on(host::install(&allow_user)),
        Action::Uninstall {
            status,
            wait_parent,
            install_id,
        } => {
            if status {
                return host::uninstall_status();
            }
            if let (Some(pid), Some(id)) = (wait_parent, install_id) {
                #[cfg(windows)]
                {
                    return host::finish_deferred_uninstall(pid, &id);
                }
                #[cfg(not(windows))]
                {
                    let _ = (pid, id);
                    bail!("uninstall worker is Windows-only");
                }
            }
            runtime.block_on(host::uninstall())
        }
        Action::ResumeService => runtime.block_on(host::resume_service()),
    }
}

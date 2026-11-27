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

/// An installer tag: 1 to 64 ASCII letters, digits, braces, hyphens,
/// underscores or dots (an MSI ProductCode fits).
fn owner_tag(value: &str) -> Result<String, String> {
    let valid = (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'{' | b'}' | b'-' | b'_' | b'.'));
    if valid {
        Ok(value.to_owned())
    } else {
        Err("expected 1-64 letters, digits, braces, hyphens, underscores or dots".into())
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
        /// One more administrator: an account SID (S-1-5-21-..., RID 1000
        /// or above) on Windows, a UID elsewhere. Repeatable.
        #[arg(long, value_name = "SID_OR_UID")]
        allow_user: Vec<String>,
        /// Record who installs (an MSI passes its ProductCode); see
        /// `uninstall --only-owner`.
        #[arg(long, value_name = "TAG", value_parser = owner_tag)]
        owner: Option<String>,
    },
    /// Replace the installed service with this build, keeping its state
    /// (requires administrator privileges; run from the new payload).
    Upgrade,
    /// Stop, reclaim and remove the installed service.
    Uninstall {
        /// Report the durable uninstall phase and deferred worker outcome.
        #[arg(long, conflicts_with_all = ["wait_parent", "install_id"])]
        status: bool,
        #[arg(long, hide = true, requires = "install_id")]
        wait_parent: Option<u32>,
        #[arg(long, hide = true, requires = "wait_parent")]
        install_id: Option<String>,
        /// Uninstall only an installation recorded with this owner; when
        /// there is none, do nothing and succeed (an installer's rollback).
        #[arg(long, value_name = "TAG", value_parser = owner_tag,
              conflicts_with_all = ["status", "wait_parent", "install_id"])]
        only_owner: Option<String>,
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
            // The lock goes only after the runtime is down.
            let (exit, settled) =
                run_bounded(runtime, host::run_until(HostMode::Service, Some(stop)));
            exit.finish(settled)
                .map_err(|error| std::io::Error::other(format!("{error:#}")))
        })
        .context("Windows service dispatcher");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match command {
        Action::Doctor => host::doctor(),
        Action::Run { mode } => {
            let (exit, settled) = run_bounded(runtime, host::run(mode.into()));
            exit.finish(settled)
        }
        Action::Reclaim { mode, all, purge } => {
            run_bounded(runtime, host::reclaim(mode.into(), all, purge)).0
        }
        Action::RemoveCore { mode, version } => {
            run_bounded(runtime, host::remove_core(mode.into(), &version)).0
        }
        Action::Install { allow_user, owner } => {
            run_bounded(runtime, host::install(&allow_user, owner)).0
        }
        Action::Upgrade => run_bounded(runtime, host::upgrade::upgrade()).0,
        Action::Uninstall {
            status,
            wait_parent,
            install_id,
            only_owner,
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
            run_bounded(runtime, host::uninstall(only_owner.as_deref())).0
        }
        Action::ResumeService => run_bounded(runtime, host::resume_service()).0,
    }
}

/// Run `work` on `runtime`, then shut the runtime down within
/// [`host::RUNTIME_SHUTDOWN`]. Dropping a runtime waits for its blocking
/// tasks without limit: one stuck in a system call (an SCM or registry read,
/// a management query) must never hold the process from exiting, whatever
/// the command. Also returns whether the runtime settled: every thread
/// ended before the timeout (`shutdown_timeout` returns early then).
fn run_bounded<T>(
    runtime: tokio::runtime::Runtime,
    work: impl std::future::Future<Output = T>,
) -> (T, bool) {
    let output = runtime.block_on(work);
    let started = std::time::Instant::now();
    runtime.shutdown_timeout(host::RUNTIME_SHUTDOWN);
    (output, started.elapsed() < host::RUNTIME_SHUTDOWN)
}

#[cfg(test)]
mod run_bounded_tests {
    use super::*;

    #[test]
    fn a_stuck_blocking_task_does_not_hold_the_exit() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let started = std::time::Instant::now();
        let (output, settled) = run_bounded(runtime, async {
            // Never awaited to completion: stands in for a system call that
            // does not return.
            let _task = tokio::task::spawn_blocking(move || {
                let _ = stuck.recv_timeout(std::time::Duration::from_secs(60));
            });
            7
        });
        let took = started.elapsed();
        drop(release);
        assert_eq!(output, 7);
        assert!(!settled, "the stuck task is reported");
        assert!(
            took < host::RUNTIME_SHUTDOWN + std::time::Duration::from_secs(1),
            "took {took:?}"
        );
    }

    #[test]
    fn a_runtime_without_stuck_work_settles() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_, settled) = run_bounded(runtime, async {
            tokio::task::spawn_blocking(|| ()).await.unwrap();
        });
        assert!(settled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn owner_tags_take_a_product_code_and_nothing_that_splits_a_command_line() {
        Cli::command().debug_assert();
        let code = "{89AB7D73-819C-4BB3-BA52-DCB90C01C4ED}";
        assert_eq!(owner_tag(code).unwrap(), code);
        for bad in ["", "a b", "a\"b", "a;b", &"x".repeat(65)] {
            assert!(owner_tag(bad).is_err(), "{bad}");
        }
        let cli = Cli::try_parse_from(["etd-host", "uninstall", "--only-owner", code]).unwrap();
        assert!(
            matches!(cli.command, Some(Action::Uninstall { only_owner: Some(ref o), .. }) if o == code)
        );
        assert!(
            Cli::try_parse_from(["etd-host", "uninstall", "--only-owner", code, "--status"])
                .is_err()
        );
    }
}

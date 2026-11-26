//! Command-line grammar.
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const EXIT_CODES: &str = "\
Exit codes:
  0  success (for apply, start and stop: the host durably accepted the request)
  1  internal or local I/O error
  2  invalid arguments or configuration file
  3  host unavailable; a state change may or may not have been accepted
  4  the endpoint is served by a process that failed host verification
  5  contract major version mismatch: upgrade the service
  6  permission denied or elevation required
  7  revision conflict, or request id reused with different content
  8  rejected by the host
  9  the host does not offer the needed capability";

/// Control an EasyTier Desktop host.
#[derive(Debug, Parser)]
#[command(name = "etd-ctl", version, after_help = EXIT_CODES)]
pub struct Cli {
    /// Print machine-readable JSON (errors go to stderr as JSON too).
    #[arg(long, global = true)]
    pub json: bool,
    /// Which host to talk to.
    #[arg(long, global = true, value_enum, default_value_t = HostKind::Service)]
    pub host: HostKind,
    /// Named pipe (Windows) or socket path overriding the host's default.
    #[arg(long, global = true, value_name = "ENDPOINT")]
    pub endpoint: Option<String>,
    /// Directory the host executable must run from. Default: the install
    /// directory for the service host, etd-ctl's own for the user host.
    #[arg(long, global = true, value_name = "DIR")]
    pub host_dir: Option<PathBuf>,
    /// Seconds to wait for the connection, and for each reply.
    #[arg(long, global = true, value_name = "SECONDS", default_value_t = 10,
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HostKind {
    /// The installed system service.
    Service,
    /// The current user's own host.
    User,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the host and its instances.
    Status {
        /// Only this instance.
        instance: Option<String>,
    },
    /// Create or replace an instance configuration.
    Apply(ApplyArgs),
    /// Set an instance's desired state to running.
    Start {
        instance: String,
        /// Restart an instance the host gave up on (state gave_up).
        #[arg(long)]
        retry: bool,
        #[command(flatten)]
        replay: Replay,
    },
    /// Set an instance's desired state to stopped.
    Stop {
        instance: String,
        #[command(flatten)]
        replay: Replay,
    },
    /// Print log lines of an instance, or of the host itself.
    Logs {
        /// Instance id; the host's own log when omitted.
        instance: Option<String>,
        /// Past lines to print first.
        #[arg(long, value_name = "LINES", default_value_t = 100)]
        tail: u32,
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
    },
    /// Show what is left to reclaim and what awaits an administrator.
    ReclaimReport,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// JSON file with the network configuration; "-" reads standard input.
    #[arg(short, long, value_name = "FILE")]
    pub file: PathBuf,
    /// Instance to replace; a new instance id is generated when omitted.
    #[arg(long, value_name = "ID")]
    pub instance: Option<String>,
    /// Also set the desired state to running.
    #[arg(long, conflicts_with = "stop")]
    pub start: bool,
    /// Also set the desired state to stopped.
    #[arg(long)]
    pub stop: bool,
    #[command(flatten)]
    pub replay: Replay,
}

/// Repeats an earlier request whose outcome is unknown. The host recognises
/// it only if id, revision and content are all unchanged.
#[derive(Debug, Args)]
pub struct Replay {
    /// Request id of the earlier attempt.
    #[arg(long, value_name = "ID", requires = "expected_revision")]
    pub request_id: Option<String>,
    /// Revision the change is based on; the current one when omitted.
    #[arg(long, value_name = "REVISION")]
    pub expected_revision: Option<u64>,
}

//! `etd-ctl`: command-line client of an etd host. It only speaks the local
//! contract through [`etd_client::HostClient`], never to a kernel.
mod cli;
mod commands;
mod error;
mod output;
mod spec;
mod target;

use clap::Parser;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    // Silent unless asked for through RUST_LOG; stdout carries results only.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off")),
        )
        .with_writer(std::io::stderr)
        .init();
    let json = cli.json;
    let result = tokio::runtime::Runtime::new()
        .map_err(|error| error::CtlError::internal(format!("cannot start the runtime: {error}")))
        .and_then(|runtime| runtime.block_on(commands::run(cli)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            output::print_error(&error, json);
            ExitCode::from(error.exit_code())
        }
    }
}

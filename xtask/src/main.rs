//! Repository tasks run as `cargo xtask <command>`. Owned by X1.

mod boundaries;
#[cfg(test)]
mod ci_config;
#[path = "../../crates/etd-host/core_lock.rs"]
#[allow(dead_code)]
mod core_lock;
mod dist;
mod fetch_cores;
#[cfg(test)]
mod spawn_flags;

use anyhow::{Context, Result, bail};
use cargo_metadata::MetadataCommand;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cargo xtask", about = "Repository tasks")]
enum Task {
    /// Check the architecture dependency boundaries.
    CheckBoundaries,
    /// Download, verify and extract the pinned upstream release kernels.
    FetchCores(fetch_cores::Args),
    /// Stage a release payload and build its installer package.
    Dist(dist::Args),
}

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

fn main() -> Result<()> {
    match Task::parse() {
        Task::CheckBoundaries => {
            let metadata = MetadataCommand::new()
                .current_dir(root())
                .other_options(vec!["--locked".into(), "--all-features".into()])
                .exec()
                .context("cargo metadata failed")?;
            let violations = boundaries::check(&metadata)?;
            if !violations.is_empty() {
                for violation in &violations {
                    eprintln!("{violation}");
                }
                bail!("{} architecture boundary violation(s)", violations.len());
            }
            println!("All architecture boundaries passed.");
            Ok(())
        }
        Task::FetchCores(args) => fetch_cores::run(&root(), args),
        Task::Dist(args) => dist::run(&root(), args),
    }
}

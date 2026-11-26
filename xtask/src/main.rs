//! Repository checks run as `cargo xtask <command>`. Owned by X1.

mod boundaries;
#[cfg(test)]
mod ci_config;
#[cfg(test)]
mod spawn_flags;

use anyhow::{Context, Result, bail};
use cargo_metadata::MetadataCommand;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("check-boundaries"), None) => {
            let metadata = MetadataCommand::new()
                .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
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
        _ => bail!("usage: cargo xtask check-boundaries"),
    }
}

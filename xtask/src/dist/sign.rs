//! The signing step after a package is built. v1 ships unsigned (human
//! ruling msg#1395, issue #2); a signing service plugs in here as another
//! hook.

use anyhow::Result;
use std::path::Path;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum SignHook {
    /// Leave the package unsigned.
    None,
}

pub(super) fn run(hook: SignHook, package: &Path) -> Result<()> {
    match hook {
        SignHook::None => {
            println!("{}: left unsigned (--sign-hook none)", package.display());
            Ok(())
        }
    }
}

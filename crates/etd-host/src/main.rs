//! The host binary: composition root (HR).
//!
//! CLI notes (frozen rule, F0): maintenance subcommands that change the
//! kernel store (install or remove a kernel version) and `reclaim --all
//! --purge` run only with the service stopped. They take the machine-wide
//! singleton lock themselves, so they are the only ledger writer; if the
//! lock is held they refuse and tell the administrator to stop the service.
//! Removing a kernel: `ReclaimEngine::reclaim_core`, then
//! `CoreStore::remove` only if no core-binary record is pending.

// The host composition root will construct real implementations of the trait layers.
use anyhow as _;
use etd_contract as _;
use etd_core_api as _;
use etd_core_easytier as _;
use etd_host_core as _;
use etd_ipc as _;
use etd_proc as _;
use etd_sysfx as _;
use etd_sysfx_os as _;

fn main() {
    eprintln!("EasyTier Desktop: scaffold only");
}

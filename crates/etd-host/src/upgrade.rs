//! `etd-host upgrade` (PK1): replace the installed service's host image with
//! the running one and merge this build's bundled kernels, keeping the
//! ledger, allow list, repair index and install key. Run from the new
//! payload directory (the MSI / package payload), never the installed image.
//!
//! Sequence, under the maintenance-command lock: stop and disable the
//! service, take the host lock, mark the journal `upgrading`, swap the image
//! (old one kept as `.prev`), merge kernels (old manifest saved), refresh the
//! unit, then start and verify the new service. Any failure restores the
//! image and manifest and restarts the old service; a crash leaves the
//! `upgrading` marker, and the next upgrade or uninstall restores first.
//! Old kernel directories are never deleted: live records may name them.
use super::{
    HostMode, NativeHostFilesystem, NativeServiceManager, Phase, Result, layout, require_journal,
    start_and_verify, storage,
};
use anyhow::{Context, bail, ensure};
use etd_sysfx_os::service::{HostFilesystem, HostLayout, LifecycleJournal, ServiceManager};
use std::path::{Path, PathBuf};

/// The manifest saved while an upgrade is uncommitted, in the protected
/// maintenance directory.
fn manifest_backup(layout: &HostLayout) -> PathBuf {
    layout.maintenance.join("upgrade-manifest.json")
}

fn same_file_bytes(left: &Path, right: &Path) -> Result<bool> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    fn hash(path: &Path) -> Result<[u8; 32]> {
        let mut file = std::fs::File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        Ok(hash.finalize().into())
    }
    Ok(hash(left)? == hash(right)?)
}

/// Undo an uncommitted upgrade: old image, old manifest, then the kernel
/// directories this attempt created. Caller holds the host lock with the
/// service stopped.
pub(super) fn roll_back(
    layout: &HostLayout,
    journal: &mut LifecycleJournal,
    published: &[PathBuf],
) -> Result<()> {
    NativeServiceManager
        .restore_host_image(layout)
        .context("cannot restore the previous host image")?;
    storage::restore_manifest(&layout.cores, &manifest_backup(layout))
        .context("cannot restore the previous kernel inventory")?;
    storage::remove_published_bundles(published)?;
    NativeServiceManager.discard_host_backup(layout)?;
    journal.set_upgrading(false)?;
    Ok(())
}

pub async fn upgrade() -> Result<()> {
    let layout = layout(HostMode::Service)?;
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    let source = etd_sysfx_os::service::current_exe()?;
    ensure!(
        !NativeHostFilesystem
            .is_installed_image(&layout)
            .unwrap_or(false),
        "run upgrade from the new installation payload, not the installed host image"
    );
    let bundle_root = source
        .parent()
        .context("missing payload directory")?
        .to_owned();
    let _command = NativeHostFilesystem.lock_maintenance(&layout)?;
    let journal = LifecycleJournal::open(&layout)?
        .context("no service installation; run etd-host install")?;
    ensure!(
        journal.phase() == Phase::Installed,
        "service is not installed (phase {:?}); finish uninstall or resume the service first",
        journal.phase()
    );
    let install_id = journal.install_id().to_owned();
    if !journal.upgrading()
        && same_file_bytes(&source, &layout.executable).unwrap_or(false)
        && storage::cores_current(&layout.cores).unwrap_or(false)
    {
        println!("host and kernels already up to date; checking the service");
        return start_and_verify(&layout, &install_id).await;
    }

    // The running service holds the host lock; stop it first.
    NativeServiceManager.stop_and_disable(&layout)?;
    let guard = NativeHostFilesystem.lock(&layout)?;
    let mut journal = require_journal(&layout, &install_id)?;
    if journal.upgrading() {
        println!("restoring an interrupted upgrade first");
        roll_back(&layout, &mut journal, &[]).context("cannot restore an interrupted upgrade")?;
    }
    let backup = manifest_backup(&layout);
    let mut published = Vec::new();
    let result: Result<storage::CoreMerge> = async {
        NativeHostFilesystem.validate_service(&layout)?;
        // Leftovers of an earlier, committed upgrade.
        NativeServiceManager.discard_host_backup(&layout)?;
        storage::discard_manifest_backup(&backup)?;
        journal.set_upgrading(true)?;
        NativeServiceManager.replace_host_image(&layout, &source)?;
        let merge = storage::upgrade_bundled_cores(&bundle_root, &layout.cores, &backup).await?;
        published.clone_from(&merge.published);
        NativeServiceManager.refresh_registration(&layout)?;
        NativeHostFilesystem.validate_service(&layout)?;
        Ok(merge)
    }
    .await;
    let merge = match result {
        Ok(merge) => merge,
        Err(error) => {
            if journal.upgrading()
                && let Err(rollback) = roll_back(&layout, &mut journal, &published)
            {
                bail!(
                    "upgrade failed: {error:#}; rollback incomplete: {rollback:#}; the service is disabled, retry etd-host upgrade"
                );
            }
            drop(guard);
            return match start_and_verify(&layout, &install_id).await {
                Ok(()) => Err(error.context("upgrade rolled back; previous service restarted")),
                Err(restart) => Err(error.context(format!(
                    "upgrade rolled back, but the previous service did not restart: {restart:#}"
                ))),
            };
        }
    };
    // The new service must acquire the host lock itself.
    drop(guard);
    if let Err(error) = start_and_verify(&layout, &install_id).await {
        let rollback: Result<()> = async {
            NativeServiceManager.stop_and_disable(&layout)?;
            let _guard = NativeHostFilesystem.lock(&layout)?;
            let mut journal = require_journal(&layout, &install_id)?;
            roll_back(&layout, &mut journal, &merge.published)?;
            Ok(())
        }
        .await;
        if let Err(rollback) = rollback {
            bail!(
                "new host failed to start: {error:#}; rollback incomplete: {rollback:#}; retry etd-host upgrade"
            );
        }
        start_and_verify(&layout, &install_id)
            .await
            .with_context(|| format!("new host failed to start ({error:#}); rolled back, but the previous service did not restart"))?;
        return Err(error.context("new host failed to start; upgrade rolled back"));
    }
    // Committed: the marker goes first, so a crash below leaves only stale
    // backups, which the next upgrade discards.
    require_journal(&layout, &install_id)?.set_upgrading(false)?;
    if let Err(error) = NativeServiceManager.discard_host_backup(&layout) {
        eprintln!("warning: previous host image backup kept: {error}");
    }
    if let Err(error) = storage::discard_manifest_backup(&backup) {
        eprintln!("warning: previous kernel inventory backup kept: {error:#}");
    }
    for version in &merge.dropped {
        println!(
            "kernel {version} is no longer trusted by this build; its files stay until uninstall"
        );
    }
    println!("service upgraded");
    Ok(())
}

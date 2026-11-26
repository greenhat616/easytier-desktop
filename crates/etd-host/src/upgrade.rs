//! `etd-host upgrade` (PK1): replace the installed service's host image with
//! the running one and merge this build's bundled kernels, keeping the
//! ledger, allow list, repair index and install key. Run from the new
//! payload directory (the MSI / package payload), never the installed image.
//!
//! Durable stages in the maintenance journal, each written before its step:
//! `Disabling` (stop and disable the service), `Replacing` (swap the image,
//! merge kernels, refresh the registration; backups exist), `Starting` (the
//! payload is verified and in place). The new host clears `Starting` itself
//! once its self-check reaches Serving, which commits the upgrade. While
//! `Replacing` is recorded no host starts; a crash in any stage is restored
//! by the next `upgrade` or `uninstall`. Every failure before the new host
//! ran restores image, manifest and registration and restarts the previous
//! service. Old kernel directories are never deleted: records may name
//! them, and after the new host ran neither are the ones it brought.
use super::{
    HostMode, NativeHostFilesystem, NativeServiceManager, Phase, Result, STOPPED_LOCK_WAIT, layout,
    lock_after_stop, require_journal, start_and_verify, storage,
};
use anyhow::{Context, bail, ensure};
use etd_sysfx_os::service::{
    HostFilesystem, HostLayout, LifecycleJournal, ServiceManager, UpgradeStage, ci_upgrade_fault,
    running_image_matches,
};
use std::path::PathBuf;
use std::time::Duration;

/// How long the new host has, after its endpoint is up, to finish its
/// self-check and commit.
const READY_WAIT: Duration = Duration::from_secs(90);

/// The manifest saved while an upgrade is uncommitted, in the protected
/// maintenance directory.
fn manifest_backup(layout: &HostLayout) -> PathBuf {
    layout.maintenance.join("upgrade-manifest.json")
}

/// Undo an uncommitted upgrade: old image, manifest and registration, then
/// the kernel directories in `published` (only ones no host has run with).
/// Caller holds the host lock with the service stopped.
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
    NativeServiceManager
        .restore_registration(layout)
        .context("cannot restore the previous service registration")?;
    storage::remove_published_bundles(published)?;
    NativeServiceManager.discard_host_backup(layout)?;
    journal.set_upgrade_stage(None)?;
    Ok(())
}

/// A service host started while the journal records `Starting` calls this
/// once its self-check reaches Serving: the upgrade is committed.
pub(super) fn commit_by_new_host(layout: &HostLayout, install_id: &str) {
    let committed = require_journal(layout, install_id).and_then(|mut journal| {
        if journal.upgrade_stage() == Some(UpgradeStage::Starting) {
            journal.set_upgrade_stage(None)?;
        }
        Ok(())
    });
    match committed {
        Ok(()) => tracing::info!(
            stage = "upgrade.committed",
            "upgrade committed: the new host serves"
        ),
        Err(error) => tracing::error!(
            stage = "upgrade.committed",
            error = %format!("{error:#}"),
            "upgrade not committed; etd-host upgrade will roll it back"
        ),
    }
}

/// Refuse maintenance that would act on an uncommitted upgrade.
pub(super) fn ensure_no_upgrade(journal: &LifecycleJournal) -> Result<()> {
    ensure!(
        journal.upgrade_stage().is_none(),
        "an upgrade of this service is incomplete; run etd-host upgrade from the new payload again, or etd-host uninstall"
    );
    Ok(())
}

async fn stop_for_maintenance(layout: &HostLayout) -> Result<etd_sysfx_os::service::HostLock> {
    NativeServiceManager.stop_and_disable(layout)?;
    lock_after_stop(STOPPED_LOCK_WAIT, || NativeHostFilesystem.lock(layout)).await
}

/// After an exit that left image, manifest and registration as they were:
/// clear a `Disabling` stage and restart the previous service.
async fn resume_previous(
    layout: &HostLayout,
    install_id: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let state =
        require_journal(layout, install_id).and_then(|mut journal| match journal.upgrade_stage() {
            None | Some(UpgradeStage::Disabling) => {
                journal.set_upgrade_stage(None)?;
                Ok(true)
            }
            Some(_) => Ok(false),
        });
    match state {
        Ok(true) => match start_and_verify(layout, install_id).await {
            Ok(()) => error.context("upgrade stopped; the previous service was restarted"),
            Err(restart) => error.context(format!(
                "upgrade stopped, and the previous service did not restart: {restart:#}"
            )),
        },
        Ok(false) => error.context(
            "an interrupted upgrade could not be restored; the service stays disabled; retry etd-host upgrade or etd-host uninstall",
        ),
        Err(journal) => error.context(format!(
            "the maintenance journal is unreadable ({journal:#}); the service stays disabled"
        )),
    }
}

/// Start the new host and wait until it has committed the upgrade.
async fn start_until_committed(layout: &HostLayout, install_id: &str) -> Result<()> {
    start_and_verify(layout, install_id).await?;
    let until = tokio::time::Instant::now() + READY_WAIT;
    loop {
        if require_journal(layout, install_id)?
            .upgrade_stage()
            .is_none()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            bail!("the new host did not finish its self-check within {READY_WAIT:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn discard_backups(layout: &HostLayout) {
    if let Err(error) = NativeServiceManager.discard_host_backup(layout) {
        eprintln!("warning: previous host image backup kept: {error}");
    }
    if let Err(error) = storage::discard_manifest_backup(&manifest_backup(layout)) {
        eprintln!("warning: previous kernel inventory backup kept: {error:#}");
    }
}

pub async fn upgrade() -> Result<()> {
    let layout = layout(HostMode::Service)?;
    ensure!(
        NativeServiceManager.entry_is_elevated()?,
        "administrator privileges required"
    );
    ensure!(
        !NativeHostFilesystem
            .is_installed_image(&layout)
            .context("cannot tell whether this is the installed host image")?,
        "run upgrade from the new installation payload, not the installed host image"
    );
    // Kernels are verified against this build's embedded table wherever
    // they come from; the image itself is copied from the running process.
    let bundle_root = etd_sysfx_os::service::current_exe()?
        .parent()
        .context("missing payload directory")?
        .to_owned();
    let _command = NativeHostFilesystem.lock_maintenance(&layout)?;
    let mut journal = LifecycleJournal::open(&layout)?
        .context("no service installation; run etd-host install")?;
    ensure!(
        journal.phase() == Phase::Installed,
        "service is not installed (phase {:?}); finish uninstall or resume the service first",
        journal.phase()
    );
    let install_id = journal.install_id().to_owned();
    let interrupted = journal.upgrade_stage();
    if interrupted.is_none()
        && running_image_matches(&layout.executable).unwrap_or(false)
        && storage::cores_current(&layout.cores).unwrap_or(false)
    {
        println!("host and kernels already up to date; checking the service");
        discard_backups(&layout);
        return start_and_verify(&layout, &install_id).await;
    }
    if interrupted.is_none() {
        journal.set_upgrade_stage(Some(UpgradeStage::Disabling))?;
    }

    // From here every exit restarts the previous service unless an
    // interrupted upgrade could not be restored.
    let prepared = async {
        let guard = stop_for_maintenance(&layout).await?;
        let mut journal = require_journal(&layout, &install_id)?;
        if matches!(
            interrupted,
            Some(UpgradeStage::Replacing | UpgradeStage::Starting)
        ) {
            println!("restoring an interrupted upgrade first");
            // Kernel directories it published stay: a host may have run.
            roll_back(&layout, &mut journal, &[])
                .context("cannot restore the interrupted upgrade")?;
        }
        Ok((guard, journal))
    }
    .await;
    let (guard, mut journal) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err(resume_previous(&layout, &install_id, error).await),
    };
    let ledger_before = storage::ledger_header(&layout.state);
    let mut published = Vec::new();
    let result: Result<storage::CoreMerge> = async {
        NativeHostFilesystem.validate_service(&layout)?;
        // Leftovers of an earlier, committed upgrade.
        NativeServiceManager.discard_host_backup(&layout)?;
        storage::discard_manifest_backup(&manifest_backup(&layout))?;
        journal.set_upgrade_stage(Some(UpgradeStage::Replacing))?;
        NativeServiceManager.replace_host_image(&layout)?;
        let merge =
            storage::upgrade_bundled_cores(&bundle_root, &layout.cores, &manifest_backup(&layout))
                .await?;
        published.clone_from(&merge.published);
        NativeServiceManager.refresh_registration(&layout)?;
        NativeHostFilesystem.validate_service(&layout)?;
        if ci_upgrade_fault(&layout, "crash-after-replace") {
            eprintln!("CI fault: exiting with the upgrade at stage Replacing");
            std::process::exit(86);
        }
        journal.set_upgrade_stage(Some(UpgradeStage::Starting))?;
        Ok(merge)
    }
    .await;
    let merge = match result {
        Ok(merge) => merge,
        Err(error) => {
            // No host has run with anything this attempt published.
            if let Err(rollback) = roll_back(&layout, &mut journal, &published) {
                bail!(
                    "upgrade failed: {error:#}; rollback incomplete: {rollback:#}; the service stays disabled; retry etd-host upgrade or etd-host uninstall"
                );
            }
            drop(guard);
            return Err(resume_previous(
                &layout,
                &install_id,
                error.context("upgrade rolled back"),
            )
            .await);
        }
    };
    let notice = storage::kernel_selection_notice(&layout.state, &merge.dropped).await;
    // The new host must acquire the host lock itself.
    drop(guard);
    if let Err(error) = start_until_committed(&layout, &install_id).await {
        let rolled_back: Result<bool> = async {
            let _guard = stop_for_maintenance(&layout).await?;
            let mut journal = require_journal(&layout, &install_id)?;
            if journal.upgrade_stage().is_none() {
                // The new host committed after the wait ended.
                return Ok(false);
            }
            // The new host ran: records may name the kernels it brought.
            roll_back(&layout, &mut journal, &[])?;
            Ok(true)
        }
        .await;
        match rolled_back {
            Ok(true) => {}
            Ok(false) => {
                start_and_verify(&layout, &install_id)
                    .await
                    .context("the new host committed the upgrade late and did not restart")?;
                discard_backups(&layout);
                println!("service upgraded (the new host became ready late: {error:#})");
                return Ok(());
            }
            Err(rollback) => bail!(
                "the new host did not become ready: {error:#}; rollback incomplete: {rollback:#}; the service stays disabled; retry etd-host upgrade or etd-host uninstall"
            ),
        }
        let migrated = match (ledger_before, storage::ledger_header(&layout.state)) {
            (Some(before), Some(after)) => {
                after.user_version != before.user_version || after.wal_pending
            }
            _ => false,
        };
        let mut error = error.context("the new host did not become ready; upgrade rolled back");
        if migrated {
            error = error.context(
                "rolled back, but the ledger was (or may have been) migrated by the new version, so the previous host runs diagnostics-only; run the new upgrade again",
            );
        }
        if let Err(restart) = start_and_verify(&layout, &install_id).await {
            error = error.context(format!("the previous service did not restart: {restart:#}"));
        }
        return Err(error);
    }
    discard_backups(&layout);
    for version in &merge.dropped {
        println!(
            "kernel {version} is no longer trusted by this build; its files stay until uninstall"
        );
    }
    if let Some(notice) = notice {
        println!("{notice}");
    }
    println!("service upgraded");
    Ok(())
}

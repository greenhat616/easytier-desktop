//! Startup self-check, six steps: singleton lock, open ledger + boot id,
//! orphan processes, reclaim open records in rank order, exclusive
//! containers / candidates, then serve and start desired instances.
//! In diagnose-only mode (ledger schema newer or unreadable) step 3 only
//! lists orphan processes and step 4 is `ReclaimEngine::diagnose`; nothing
//! is killed or deleted and no instance starts.
//! Owned by H1.
//!
//! Step by step ([`self_check`]; the orchestrator publishes the phases):
//! 1. The machine-wide singleton lock is taken by the composition root
//!    before the orchestrator exists; the phase is `SELF_CHECK`.
//! 2. Desired state is read from the ledger. Schema newer / unreadable:
//!    diagnose only. Unavailable: recovery without the ledger (exclusive
//!    containers only), then diagnose-only serving; no instance starts.
//! 3. Orphan kernels. Every open process record with a recorded identity
//!    is checked: `Same` is killed (`kill_verified`), `Uncertain` puts the
//!    record, and so its instance, in quarantine; nothing else is touched
//!    for that instance. Then a marker sweep (our kernel store image, a
//!    command line inside the run directory) kills kernels no record knows
//!    (crash between spawn and recording the pid).
//! 4. `ReclaimEngine::reclaim_all(Instances)`: every open generation in
//!    rank order, one failing generation never stopping the others.
//! 5. The report is published; closed records are compacted.
//! 6. Serving: one supervisor per desired instance, starting from what is
//!    still open (quarantined or pending generations), then accepted
//!    tickets are replayed.
//!
//! Running it twice in a row writes nothing the second time: killed
//! processes are gone, quarantined records are skipped, and the engine
//! finds nothing open to reclaim.
use crate::lifecycle::Ctx;
use crate::reclaimers::{exact_identity, recorded_identity};
use crate::supervisor::Initial;
use etd_contract::{DesiredInstance, InstanceId, Revision};
use etd_proc::{KillOutcome, Liveness, ProcessIdentity, ProcessMarker};
use etd_sysfx::{
    Effect, EffectKind, EffectState, GenerationOutcome, LedgerError, ReclaimReport, ReclaimScope,
    ScopeFilter,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What the self-check leaves for the orchestrator.
pub(crate) struct BootOutcome {
    /// Diagnose-only (or ledger-less recovery): serve nothing, start nothing.
    pub diagnostic: bool,
    pub revision: Revision,
    pub desired: Vec<DesiredInstance>,
    /// How each instance's supervisor starts; missing means idle.
    pub initial: BTreeMap<InstanceId, Initial>,
    pub report: Option<ReclaimReport>,
    /// Host log lines.
    pub log: Vec<String>,
}

impl BootOutcome {
    fn diagnostic(report: Option<ReclaimReport>, log: Vec<String>) -> Self {
        Self {
            diagnostic: true,
            revision: 0,
            desired: Vec::new(),
            initial: BTreeMap::new(),
            report,
            log,
        }
    }
}

/// Our kernels: an image from the kernel store, a command line inside the
/// run directory.
pub(crate) fn kernel_marker(ctx: &Ctx) -> ProcessMarker {
    ProcessMarker {
        exe_root: ctx.deps.dirs.core_store_dir.clone(),
        cmdline_root: ctx.deps.dirs.run_dir.clone(),
    }
}

pub(crate) async fn self_check(ctx: Arc<Ctx>) -> BootOutcome {
    let mut log = vec!["self-check: singleton lock held".to_string()];
    let deps = &ctx.deps;

    // Step 2: ledger and boot id.
    match deps.boot_id.current() {
        Ok(b) => log.push(format!("self-check: boot id {}", b.0)),
        Err(e) => log.push(format!(
            "self-check: boot id unreadable ({e}); volatile records are probed"
        )),
    }
    let desired = deps.ledger.desired().await;
    let (revision, desired) = match desired {
        Ok(d) => d,
        Err(e @ (LedgerError::SchemaTooNew { .. } | LedgerError::Unreadable(_))) => {
            log.push(format!("self-check: diagnose only: {e}"));
            list_orphans(&ctx, &mut log).await;
            let report = match deps.reclaim.diagnose().await {
                Ok(r) => Some(r),
                Err(e) => {
                    log.push(format!("self-check: diagnosis failed: {e}"));
                    None
                }
            };
            return BootOutcome::diagnostic(report, log);
        }
        Err(e) => {
            log.push(format!(
                "self-check: ledger unavailable ({e}); recovering without it"
            ));
            sweep_orphans(&ctx, &BTreeSet::new(), &mut log).await;
            let report = match deps.reclaim.recover_without_ledger().await {
                Ok(r) => Some(r),
                Err(e) => {
                    log.push(format!("self-check: recovery failed: {e}"));
                    None
                }
            };
            return BootOutcome::diagnostic(report, log);
        }
    };

    // Step 3: orphan kernels.
    let mut quarantined: BTreeMap<InstanceId, String> = BTreeMap::new();
    let mut known: BTreeSet<(u32, String)> = BTreeSet::new();
    let process_filter = ScopeFilter {
        kinds: vec![EffectKind::Process],
        ..ScopeFilter::default()
    };
    match deps.ledger.open_effects(&process_filter).await {
        Ok(records) => {
            for e in records {
                let Some(id) = recorded_identity(&e) else {
                    continue;
                };
                known.insert((id.pid, id.start_token.clone()));
                let Some((instance, _)) = e.scope.generation() else {
                    continue;
                };
                let instance = instance.clone();
                if e.state == EffectState::Quarantined {
                    quarantined
                        .entry(instance)
                        .or_insert_with(|| e.last_error.clone().unwrap_or_default());
                    continue;
                }
                if let Err(reason) = kill_recorded(&ctx, &e, &id).await {
                    log.push(format!(
                        "self-check: instance {instance} quarantined: {reason}"
                    ));
                    quarantine_record(&ctx, &e, &reason).await;
                    quarantined.insert(instance, reason);
                }
            }
        }
        Err(e) => log.push(format!("self-check: process records unreadable: {e}")),
    }
    sweep_orphans(&ctx, &known, &mut log).await;

    // Step 4: reclaim every open generation in rank order.
    let report = match deps.reclaim.reclaim_all(ReclaimScope::Instances).await {
        Ok(r) => Some(r),
        Err(e) => {
            log.push(format!("self-check: reclaim failed: {e}"));
            None
        }
    };

    // Step 5: compact closed records.
    match deps.ledger.compact().await {
        Ok(0) => {}
        Ok(n) => log.push(format!("self-check: compacted {n} closed records")),
        Err(e) => log.push(format!("self-check: compaction failed: {e}")),
    }

    // Step 6: what each instance starts from. Desired state is read again:
    // a removal completes when its last generation closes.
    let (revision, desired) = deps.ledger.desired().await.unwrap_or((revision, desired));
    let mut initial = BTreeMap::new();
    match deps.ledger.open_effects(&ScopeFilter::default()).await {
        Ok(open) => {
            for d in &desired {
                let id = InstanceId(d.instance_id.clone());
                let mine: Vec<Effect> = open
                    .iter()
                    .filter(|e| e.scope.generation().is_some_and(|(i, _)| *i == id))
                    .cloned()
                    .collect();
                let mut init = initial_from_open(&mine, report.as_ref());
                if let (Initial::Reclaim(epoch), Some(reason)) = (&init, quarantined.get(&id)) {
                    init = Initial::Quarantined(*epoch, reason.clone());
                }
                if !matches!(init, Initial::Idle) {
                    initial.insert(id, init);
                }
            }
        }
        Err(e) => log.push(format!("self-check: open records unreadable: {e}")),
    }
    BootOutcome {
        diagnostic: false,
        revision,
        desired,
        initial,
        report,
        log,
    }
}

/// How a supervisor starts, given the open records of its instance.
pub(crate) fn initial_from_open(open: &[Effect], report: Option<&ReclaimReport>) -> Initial {
    let Some(epoch) = open
        .iter()
        .filter_map(|e| e.scope.generation().map(|(_, epoch)| epoch))
        .min()
    else {
        return Initial::Idle;
    };
    let instance = open
        .iter()
        .find_map(|e| e.scope.generation().map(|(i, _)| i.clone()));
    let reported = report.and_then(|r| {
        r.generations.iter().find_map(|g| match &g.outcome {
            GenerationOutcome::Quarantined(reason)
                if Some(&g.instance) == instance.as_ref() && g.epoch == epoch =>
            {
                Some(reason.clone())
            }
            _ => None,
        })
    });
    let held = open
        .iter()
        .filter(|e| e.scope.generation().is_some_and(|(_, ep)| ep == epoch))
        .find(|e| e.state == EffectState::Quarantined);
    match (reported, held) {
        (Some(reason), _) => Initial::Quarantined(epoch, reason),
        (None, Some(e)) => Initial::Quarantined(
            epoch,
            e.last_error
                .clone()
                .unwrap_or_else(|| format!("{} record quarantined", e.kind)),
        ),
        (None, None) => Initial::Reclaim(epoch),
    }
}

/// Kill a recorded kernel that is still alive. `Err`: its liveness cannot
/// be established (quarantine).
async fn kill_recorded(ctx: &Ctx, e: &Effect, id: &ProcessIdentity) -> Result<(), String> {
    let process = &ctx.deps.process;
    match process.liveness(id).await {
        Liveness::Gone | Liveness::Reused => Ok(()), // the reclaim engine closes it
        Liveness::Uncertain => Err(format!("liveness of pid {} is uncertain", id.pid)),
        Liveness::Same => {
            let target = exact_identity(process.as_ref(), e, id)
                .await?
                .unwrap_or_else(|| id.clone());
            match process.kill_verified(&target).await {
                Ok(KillOutcome::Killed | KillOutcome::Gone | KillOutcome::Reused) => Ok(()),
                Ok(KillOutcome::Uncertain) => {
                    Err(format!("pid {} could not be killed with certainty", id.pid))
                }
                Err(err) => Err(format!("pid {}: {err}", id.pid)),
            }
        }
    }
}

/// Persist the quarantine, so neither the reclaim engine nor a later host
/// run treats the generation as closable.
async fn quarantine_record(ctx: &Ctx, e: &Effect, reason: &str) {
    let ledger = &ctx.deps.ledger;
    if e.state != EffectState::Reclaiming {
        let _ = ledger
            .transition(&e.id, EffectState::Reclaiming, None)
            .await;
    }
    let _ = ledger.record_failure(&e.id, reason).await;
    let _ = ledger
        .transition(&e.id, EffectState::Quarantined, None)
        .await;
}

/// Diagnose only: list, never kill.
async fn list_orphans(ctx: &Ctx, log: &mut Vec<String>) {
    match ctx.deps.process.find_marked(&kernel_marker(ctx)).await {
        Ok(found) => {
            for id in found {
                log.push(format!(
                    "self-check: kernel pid {} ({}) left running (diagnose only)",
                    id.pid,
                    id.exe.display()
                ));
            }
        }
        Err(e) => log.push(format!("self-check: process sweep failed: {e}")),
    }
}

/// Kill our kernels that no open record knows.
async fn sweep_orphans(ctx: &Ctx, known: &BTreeSet<(u32, String)>, log: &mut Vec<String>) {
    let process = &ctx.deps.process;
    match process.find_marked(&kernel_marker(ctx)).await {
        Ok(found) => {
            for id in found {
                if known.contains(&(id.pid, id.start_token.clone())) {
                    continue;
                }
                match process.kill_verified(&id).await {
                    Ok(KillOutcome::Killed) => {
                        log.push(format!(
                            "self-check: killed unrecorded kernel pid {}",
                            id.pid
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log.push(format!("self-check: kernel pid {} not killed: {e}", id.pid))
                    }
                }
            }
        }
        Err(e) => log.push(format!("self-check: process sweep failed: {e}")),
    }
}

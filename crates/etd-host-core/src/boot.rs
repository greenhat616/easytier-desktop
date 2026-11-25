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
//!    is checked: `Same` is killed (`kill_verified`), `Uncertain` (or a
//!    failed kill) quarantines the record, persisted, and so its instance.
//!    Then a marker sweep per runtime directory `run/<instance>/<epoch>/`
//!    kills kernels no record knows (crash between spawn and recording the
//!    pid); a kill that fails or is uncertain quarantines that instance,
//!    and a final sweep of the whole run directory catches the rest.
//! 4. `ReclaimEngine::reclaim_all(Instances)`: every open generation, the
//!    process record first; one failing generation never stops the others.
//! 5. The report is published; closed records are compacted.
//! 6. Serving: one supervisor per desired instance, starting from what is
//!    still open (quarantined or pending generations), then accepted
//!    tickets are replayed.
//!
//! The self-check never passes over a failure (ruling msg#567): if the
//! process records cannot be read, or a sweep fails or finds a kernel it
//! cannot kill and cannot attribute, no privileged instance starts until a
//! later sweep succeeds ([`resweep`]); an orphan attributed to an instance
//! quarantines that instance. Where the quarantine cannot be persisted
//! (its generation is already closed, or the ledger refuses the write) the
//! instance stays quarantined in memory and is never reclaimed or started
//! automatically; the next host start finds the same orphan again.
//!
//! Running it twice in a row writes nothing the second time: killed
//! processes are gone, quarantined records are skipped, and the engine
//! finds nothing open to reclaim.
use crate::lifecycle::{Ctx, view};
use crate::reclaimers::{exact_identity, recorded_identity};
use crate::supervisor::Initial;
use etd_contract::v1::{self, NoticeLevel};
use etd_contract::{DesiredInstance, HostMode, InstanceId, Revision};
use etd_proc::{KillOutcome, Liveness, ProcessIdentity, ProcessMarker};
use etd_sysfx::{
    Effect, EffectKind, EffectState, Epoch, GenerationOutcome, LedgerError, ReclaimReport,
    ReclaimScope, ScopeFilter,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
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
    /// No privileged instance may start until a sweep succeeds.
    pub hold_starts: Option<String>,
    /// Published once serving.
    pub notices: Vec<v1::Notice>,
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
            hold_starts: None,
            notices: Vec::new(),
            log,
        }
    }
}

/// Our kernels: an image from the kernel store, a command line inside the
/// run directory (or one generation's runtime directory).
pub(crate) fn kernel_marker(ctx: &Ctx, cmdline_root: PathBuf) -> ProcessMarker {
    ProcessMarker {
        exe_root: ctx.deps.dirs.core_store_dir.clone(),
        cmdline_root,
    }
}

/// Outcome of a sweep for kernels no record knows.
#[derive(Default)]
pub(crate) struct Sweep {
    /// Instances whose orphan could not be killed: (epoch, reason).
    pub quarantine: BTreeMap<InstanceId, (Epoch, String)>,
    /// The sweep itself failed, or an orphan nobody can be blamed for
    /// survived: hold every privileged start.
    pub failed: Option<String>,
    pub log: Vec<String>,
}

/// Starts are held only on a privileged host (a user host's kernels run
/// with the user's own rights).
fn privileged(ctx: &Ctx) -> bool {
    ctx.deps.mode != HostMode::User
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
            let sweep = sweep_orphans(&ctx, &BTreeSet::new()).await;
            log.extend(sweep.log);
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
    let mut quarantined: BTreeMap<InstanceId, (Epoch, String)> = BTreeMap::new();
    let mut notices = Vec::new();
    let mut hold: Option<String> = None;
    let mut known: BTreeSet<(u32, String)> = BTreeSet::new();
    let process_filter = ScopeFilter {
        kinds: vec![EffectKind::Process],
        ..ScopeFilter::default()
    };
    match deps.ledger.open_effects(&process_filter).await {
        Ok(records) => {
            for e in records {
                let Some((instance, epoch)) = e.scope.generation() else {
                    continue;
                };
                let instance = instance.clone();
                if e.state == EffectState::Quarantined {
                    quarantined
                        .entry(instance)
                        .or_insert_with(|| (epoch, e.last_error.clone().unwrap_or_default()));
                    continue;
                }
                let Some(id) = recorded_identity(&e) else {
                    continue;
                };
                known.insert((id.pid, id.start_token.clone()));
                if let Err(reason) = kill_recorded(&ctx, &e, &id).await {
                    log.push(format!(
                        "self-check: instance {instance} quarantined: {reason}"
                    ));
                    if let Err(err) = quarantine_record(&ctx, &e, &reason).await {
                        log.push(format!(
                            "self-check: quarantine of {instance} not recorded ({err}); \
                             it is held in memory, nothing reclaimed or started"
                        ));
                    }
                    notices.push(view::notice(
                        NoticeLevel::Error,
                        "selfcheck.quarantined",
                        reason.clone(),
                        instance.as_str(),
                    ));
                    quarantined.insert(instance, (epoch, reason));
                }
            }
        }
        Err(e) => {
            let why = format!("process records unreadable: {e}");
            log.push(format!("self-check: {why}"));
            hold = Some(why);
        }
    }
    let sweep = sweep_orphans(&ctx, &known).await;
    log.extend(sweep.log);
    for (instance, (epoch, reason)) in sweep.quarantine {
        notices.push(view::notice(
            NoticeLevel::Error,
            "selfcheck.quarantined",
            reason.clone(),
            instance.as_str(),
        ));
        persist_orphan_quarantine(&ctx, &instance, epoch, &reason, &mut log).await;
        quarantined.entry(instance).or_insert((epoch, reason));
    }
    if let Some(why) = sweep.failed {
        hold.get_or_insert(why);
    }
    let hold_starts = hold.filter(|_| privileged(&ctx));
    if let Some(why) = &hold_starts {
        notices.push(view::notice(
            NoticeLevel::Error,
            "selfcheck.incomplete",
            format!("no instance starts until the kernel sweep succeeds: {why}"),
            "",
        ));
    }

    // Step 4: reclaim every open generation (the engine holds those whose
    // kernel is not verified dead).
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
    let open = deps.ledger.open_effects(&ScopeFilter::default()).await;
    if let Err(e) = &open {
        log.push(format!("self-check: open records unreadable: {e}"));
    }
    for d in &desired {
        let id = InstanceId(d.instance_id.clone());
        let mine: Vec<Effect> = match &open {
            Ok(open) => open
                .iter()
                .filter(|e| e.scope.generation().is_some_and(|(i, _)| *i == id))
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        };
        let mut init = initial_from_open(&mine, report.as_ref());
        if let Some((epoch, reason)) = quarantined.get(&id) {
            let epoch = match &init {
                Initial::Reclaim(e) | Initial::Quarantined(e, _) => *e,
                Initial::Idle => *epoch,
            };
            init = Initial::Quarantined(epoch, reason.clone());
        }
        if !matches!(init, Initial::Idle) {
            initial.insert(id, init);
        }
    }
    BootOutcome {
        diagnostic: false,
        revision,
        desired,
        initial,
        report,
        hold_starts,
        notices,
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
/// be established or the kill failed (quarantine).
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
pub(crate) async fn quarantine_record(
    ctx: &Ctx,
    e: &Effect,
    reason: &str,
) -> Result<(), LedgerError> {
    let ledger = &ctx.deps.ledger;
    if e.state != EffectState::Reclaiming {
        ledger
            .transition(&e.id, EffectState::Reclaiming, None)
            .await?;
    }
    ledger.record_failure(&e.id, reason).await?;
    ledger
        .transition(&e.id, EffectState::Quarantined, None)
        .await
}

/// An unkillable orphan of `instance` / `epoch`: quarantine that
/// generation's open process records; with none open (closed generation)
/// the quarantine lives in memory only.
async fn persist_orphan_quarantine(
    ctx: &Ctx,
    instance: &InstanceId,
    epoch: Epoch,
    reason: &str,
    log: &mut Vec<String>,
) {
    let filter = ScopeFilter {
        kinds: vec![EffectKind::Process],
        ..ScopeFilter::epoch(instance.clone(), epoch)
    };
    let records = match ctx.deps.ledger.open_effects(&filter).await {
        Ok(r) => r,
        Err(e) => {
            log.push(format!(
                "self-check: quarantine of {instance} not recorded ({e}); held in memory"
            ));
            return;
        }
    };
    if records.is_empty() {
        log.push(format!(
            "self-check: generation {} of {instance} is closed; its orphan keeps the instance quarantined in memory",
            epoch.0
        ));
    }
    for e in records
        .iter()
        .filter(|e| e.state != EffectState::Quarantined)
    {
        if let Err(err) = quarantine_record(ctx, e, reason).await {
            log.push(format!(
                "self-check: quarantine of {instance} not recorded ({err}); held in memory"
            ));
        }
    }
}

/// Diagnose only: list, never kill.
async fn list_orphans(ctx: &Ctx, log: &mut Vec<String>) {
    let marker = kernel_marker(ctx, ctx.deps.dirs.run_dir.clone());
    match ctx.deps.process.find_marked(&marker).await {
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

/// `run/<instance>/<epoch>/` directories present on disk.
fn epoch_dirs(run: &std::path::Path) -> std::io::Result<Vec<(InstanceId, Epoch, PathBuf)>> {
    let mut out = Vec::new();
    let instances = match std::fs::read_dir(run) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for inst in instances {
        let inst = inst?;
        if !inst.file_type()?.is_dir() {
            continue;
        }
        let name = inst.file_name().to_string_lossy().into_owned();
        for ep in std::fs::read_dir(inst.path())? {
            let ep = ep?;
            if let Ok(n) = ep.file_name().to_string_lossy().parse::<u64>()
                && ep.file_type()?.is_dir()
            {
                out.push((InstanceId(name.clone()), Epoch(n), ep.path()));
            }
        }
    }
    Ok(out)
}

/// Kill our kernels that no open record knows: per generation directory
/// first (an unkillable one quarantines its instance), then the whole run
/// directory (an unkillable kernel there cannot be attributed).
pub(crate) async fn sweep_orphans(ctx: &Ctx, known: &BTreeSet<(u32, String)>) -> Sweep {
    let mut sweep = Sweep::default();
    let process = &ctx.deps.process;
    let mut handled: BTreeSet<(u32, String)> = known.clone();
    let run = ctx.deps.dirs.run_dir.clone();
    let dirs = tokio::task::spawn_blocking(move || epoch_dirs(&run))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
        .and_then(|r| r);
    match dirs {
        Ok(dirs) => {
            for (instance, epoch, dir) in dirs {
                match process.find_marked(&kernel_marker(ctx, dir)).await {
                    Err(e) => {
                        sweep
                            .failed
                            .get_or_insert(format!("process sweep failed: {e}"));
                    }
                    Ok(found) => {
                        for id in found {
                            if !handled.insert((id.pid, id.start_token.clone())) {
                                continue;
                            }
                            if let Err(reason) = kill_orphan(ctx, &id, &mut sweep.log).await {
                                sweep
                                    .quarantine
                                    .entry(instance.clone())
                                    .or_insert((epoch, reason));
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            sweep
                .failed
                .get_or_insert(format!("run directory unreadable: {e}"));
        }
    }
    let marker = kernel_marker(ctx, ctx.deps.dirs.run_dir.clone());
    match process.find_marked(&marker).await {
        Err(e) => {
            sweep
                .failed
                .get_or_insert(format!("process sweep failed: {e}"));
        }
        Ok(found) => {
            for id in found {
                if !handled.insert((id.pid, id.start_token.clone())) {
                    continue;
                }
                if let Err(reason) = kill_orphan(ctx, &id, &mut sweep.log).await {
                    sweep.failed.get_or_insert(reason);
                }
            }
        }
    }
    if let Some(why) = &sweep.failed {
        sweep.log.push(format!("self-check: {why}"));
    }
    sweep
}

async fn kill_orphan(ctx: &Ctx, id: &ProcessIdentity, log: &mut Vec<String>) -> Result<(), String> {
    match ctx.deps.process.kill_verified(id).await {
        Ok(KillOutcome::Killed) => {
            log.push(format!(
                "self-check: killed unrecorded kernel pid {}",
                id.pid
            ));
            Ok(())
        }
        Ok(KillOutcome::Gone | KillOutcome::Reused) => Ok(()),
        Ok(KillOutcome::Uncertain) => Err(format!(
            "unrecorded kernel pid {} could not be killed with certainty",
            id.pid
        )),
        Err(e) => Err(format!("unrecorded kernel pid {} not killed: {e}", id.pid)),
    }
}

/// Retry of a failed sweep while starts are held. `Ok`: starts may go on.
pub(crate) async fn resweep(ctx: &Ctx) -> Result<(), String> {
    let known: BTreeSet<(u32, String)> = ctx
        .deps
        .ledger
        .open_effects(&ScopeFilter {
            kinds: vec![EffectKind::Process],
            ..ScopeFilter::default()
        })
        .await
        .map_err(|e| format!("process records unreadable: {e}"))?
        .iter()
        .filter_map(recorded_identity)
        .map(|id| (id.pid, id.start_token))
        .collect();
    let sweep = sweep_orphans(ctx, &known).await;
    match sweep.failed {
        Some(why) => Err(why),
        None if sweep.quarantine.is_empty() => Ok(()),
        None => Err("an orphan kernel could not be killed".into()),
    }
}

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
//! The self-check never passes over a failure (rulings msg#567, msg#631):
//! nothing is reclaimed automatically without proof that no kernel of ours
//! is alive to use it.
//! - The process records cannot be read, a sweep fails, or a kernel that
//!   cannot be attributed survives: step 4 is skipped, no instance starts
//!   and no supervisor reclaims (`Ctx::hold`) until a re-sweep succeeds
//!   ([`resweep`], same path as here), which then runs step 4.
//! - An orphan attributed to an instance (`run/<instance>/<epoch>/`) that
//!   cannot be killed quarantines that instance, persisted on the
//!   generation's process records. Where that cannot be persisted (the
//!   generation is closed, or the ledger refuses the write) the instance
//!   is quarantined in memory and its generations are left out of step 4,
//!   as is the exclusive-container sweep; the next host start finds the
//!   same orphan again. A RetryReclaim first kills the instance's orphans.
//! - Ledger unavailable: exclusive containers are cleaned only when the
//!   sweep killed every kernel it found; otherwise diagnosis only.
//!
//! Running it twice in a row writes nothing the second time: killed
//! processes are gone, quarantined records are skipped, and the engine
//! finds nothing open to reclaim.
use crate::lifecycle::{Ctx, view};
use crate::reclaimers::{exact_identity, recorded_identity};
use crate::supervisor::Initial;
use etd_contract::v1::{self, NoticeLevel};
use etd_contract::{DesiredInstance, InstanceId, Revision};
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
    /// Nothing is reclaimed or started until a sweep succeeds.
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
    /// survived: no automatic reclaim and no start until a sweep succeeds.
    pub failed: Option<String>,
    pub log: Vec<String>,
}

impl Sweep {
    /// Every kernel of ours it found is verified dead.
    fn proved(&self) -> bool {
        self.failed.is_none() && self.quarantine.is_empty()
    }
}

/// Orphans that could not be killed: quarantine their instances (persisted
/// where a generation is open), with a notice each. Returns the instances
/// whose quarantine is held in memory only: no automatic reclaim for them.
async fn quarantine_orphans(
    ctx: &Ctx,
    orphans: &BTreeMap<InstanceId, (Epoch, String)>,
    log: &mut Vec<String>,
    notices: &mut Vec<v1::Notice>,
) -> BTreeSet<InstanceId> {
    let mut unpersisted = BTreeSet::new();
    for (instance, (epoch, reason)) in orphans {
        notices.push(view::notice(
            NoticeLevel::Error,
            "selfcheck.quarantined",
            reason.clone(),
            instance.as_str(),
        ));
        if !persist_orphan_quarantine(ctx, instance, *epoch, reason, log).await {
            unpersisted.insert(instance.clone());
        }
    }
    unpersisted
}

/// Step 4 once the kernels are accounted for: every open generation, the
/// process record first. Instances in `excluded` (a quarantine not
/// persisted) are left alone entirely, and so is the exclusive-container
/// sweep (their kernel may still use what is in it).
pub(crate) async fn reclaim_proven(
    ctx: &Ctx,
    excluded: &BTreeSet<InstanceId>,
    log: &mut Vec<String>,
) -> Option<ReclaimReport> {
    let engine = &ctx.deps.reclaim;
    if excluded.is_empty() {
        return match engine.reclaim_all(ReclaimScope::Instances).await {
            Ok(r) => Some(r),
            Err(e) => {
                log.push(format!("self-check: reclaim failed: {e}"));
                None
            }
        };
    }
    log.push(format!(
        "self-check: generations of {} left alone (quarantine held in memory); no container sweep",
        excluded
            .iter()
            .map(InstanceId::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let open = match ctx.deps.ledger.open_effects(&ScopeFilter::default()).await {
        Ok(o) => o,
        Err(e) => {
            log.push(format!("self-check: reclaim failed: {e}"));
            return None;
        }
    };
    let generations: BTreeSet<(InstanceId, Epoch)> = open
        .iter()
        .filter_map(|e| e.scope.generation().map(|(i, ep)| (i.clone(), ep)))
        .filter(|(i, _)| !excluded.contains(i))
        .collect();
    let mut reports = Vec::new();
    for (instance, epoch) in generations {
        match engine.reclaim_generation(&instance, epoch).await {
            Ok(r) => reports.push(r),
            Err(e) => log.push(format!(
                "self-check: reclaim of {instance} generation {} failed: {e}",
                epoch.0
            )),
        }
    }
    match engine.report().await {
        Ok(mut r) => {
            r.generations = reports;
            Some(r)
        }
        Err(e) => {
            log.push(format!("self-check: reclaim report unavailable: {e}"));
            None
        }
    }
}

pub(crate) async fn self_check(ctx: Arc<Ctx>) -> BootOutcome {
    let mut log = vec!["self-check: singleton lock held".to_string()];
    let deps = &ctx.deps;

    // Step 2: ledger and boot id.
    let boot = match deps.boot_id.current() {
        Ok(b) => {
            log.push(format!("self-check: boot id {}", b.0));
            Some(b)
        }
        Err(e) => {
            log.push(format!(
                "self-check: boot id unreadable ({e}); volatile records are probed"
            ));
            None
        }
    };
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
            let proved = sweep.proved();
            log.extend(sweep.log);
            // Exclusive containers are cleaned only once no kernel of ours
            // can be alive to use them.
            let report = if proved {
                match deps.reclaim.recover_without_ledger().await {
                    Ok(r) => Some(r),
                    Err(e) => {
                        log.push(format!("self-check: recovery failed: {e}"));
                        None
                    }
                }
            } else {
                log.push(
                    "self-check: a kernel of ours may still be alive; nothing cleaned up".into(),
                );
                match deps.reclaim.diagnose().await {
                    Ok(r) => Some(r),
                    Err(e) => {
                        log.push(format!("self-check: diagnosis failed: {e}"));
                        None
                    }
                }
            };
            return BootOutcome::diagnostic(report, log);
        }
    };

    // Step 3: orphan kernels.
    let mut quarantined: BTreeMap<InstanceId, (Epoch, String)> = BTreeMap::new();
    let mut excluded: BTreeSet<InstanceId> = BTreeSet::new();
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
                // A kernel of an earlier boot died with it: the reclaim
                // engine closes its record unprobed (its pid may belong to
                // anything now).
                if boot.as_ref().is_some_and(|b| *b != e.boot) && e.persistence.closes_on_reboot() {
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
                        excluded.insert(instance.clone());
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
    excluded.extend(quarantine_orphans(&ctx, &sweep.quarantine, &mut log, &mut notices).await);
    for (instance, q) in sweep.quarantine {
        quarantined.entry(instance).or_insert(q);
    }
    if let Some(why) = sweep.failed {
        hold.get_or_insert(why);
    }
    if let Some(why) = &hold {
        notices.push(view::notice(
            NoticeLevel::Error,
            "selfcheck.incomplete",
            format!("nothing is reclaimed or started until the kernel sweep succeeds: {why}"),
            "",
        ));
    }

    // Step 4: reclaim every open generation (the engine holds those whose
    // kernel is not verified dead), only once every kernel of ours is
    // accounted for; otherwise it waits for a successful re-sweep.
    ctx.exclude(excluded);
    let report = if hold.is_some() {
        log.push("self-check: automatic reclaim deferred until the kernel sweep succeeds".into());
        None
    } else {
        reclaim_proven(&ctx, &ctx.excluded(), &mut log).await
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
        hold_starts: hold,
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
) -> bool {
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
            return false;
        }
    };
    if records.is_empty() {
        log.push(format!(
            "self-check: generation {} of {instance} is closed; its orphan keeps the instance quarantined in memory",
            epoch.0
        ));
        return false;
    }
    let mut persisted = true;
    for e in records
        .iter()
        .filter(|e| e.state != EffectState::Quarantined)
    {
        if let Err(err) = quarantine_record(ctx, e, reason).await {
            log.push(format!(
                "self-check: quarantine of {instance} not recorded ({err}); held in memory"
            ));
            persisted = false;
        }
    }
    persisted
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

/// A successful re-sweep while everything is held.
pub(crate) struct Resweep {
    /// Instances whose orphan could not be killed: quarantined (persisted
    /// where possible), to be put in quarantine by their supervisors.
    pub quarantined: BTreeMap<InstanceId, (Epoch, String)>,
    pub notices: Vec<v1::Notice>,
    pub report: Option<ReclaimReport>,
    pub log: Vec<String>,
}

/// Retry of a failed sweep while starts and reclaims are held, the same
/// path as the self-check: an attributable unkillable orphan quarantines
/// its instance; then the deferred reclaim runs. `Err`: still no proof.
pub(crate) async fn resweep(ctx: &Ctx) -> Result<Resweep, String> {
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
    if let Some(why) = sweep.failed {
        return Err(why);
    }
    let mut log = sweep.log;
    let mut notices = Vec::new();
    // Earlier unrecorded quarantines stay excluded: a sweep that no longer
    // sees their orphan proves nothing about it (msg#650).
    ctx.exclude(quarantine_orphans(ctx, &sweep.quarantine, &mut log, &mut notices).await);
    let report = reclaim_proven(ctx, &ctx.excluded(), &mut log).await;
    if let Err(e) = ctx.deps.ledger.compact().await {
        log.push(format!("self-check: compaction failed: {e}"));
    }
    Ok(Resweep {
        quarantined: sweep.quarantine,
        notices,
        report,
        log,
    })
}

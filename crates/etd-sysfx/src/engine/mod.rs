//! Reclaim engine: probe -> delete -> verify in rank order; delete only on a
//! matching credential or exclusive container, otherwise candidate; conflicts
//! stay open; quarantine after five failures; boot-id change closes volatile
//! records unprobed; repair-index name re-derivation after ledger loss.
//! Owned by R1. The type name and `new(ReclaimDeps)` are frozen (F0); the
//! body is R1's.
//!
//! Rules every path follows (doc#2 v7, "名字只用来找到对象，删除要有创建凭据"):
//! - A recorded object is deleted only when the probe finds it in an
//!   exclusive container, or with exactly the credential read back when the
//!   record was applied. A record still `Planned` (no credential) whose
//!   object is present outside an exclusive container becomes a candidate;
//!   a different credential is a conflict. Neither is ever deleted
//!   automatically.
//! - Settings (`Undo::RestoreIfOurs`) are handed to the reclaimer, which
//!   restores only while the current value is still ours.
//! - Within a generation the kernel process records go first; until every
//!   one of them is closed (kernel verified dead) no other record of the
//!   generation is touched (rulings msg#557 / msg#567). Then records are
//!   handled rank by rank (lowest first); a rank whose records are still
//!   ours and not gone (failing, quarantined, indeterminate) stops the
//!   higher ranks, fences last.
//! - Swept objects (outside the ledger) are removed only when they sit in an
//!   exclusive container; everything else, including whatever the repair
//!   index re-derives, is listed as a candidate.
//! - `diagnose` never calls a reclaimer.
mod record;
mod report;

use crate::*;
use async_trait::async_trait;
use etd_contract::{CandidateDecision, InstanceId, v1::CandidateAction};
use record::{Ctx, RecordOutcome};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, PoisonError},
};

/// Notes kept for `report()` between runs.
const MAX_NOTES: usize = 200;

/// Which shared (product / core-binary) records must wait for open
/// instance generations.
#[derive(Default)]
struct SharedGate {
    any_open: bool,
    /// SHA-256 (lower-case hex) of the kernels open generations run.
    binaries: BTreeSet<String>,
    /// Some open generation's inputs could not be read.
    unknown: bool,
}

impl SharedGate {
    fn waits(&self, e: &Effect) -> bool {
        match &e.scope {
            EffectScope::Instance { .. } => false,
            EffectScope::CoreBinary { sha256 } => {
                self.unknown || self.binaries.contains(&sha256.to_ascii_lowercase())
            }
            _ => self.any_open,
        }
    }
}

pub struct ReclaimEngineImpl {
    deps: ReclaimDeps,
    reclaimers: HashMap<EffectKind, Arc<dyn Reclaimer>>,
    /// Serialises entry points: one reclaim run at a time.
    run: tokio::sync::Mutex<()>,
    memory: Mutex<Memory>,
}

/// What the engine keeps between calls (not persisted: a restart re-sweeps).
#[derive(Default)]
struct Memory {
    /// Swept candidates of the latest sweep, by candidate id.
    swept: BTreeMap<String, FoundObject>,
    /// Swept candidate ids an administrator kept (not ours).
    kept: BTreeSet<String>,
    /// Notes of the latest run.
    notes: Vec<String>,
    /// Latest diagnose / recover-without-ledger report, for `report()` while
    /// the ledger cannot be read.
    offline: Option<ReclaimReport>,
}

impl ReclaimEngineImpl {
    pub fn new(deps: ReclaimDeps) -> Self {
        let reclaimers = deps
            .reclaimers
            .iter()
            .map(|r| (r.kind(), Arc::clone(r)))
            .collect();
        Self {
            deps,
            reclaimers,
            run: tokio::sync::Mutex::new(()),
            memory: Mutex::new(Memory::default()),
        }
    }

    fn memory(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.memory.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ctx<'a>(&'a self, boot: Option<BootId>, notes: &'a mut Vec<String>) -> Ctx<'a> {
        Ctx {
            ledger: self.deps.ledger.as_ref(),
            reclaimers: &self.reclaimers,
            boot,
            notes,
            process_closed_at: None,
        }
    }

    /// Current boot id; `None` (with a note) if it cannot be read, in which
    /// case nothing is closed unprobed.
    fn boot(&self, notes: &mut Vec<String>) -> Option<BootId> {
        match self.deps.boot_id.current() {
            Ok(b) => Some(b),
            Err(e) => {
                notes.push(format!(
                    "boot id unavailable ({e}); volatile records are probed"
                ));
                None
            }
        }
    }

    /// Run one group of records (a generation, or product / core-binary
    /// records) rank by rank.
    async fn run_group(&self, ctx: &mut Ctx<'_>, records: Vec<Effect>) -> Result<(), LedgerError> {
        // Record-only effects never take part in the rank order; they close
        // after it, whatever it reached.
        let (record_only, mut records): (Vec<Effect>, Vec<Effect>) = records
            .into_iter()
            .partition(|e| record::record_only(e.persistence));
        ctx.process_closed_at = None;
        records.sort_by(|a, b| (ctx.rank(a.kind), &a.id).cmp(&(ctx.rank(b.kind), &b.id)));
        // The kernel goes first (ruling msg#567): while it may still be
        // alive it owns, and would fight or recreate, every object of its
        // generation. Process records are reclaimed before any other rank;
        // unless every one of them closes (probe absent, or killed and
        // verified gone), no other record of the group is touched.
        let (processes, records): (Vec<Effect>, Vec<Effect>) = records
            .into_iter()
            .partition(|e| e.kind == EffectKind::Process);
        let mut held: Option<String> = None;
        for e in &processes {
            match ctx.step(e).await? {
                RecordOutcome::Closed => ctx.process_closed_at = Some(jiff::Timestamp::now()),
                outcome => {
                    held.get_or_insert(format!("process record {} is {outcome:?}", e.id.0));
                }
            }
        }
        if let Some(why) = held {
            for e in &records {
                ctx.notes.push(format!(
                    "{}: waiting for the kernel process to be verified dead ({why})",
                    report::pending_note(e)
                ));
            }
            for e in &record_only {
                ctx.step(e).await?;
            }
            return Ok(());
        }
        let mut blocked = false;
        let mut i = 0;
        while i < records.len() {
            let rank = ctx.rank(records[i].kind);
            let end = records[i..]
                .iter()
                .position(|e| ctx.rank(e.kind) != rank)
                .map_or(records.len(), |n| i + n);
            // Higher ranks wait; their records stay open and show up as
            // residues. (Fences need the process records closed, which the
            // process-first pass above already guarantees.)
            if blocked {
                break;
            }
            for e in &records[i..end] {
                let outcome = ctx.step(e).await?;
                if outcome.blocks() {
                    blocked = true;
                }
            }
            i = end;
        }
        for e in &record_only {
            ctx.step(e).await?;
        }
        Ok(())
    }

    /// Reclaim one generation and report on it.
    async fn run_generation(
        &self,
        ctx: &mut Ctx<'_>,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<GenerationReport, LedgerError> {
        let filter = ScopeFilter::epoch(instance.clone(), epoch);
        let records = self.deps.ledger.open_effects(&filter).await?;
        self.run_group(ctx, records).await?;
        let open = self.deps.ledger.open_effects(&filter).await?;
        Ok(report::generation(instance, epoch, &open))
    }

    /// Open instance generations, oldest epoch first per instance.
    async fn open_generations(
        &self,
        filter: &ScopeFilter,
    ) -> Result<Vec<(InstanceId, Epoch)>, LedgerError> {
        let set: BTreeSet<(InstanceId, Epoch)> = self
            .deps
            .ledger
            .open_effects(filter)
            .await?
            .iter()
            .filter_map(|e| e.scope.generation().map(|(i, n)| (i.clone(), n)))
            .collect();
        Ok(set.into_iter().collect())
    }

    /// Instances the repair index and the ledger know about, plus the install
    /// key, for re-deriving names during a sweep.
    fn repair_index(&self, notes: &mut Vec<String>) -> (Option<InstallKey>, Vec<InstanceId>) {
        match self.deps.repair_index.load() {
            Ok(Some(index)) => (Some(index.install_key), index.instances),
            Ok(None) => {
                notes.push("no repair index: names cannot be re-derived".into());
                (None, Vec::new())
            }
            Err(e) => {
                notes.push(format!(
                    "repair index unreadable ({e}): names cannot be re-derived"
                ));
                (None, Vec::new())
            }
        }
    }

    /// Sweep for marked objects outside the ledger. `open` are the open
    /// records (objects they locate are left to the ledger path).
    /// `remove_exclusive`: remove exclusive-container objects (never in
    /// diagnose mode). Fills the swept candidates in memory.
    async fn sweep(
        &self,
        key: Option<&InstallKey>,
        known: &[InstanceId],
        open: &[Effect],
        remove_exclusive: bool,
        notes: &mut Vec<String>,
    ) -> Result<(), ReclaimError> {
        let found = self.deps.sweeper.find_marked(key, known).await?;
        let kept = self.memory().kept.clone();
        let mut swept = BTreeMap::new();
        for object in found {
            if open
                .iter()
                .any(|e| report::locates_record(e, object.kind, &object.key))
            {
                continue;
            }
            let id = report::swept_id(&object);
            if kept.contains(&id) {
                continue;
            }
            // Exclusive resources wait until every kernel process record is
            // closed (kernel verified dead).
            let process_open = open.iter().any(|e| e.kind == EffectKind::Process);
            if remove_exclusive && process_open && object.origin == FoundBy::ExclusiveContainer {
                notes.push(format!(
                    "exclusive-container object {} {:?}: waiting for kernel process records to close",
                    object.kind, object.key
                ));
            } else if remove_exclusive && object.origin == FoundBy::ExclusiveContainer {
                match self.remove_swept(&object).await {
                    Ok(()) => continue,
                    Err(e) => notes.push(format!(
                        "exclusive-container object {} {:?} not removed: {e}",
                        object.kind, object.key
                    )),
                }
            }
            swept.insert(id, object);
        }
        self.memory().swept = swept;
        Ok(())
    }

    /// Remove an object found outside the ledger (exclusive container, or an
    /// administrator's DELETE), then verify it is gone.
    async fn remove_swept(&self, object: &FoundObject) -> Result<(), ReclaimError> {
        let reclaimer = self
            .reclaimers
            .get(&object.kind)
            .ok_or(ReclaimError::Unsupported(object.kind))?;
        let effect = report::synthetic_effect(object);
        reclaimer.reclaim(&effect).await?;
        match reclaimer.probe(&effect).await {
            Probe::Absent => Ok(()),
            Probe::Present(_) => Err(ReclaimError::Indeterminate(
                "still present after removal".into(),
            )),
            Probe::Indeterminate(m) => Err(ReclaimError::Indeterminate(m)),
        }
    }

    /// Report built from the ledger's open records plus the engine's memory.
    async fn build_report(
        &self,
        generations: Option<Vec<GenerationReport>>,
    ) -> Result<ReclaimReport, LedgerError> {
        let open = self.deps.ledger.open_effects(&ScopeFilter::all()).await?;
        let memory = self.memory();
        Ok(report::build(
            &open,
            generations,
            &memory.swept,
            memory.notes.clone(),
        ))
    }

    /// Report of a run without the ledger; kept for `report()`.
    fn offline_report(&self) -> ReclaimReport {
        let mut memory = self.memory();
        let report = report::build(&[], Some(Vec::new()), &memory.swept, memory.notes.clone());
        memory.offline = Some(report.clone());
        report
    }

    /// Product and core-binary records that may be reclaimed now: product
    /// records once no instance generation is open, core-binary records once
    /// no open generation launched from that binary. The others wait.
    async fn shared_ready(&self, notes: &mut Vec<String>) -> Result<Vec<Effect>, LedgerError> {
        let gate = self.shared_gate().await?;
        let mut ready = Vec::new();
        for e in self.deps.ledger.open_effects(&ScopeFilter::all()).await? {
            if e.scope.generation().is_some() {
                continue;
            }
            if gate.waits(&e) && !record::record_only(e.persistence) {
                notes.push(format!(
                    "{}: waiting for the instance generations that may use it to close",
                    report::pending_note(&e)
                ));
            } else {
                ready.push(e);
            }
        }
        Ok(ready)
    }

    /// What open instance generations use, for the shared-scope gate.
    async fn shared_gate(&self) -> Result<SharedGate, LedgerError> {
        let open = self.open_generations(&ScopeFilter::default()).await?;
        let mut gate = SharedGate {
            any_open: !open.is_empty(),
            ..SharedGate::default()
        };
        for (instance, epoch) in &open {
            match self.deps.ledger.generation(instance, *epoch).await? {
                Some(g) => {
                    gate.binaries.insert(report::hex(&g.inputs.core.sha256));
                }
                None => gate.unknown = true,
            }
        }
        Ok(gate)
    }

    /// Why an administrator's DELETE on this record must wait, if it must:
    /// the same gates as automatic reclaim (shared scopes wait for the
    /// generations that may use them; lower ranks of its group still ours
    /// and open; fences until the kernel process record is closed).
    async fn delete_gate(&self, e: &Effect) -> Result<Option<String>, LedgerError> {
        if e.scope.generation().is_none() && self.shared_gate().await?.waits(e) {
            return Ok(Some(
                "instance generations that may use it are still open".into(),
            ));
        }
        let group: Vec<Effect> = self
            .deps
            .ledger
            .open_effects(&ScopeFilter::all())
            .await?
            .into_iter()
            .filter(|o| o.id != e.id && o.scope == e.scope)
            .collect();
        let rank = record::rank_of(&self.reclaimers, e.kind);
        if group
            .iter()
            .any(|o| record::rank_of(&self.reclaimers, o.kind) < rank && record::blocking_state(o))
        {
            return Ok(Some(
                "lower-rank records of its generation are still open".into(),
            ));
        }
        if rank >= crate::rank::FENCE && group.iter().any(|o| o.kind == EffectKind::Process) {
            return Ok(Some("the kernel process is not verified dead".into()));
        }
        Ok(None)
    }

    /// An administrator's DELETE on a swept object: only the object as it
    /// was reported (same key and identity, confirmed now), and a fence only
    /// while no kernel process record is open. `Ok(Err(why))`: refused.
    async fn delete_swept(&self, object: &FoundObject) -> Result<Result<(), String>, LedgerError> {
        let Some(reclaimer) = self.reclaimers.get(&object.kind) else {
            return Ok(Err(format!("no reclaimer for {}", object.kind)));
        };
        // A swept object may belong to a running generation: one re-derived
        // for an instance waits for that instance's open generations, any
        // other for every open generation.
        let filter = match &object.origin {
            FoundBy::DerivedName { instance } => ScopeFilter::instance(instance.clone()),
            _ => ScopeFilter::default(),
        };
        if !self.deps.ledger.open_effects(&filter).await?.is_empty() {
            return Ok(Err(
                "delete refused, instance generations that may use it are still open".into(),
            ));
        }
        if record::rank_of(&self.reclaimers, object.kind) >= crate::rank::FENCE {
            let processes = ScopeFilter {
                kinds: vec![EffectKind::Process],
                ..ScopeFilter::default()
            };
            if !self.deps.ledger.open_effects(&processes).await?.is_empty() {
                return Ok(Err(
                    "delete refused, a kernel process is not verified dead".into()
                ));
            }
        }
        let effect = report::synthetic_effect(object);
        let reported = object.observation.credential.as_ref();
        match reclaimer.probe(&effect).await {
            Probe::Absent => return Ok(Ok(())),
            Probe::Present(now)
                if reported.is_some()
                    && now.credential.as_ref() == reported
                    && now.key.as_ref().is_none_or(|k| *k == object.key) => {}
            Probe::Present(_) => {
                return Ok(Err(
                    "delete refused, the object changed since it was reported or its identity cannot be confirmed".into(),
                ));
            }
            Probe::Indeterminate(m) => {
                return Ok(Err(format!(
                    "delete refused, cannot confirm the object: {m}"
                )));
            }
        }
        Ok(self
            .remove_swept(object)
            .await
            .map_err(|e| format!("delete failed: {e}")))
    }

    fn set_notes(&self, notes: Vec<String>) {
        self.memory().notes = notes;
    }

    /// Append notes, keeping the most recent [`MAX_NOTES`].
    fn add_notes(&self, notes: Vec<String>) {
        let mut m = self.memory();
        m.notes.extend(notes);
        let excess = m.notes.len().saturating_sub(MAX_NOTES);
        m.notes.drain(..excess);
    }
}

#[async_trait]
impl ReclaimEngine for ReclaimEngineImpl {
    async fn reclaim_generation(
        &self,
        instance: &InstanceId,
        epoch: Epoch,
    ) -> Result<GenerationReport, LedgerError> {
        let _run = self.run.lock().await;
        let mut notes = Vec::new();
        let boot = self.boot(&mut notes);
        let mut ctx = self.ctx(boot, &mut notes);
        let report = self.run_generation(&mut ctx, instance, epoch).await?;
        self.add_notes(notes);
        Ok(report)
    }

    async fn reclaim_all(&self, scope: ReclaimScope) -> Result<ReclaimReport, LedgerError> {
        let _run = self.run.lock().await;
        let mut notes = Vec::new();
        let boot = self.boot(&mut notes);
        let instances = ScopeFilter::default();
        let mut generations = Vec::new();
        {
            let mut ctx = self.ctx(boot.clone(), &mut notes);
            for (instance, epoch) in self.open_generations(&instances).await? {
                generations.push(self.run_generation(&mut ctx, &instance, epoch).await?);
            }
            if scope == ReclaimScope::Everything {
                let ready = self.shared_ready(ctx.notes).await?;
                self.run_group(&mut ctx, ready).await?;
            }
        }
        // Sweep: exclusive containers are cleaned, the rest are candidates.
        let open = self.deps.ledger.open_effects(&ScopeFilter::all()).await?;
        let (key, mut known) = self.repair_index(&mut notes);
        let (_, desired) = self.deps.ledger.desired().await?;
        known.extend(desired.iter().filter_map(report::desired_id));
        known.extend(
            open.iter()
                .filter_map(|e| e.scope.generation().map(|(i, _)| i.clone())),
        );
        known.sort();
        known.dedup();
        if let Err(e) = self
            .sweep(key.as_ref(), &known, &open, true, &mut notes)
            .await
        {
            notes.push(format!("sweep failed: {e}"));
        }
        self.set_notes(notes);
        self.build_report(Some(generations)).await
    }

    async fn retry(&self, instance: &InstanceId) -> Result<GenerationReport, LedgerError> {
        let _run = self.run.lock().await;
        let quarantined = ScopeFilter {
            states: vec![EffectState::Quarantined],
            ..ScopeFilter::instance(instance.clone())
        };
        for e in self.deps.ledger.open_effects(&quarantined).await? {
            self.deps
                .ledger
                .transition(&e.id, EffectState::Reclaiming, None)
                .await?;
        }
        let mut notes = Vec::new();
        let boot = self.boot(&mut notes);
        let mut ctx = self.ctx(boot, &mut notes);
        let mut first_open = None;
        let mut last = None;
        for (i, epoch) in self
            .open_generations(&ScopeFilter::instance(instance.clone()))
            .await?
        {
            let report = self.run_generation(&mut ctx, &i, epoch).await?;
            if first_open.is_none() && report.outcome != GenerationOutcome::Closed {
                first_open = Some(report.clone());
            }
            last = Some(report);
        }
        self.add_notes(notes);
        match first_open.or(last) {
            Some(r) => Ok(r),
            None => {
                let next = self.deps.ledger.next_epoch(instance).await?;
                Ok(GenerationReport {
                    instance: instance.clone(),
                    epoch: Epoch(next.0.saturating_sub(1)),
                    outcome: GenerationOutcome::Closed,
                    residues: Vec::new(),
                })
            }
        }
    }

    async fn resolve(&self, decisions: &[CandidateDecision]) -> Result<ReclaimReport, LedgerError> {
        let _run = self.run.lock().await;
        let mut notes = Vec::new();
        for d in decisions {
            let action = d.action();
            match report::parse_id(&d.candidate_id) {
                Some(
                    reference @ (report::CandidateRef::Candidate(..)
                    | report::CandidateRef::Conflict(_)),
                ) => {
                    let Some(id) = reference.effect() else {
                        continue;
                    };
                    let open = self.deps.ledger.open_effects(&ScopeFilter::all()).await?;
                    let Some(e) = open.into_iter().find(|e| e.id == *id) else {
                        notes.push(format!("{}: no such open record", d.candidate_id));
                        continue;
                    };
                    // Each reference kind is checked on its own: a conflict
                    // reference only ever releases a record still in
                    // conflict; a candidate reference binds to the identity
                    // version it was given for (a refreshed candidate has a
                    // new id).
                    let refusal = match &reference {
                        report::CandidateRef::Conflict(_) if e.state != EffectState::Conflict => {
                            Some("not a conflict (any more); decide on the current report")
                        }
                        report::CandidateRef::Conflict(_) if action != CandidateAction::Keep => {
                            Some("a conflict can only be kept")
                        }
                        report::CandidateRef::Candidate(_, version)
                            if e.state != EffectState::Candidate
                                || *version != report::candidate_version(&e) =>
                        {
                            Some(
                                "stale decision, the candidate was refreshed; decide on the current report",
                            )
                        }
                        _ => None,
                    };
                    if let Some(why) = refusal {
                        notes.push(format!("{}: {why}", d.candidate_id));
                        continue;
                    }
                    let gate = match action {
                        CandidateAction::Delete => self.delete_gate(&e).await?,
                        _ => None,
                    };
                    let mut ctx = self.ctx(None, &mut notes);
                    ctx.decide(&e, action, gate).await?;
                }
                Some(report::CandidateRef::Swept) => {
                    let object = self.memory().swept.get(&d.candidate_id).cloned();
                    let Some(object) = object else {
                        notes.push(format!("{}: unknown candidate", d.candidate_id));
                        continue;
                    };
                    match action {
                        CandidateAction::Delete => match self.delete_swept(&object).await? {
                            Ok(()) => {
                                self.memory().swept.remove(&d.candidate_id);
                            }
                            Err(why) => notes.push(format!("{}: {why}", d.candidate_id)),
                        },
                        CandidateAction::Keep => {
                            let mut m = self.memory();
                            m.swept.remove(&d.candidate_id);
                            m.kept.insert(d.candidate_id.clone());
                        }
                        CandidateAction::Unspecified => {
                            notes.push(format!("{}: no action given", d.candidate_id))
                        }
                    }
                }
                None => notes.push(format!("{}: unknown candidate id", d.candidate_id)),
            }
        }
        self.add_notes(notes);
        self.build_report(None).await
    }

    async fn recover_without_ledger(&self) -> Result<ReclaimReport, ReclaimError> {
        let _run = self.run.lock().await;
        let mut notes =
            vec!["ledger unavailable: only exclusive containers are cleaned".to_owned()];
        let (key, known) = self.repair_index(&mut notes);
        self.sweep(key.as_ref(), &known, &[], true, &mut notes)
            .await?;
        self.set_notes(notes);
        Ok(self.offline_report())
    }

    async fn diagnose(&self) -> Result<ReclaimReport, ReclaimError> {
        let _run = self.run.lock().await;
        let mut notes = vec!["diagnose only: nothing is deleted or changed".to_owned()];
        let (key, known) = self.repair_index(&mut notes);
        self.sweep(key.as_ref(), &known, &[], false, &mut notes)
            .await?;
        self.set_notes(notes);
        Ok(self.offline_report())
    }

    async fn reclaim_core(&self, sha256: &str) -> Result<ReclaimReport, LedgerError> {
        let _run = self.run.lock().await;
        for (instance, epoch) in self.open_generations(&ScopeFilter::default()).await? {
            if let Some(g) = self.deps.ledger.generation(&instance, epoch).await?
                && report::hex(&g.inputs.core.sha256).eq_ignore_ascii_case(sha256)
            {
                return Err(LedgerError::EpochOpen {
                    instance,
                    open: epoch,
                });
            }
        }
        let records: Vec<Effect> = self
            .deps
            .ledger
            .open_effects(&ScopeFilter {
                core_binary: true,
                ..ScopeFilter::default()
            })
            .await?
            .into_iter()
            .filter(|e| report::core_scope_of(e).is_some_and(|s| s.eq_ignore_ascii_case(sha256)))
            .collect();
        let mut notes = Vec::new();
        let boot = self.boot(&mut notes);
        {
            let mut ctx = self.ctx(boot, &mut notes);
            self.run_group(&mut ctx, records).await?;
        }
        self.add_notes(notes);
        let open = self.deps.ledger.open_effects(&ScopeFilter::all()).await?;
        let pending: Vec<Effect> = open
            .into_iter()
            .filter(|e| report::core_scope_of(e).is_some_and(|s| s.eq_ignore_ascii_case(sha256)))
            .collect();
        let notes = self.memory().notes.clone();
        Ok(report::build(
            &pending,
            Some(Vec::new()),
            &BTreeMap::new(),
            notes,
        ))
    }

    async fn report(&self) -> Result<ReclaimReport, LedgerError> {
        match self.build_report(None).await {
            Ok(report) => Ok(report),
            // Ledger unreadable: the latest diagnose / recovery report.
            Err(e) => self.memory().offline.clone().ok_or(e),
        }
    }
}

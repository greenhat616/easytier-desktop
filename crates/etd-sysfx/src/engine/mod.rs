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
//! - Within a generation, records are handled rank by rank (lowest first).
//!   A rank whose records are still ours and not gone (failing, quarantined,
//!   indeterminate) stops the higher ranks; fences additionally wait until
//!   every process record of the generation is closed (kernel verified
//!   dead).
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
    async fn run_group(
        &self,
        ctx: &mut Ctx<'_>,
        mut records: Vec<Effect>,
    ) -> Result<(), LedgerError> {
        records.sort_by(|a, b| (ctx.rank(a.kind), &a.id).cmp(&(ctx.rank(b.kind), &b.id)));
        let mut process_open = false;
        let mut blocked = false;
        let mut i = 0;
        while i < records.len() {
            let rank = ctx.rank(records[i].kind);
            let end = records[i..]
                .iter()
                .position(|e| ctx.rank(e.kind) != rank)
                .map_or(records.len(), |n| i + n);
            // Higher ranks wait; their records stay open and show up as
            // residues.
            if blocked || (rank >= crate::rank::FENCE && process_open) {
                break;
            }
            for e in &records[i..end] {
                let outcome = ctx.step(e).await?;
                if e.kind == EffectKind::Process && outcome != RecordOutcome::Closed {
                    process_open = true;
                }
                if outcome.blocks() {
                    blocked = true;
                }
            }
            i = end;
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
            let id = report::swept_id(object.kind, &object.key);
            if kept.contains(&id) {
                continue;
            }
            if remove_exclusive && object.origin == FoundBy::ExclusiveContainer {
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
                let shared: Vec<Effect> = self
                    .deps
                    .ledger
                    .open_effects(&ScopeFilter::all())
                    .await?
                    .into_iter()
                    .filter(|e| e.scope.generation().is_none())
                    .collect();
                self.run_group(&mut ctx, shared).await?;
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
                Some(report::CandidateRef::Record(id)) => {
                    let open = self.deps.ledger.open_effects(&ScopeFilter::all()).await?;
                    let Some(e) = open.into_iter().find(|e| e.id == id) else {
                        notes.push(format!("{}: no such open record", d.candidate_id));
                        continue;
                    };
                    let boot = None;
                    let mut ctx = self.ctx(boot, &mut notes);
                    ctx.decide(&e, action).await?;
                }
                Some(report::CandidateRef::Swept) => {
                    let object = self.memory().swept.get(&d.candidate_id).cloned();
                    let Some(object) = object else {
                        notes.push(format!("{}: unknown candidate", d.candidate_id));
                        continue;
                    };
                    match action {
                        CandidateAction::Delete => match self.remove_swept(&object).await {
                            Ok(()) => {
                                self.memory().swept.remove(&d.candidate_id);
                            }
                            Err(e) => notes.push(format!("{}: delete failed: {e}", d.candidate_id)),
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
        let memory = self.memory();
        Ok(report::build(
            &[],
            Some(Vec::new()),
            &memory.swept,
            memory.notes.clone(),
        ))
    }

    async fn diagnose(&self) -> Result<ReclaimReport, ReclaimError> {
        let _run = self.run.lock().await;
        let mut notes = vec!["diagnose only: nothing is deleted or changed".to_owned()];
        let (key, known) = self.repair_index(&mut notes);
        self.sweep(key.as_ref(), &known, &[], false, &mut notes)
            .await?;
        self.set_notes(notes);
        let memory = self.memory();
        Ok(report::build(
            &[],
            Some(Vec::new()),
            &memory.swept,
            memory.notes.clone(),
        ))
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
        self.build_report(None).await
    }
}

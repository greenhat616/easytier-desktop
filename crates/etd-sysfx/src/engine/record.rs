//! One record: probe, decide, delete, verify.
use super::report;
use crate::*;
use etd_contract::v1::CandidateAction;
use std::{collections::HashMap, sync::Arc};

/// Prefix of `last_error` when the probe could not tell.
pub(super) const INDETERMINATE: &str = "indeterminate: ";

pub(super) struct Ctx<'a> {
    pub ledger: &'a dyn Ledger,
    pub reclaimers: &'a HashMap<EffectKind, Arc<dyn Reclaimer>>,
    /// Current boot id; `None` if unknown (nothing closed unprobed).
    pub boot: Option<BootId>,
    pub notes: &'a mut Vec<String>,
}

/// Where a record stands after one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordOutcome {
    Closed,
    /// Ours, still there or unknown; will be retried.
    Pending,
    /// Quarantined (five failures or uncertain process liveness).
    Quarantined,
    /// Not ours to delete: candidate or conflict, awaiting a decision.
    Held,
}

impl RecordOutcome {
    /// Higher ranks wait while a record of ours is still in the way.
    pub fn blocks(self) -> bool {
        matches!(self, RecordOutcome::Pending | RecordOutcome::Quarantined)
    }
}

/// What a probe result authorises.
enum Authority {
    Delete,
    Candidate,
    Conflict,
}

impl Ctx<'_> {
    pub fn rank(&self, kind: EffectKind) -> u8 {
        self.reclaimers
            .get(&kind)
            .map_or_else(|| kind.default_rank(), |r| r.rank())
    }

    fn rebooted(&self, e: &Effect) -> bool {
        self.boot.as_ref().is_some_and(|b| *b != e.boot)
    }

    async fn close(&self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        self.ledger
            .transition(&e.id, EffectState::Reclaimed, None)
            .await?;
        Ok(RecordOutcome::Closed)
    }

    /// Count a failure; quarantine at [`QUARANTINE_AFTER`].
    async fn fail(&mut self, e: &Effect, error: &str) -> Result<RecordOutcome, LedgerError> {
        let failures = self.ledger.record_failure(&e.id, error).await?;
        if failures >= QUARANTINE_AFTER {
            self.ledger
                .transition(&e.id, EffectState::Quarantined, None)
                .await?;
            Ok(RecordOutcome::Quarantined)
        } else {
            Ok(RecordOutcome::Pending)
        }
    }

    /// One reclaim step for an open record.
    pub async fn step(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        match e.state {
            EffectState::Reclaimed => Ok(RecordOutcome::Closed),
            // Volatile and the machine rebooted: gone with the reboot.
            _ if self.rebooted(e) && e.persistence.closes_on_reboot() => self.close(e).await,
            EffectState::Quarantined => Ok(RecordOutcome::Quarantined),
            EffectState::Candidate | EffectState::Conflict => self.recheck_held(e).await,
            _ => self.reclaim(e).await,
        }
    }

    /// A candidate or conflict closes once its object is gone; it is never
    /// deleted here.
    async fn recheck_held(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        let Some(r) = self.reclaimers.get(&e.kind) else {
            return Ok(RecordOutcome::Held);
        };
        match r.probe(e).await {
            Probe::Absent => self.close(e).await,
            _ => Ok(RecordOutcome::Held),
        }
    }

    async fn reclaim(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        let Some(r) = self.reclaimers.get(&e.kind).cloned() else {
            if let Persistence::Expiring { until } = e.persistence {
                self.notes.push(format!(
                    "{} {:?}: not reclaimable here, expires at {until}",
                    e.kind, e.key
                ));
                return self.close(e).await;
            }
            let err = ReclaimError::Unsupported(e.kind).to_string();
            return self.fail(e, &err).await;
        };
        if e.state != EffectState::Reclaiming {
            self.ledger
                .transition(&e.id, EffectState::Reclaiming, None)
                .await?;
        }
        let found = match r.probe(e).await {
            Probe::Absent => return self.close(e).await,
            Probe::Indeterminate(m) => {
                let error = format!("{INDETERMINATE}{m}");
                if e.kind == EffectKind::Process {
                    // Liveness uncertain: never treated as dead.
                    self.ledger.record_failure(&e.id, &error).await?;
                    self.ledger
                        .transition(&e.id, EffectState::Quarantined, None)
                        .await?;
                    return Ok(RecordOutcome::Quarantined);
                }
                return self.fail(e, &error).await;
            }
            Probe::Present(found) => found,
        };
        match authority(e, &found) {
            Authority::Candidate => {
                self.ledger
                    .transition(
                        &e.id,
                        EffectState::Candidate,
                        Some(report::held_observation(&found, None)),
                    )
                    .await?;
                Ok(RecordOutcome::Held)
            }
            Authority::Conflict => self.conflict(e, &found).await,
            Authority::Delete => match r.reclaim(e).await {
                Err(ReclaimError::CredentialMismatch) => self.conflict(e, &found).await,
                Err(err) => self.fail(e, &err.to_string()).await,
                Ok(done) => self.verify(e, r.as_ref(), done).await,
            },
        }
    }

    async fn conflict(
        &mut self,
        e: &Effect,
        found: &Observation,
    ) -> Result<RecordOutcome, LedgerError> {
        let expected = e.observation.as_ref().and_then(|o| o.credential.clone());
        self.ledger
            .transition(
                &e.id,
                EffectState::Conflict,
                Some(report::held_observation(found, expected)),
            )
            .await?;
        Ok(RecordOutcome::Held)
    }

    /// After a successful reclaim call: settings are done; objects must
    /// probe absent.
    async fn verify(
        &mut self,
        e: &Effect,
        r: &dyn Reclaimer,
        done: Reclaimed,
    ) -> Result<RecordOutcome, LedgerError> {
        if let Undo::RestoreIfOurs { .. } = e.undo {
            if done == Reclaimed::LeftModified {
                self.notes.push(format!(
                    "{} {:?}: changed by someone else since, left as is",
                    e.kind, e.key
                ));
            }
            return self.close(e).await;
        }
        match r.probe(e).await {
            Probe::Absent => self.close(e).await,
            Probe::Present(_) => self.fail(e, "still present after reclaim").await,
            Probe::Indeterminate(m) => self.fail(e, &format!("{INDETERMINATE}{m}")).await,
        }
    }

    /// An administrator's decision on a candidate or conflict record.
    pub async fn decide(&mut self, e: &Effect, action: CandidateAction) -> Result<(), LedgerError> {
        match (e.state, action) {
            (EffectState::Candidate | EffectState::Conflict, CandidateAction::Keep) => {
                self.close(e).await?;
            }
            (EffectState::Candidate, CandidateAction::Delete) => {
                let Some(r) = self.reclaimers.get(&e.kind).cloned() else {
                    self.notes
                        .push(format!("{}: no reclaimer for {}", e.id.0, e.kind));
                    return Ok(());
                };
                // The administrator authorises the delete; a failure leaves
                // the record reclaiming, and the next run lists it again.
                self.ledger
                    .transition(&e.id, EffectState::Reclaiming, None)
                    .await?;
                let outcome = match r.reclaim(e).await {
                    Ok(done) => self.verify(e, r.as_ref(), done).await?,
                    Err(err) => self.fail(e, &err.to_string()).await?,
                };
                if outcome != RecordOutcome::Closed {
                    self.notes
                        .push(format!("{}: delete did not complete", e.id.0));
                }
            }
            (EffectState::Conflict, _) => self
                .notes
                .push(format!("{}: a conflict can only be kept", e.id.0)),
            (state, _) => self.notes.push(format!(
                "{}: record is {state:?}, not awaiting a decision",
                e.id.0
            )),
        }
        Ok(())
    }
}

/// Whether the object a probe found may be deleted.
fn authority(e: &Effect, found: &Observation) -> Authority {
    if matches!(e.undo, Undo::RestoreIfOurs { .. })
        || matches!(
            found.credential,
            Some(Credential::ExclusiveContainer { .. })
        )
        || matches!(e.key, ObjectKey::Fence { .. })
    {
        return Authority::Delete;
    }
    match e.observation.as_ref().and_then(|o| o.credential.as_ref()) {
        Some(recorded) if found.credential.as_ref() == Some(recorded) => Authority::Delete,
        Some(_) => Authority::Conflict,
        None => Authority::Candidate,
    }
}

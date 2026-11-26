//! One record: probe, decide, delete, verify.
//!
//! Deletion authority (doc#2 v7, "名字只用来找到对象，删除要有创建凭据"; no
//! exception for planned records or key types):
//! - the probe reports the object inside an exclusive container
//!   (`Credential::ExclusiveContainer`; fences and runtime directories), or
//! - the probe reads back exactly the credential recorded when the record
//!   was applied.
//!
//! Settings are the one undo that is not a delete: `Undo::RestoreIfOurs`
//! carries both the value we wrote and the original, and the reclaimer's
//! contract is to put the original back only while the current value still
//! equals ours (otherwise `Reclaimed::LeftModified`, nothing touched). A
//! record whose two values are equal has nothing to undo and is closed.
//!
//! `Undo::ReplayUpstreamRecovery` (E1, Magic DNS recovery) is authorised by
//! its reclaimer, which replays upstream's recovery only while no other
//! EasyTier process runs and refuses with a retryable error otherwise; the
//! record's key must probe absent afterwards like any delete. The undo
//! match is exhaustive, so a new undo form must be decided before it
//! compiles.
//!
//! Lease and Expiring records (router mappings) are record-only: they are
//! never reclaimed actively, never block a rank and never hold a generation
//! open; they close at once with a note giving the expected expiry.
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
    /// When this run closed the group's kernel process record, if it did
    /// (lease expiry is counted from then).
    pub process_closed_at: Option<jiff::Timestamp>,
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
    /// Restore a setting if it is still ours.
    Restore,
    /// A setting whose undo changes nothing.
    NothingToUndo,
    /// The undo carries its own authorisation check, done by the reclaimer.
    ByReclaimer,
    Candidate,
    Conflict,
    /// Present, the record has a credential, the probe could not read one.
    Unconfirmed,
}

/// Router mappings and the like: recorded, never reclaimed.
pub(super) fn record_only(p: Persistence) -> bool {
    matches!(p, Persistence::Lease { .. } | Persistence::Expiring { .. })
}

/// Open and still ours: blocks higher ranks of its group.
pub(super) fn blocking_state(e: &Effect) -> bool {
    !record_only(e.persistence)
        && matches!(
            e.state,
            EffectState::Planned
                | EffectState::Applied
                | EffectState::Reclaiming
                | EffectState::Quarantined
        )
}

pub(super) fn rank_of(
    reclaimers: &HashMap<EffectKind, Arc<dyn Reclaimer>>,
    kind: EffectKind,
) -> u8 {
    reclaimers
        .get(&kind)
        .map_or_else(|| kind.default_rank(), |r| r.rank())
}

impl Ctx<'_> {
    pub fn rank(&self, kind: EffectKind) -> u8 {
        rank_of(self.reclaimers, kind)
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

    /// Count a failure; quarantine at [`QUARANTINE_AFTER`]. The record is
    /// `Reclaiming` (L1's state machine: only `Reclaiming -> Quarantined`).
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

    async fn reclaiming(&self, e: &Effect) -> Result<(), LedgerError> {
        if e.state != EffectState::Reclaiming {
            self.ledger
                .transition(&e.id, EffectState::Reclaiming, None)
                .await?;
        }
        Ok(())
    }

    /// One reclaim step for an open record. Each step that reaches the
    /// system is logged with its duration: a slow stop or start must show
    /// which records its time went to.
    pub async fn step(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        let started = std::time::Instant::now();
        let outcome = self.step_record(e).await;
        if e.state != EffectState::Reclaimed {
            tracing::info!(
                stage = "reclaim.record",
                kind = %e.kind,
                key = ?report::lookup_key(e),
                from = ?e.state,
                outcome = ?outcome.as_ref().map_err(ToString::to_string),
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "reclaim step"
            );
        }
        outcome
    }

    async fn step_record(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        match e.state {
            EffectState::Reclaimed => Ok(RecordOutcome::Closed),
            _ if record_only(e.persistence) => self.close_record_only(e).await,
            // Volatile and the machine rebooted: gone with the reboot.
            _ if self.rebooted(e) && e.persistence.closes_on_reboot() => self.close(e).await,
            EffectState::Quarantined => Ok(RecordOutcome::Quarantined),
            EffectState::Candidate | EffectState::Conflict => self.recheck_held(e).await,
            _ => self.reclaim(e).await,
        }
    }

    async fn close_record_only(&mut self, e: &Effect) -> Result<RecordOutcome, LedgerError> {
        let expiry = match e.persistence {
            Persistence::Expiring { until } => format!("expires at {until}"),
            Persistence::Lease { seconds } => match self.process_closed_at {
                Some(at) => format!(
                    "expires {seconds}s after the kernel process ended, at {}",
                    at + jiff::SignedDuration::from_secs(i64::from(seconds))
                ),
                None => format!("expires {seconds}s after the kernel process ended"),
            },
            _ => String::new(),
        };
        self.notes.push(format!(
            "{} {:?}: recorded only, not reclaimed; {expiry}",
            e.kind,
            report::lookup_key(e)
        ));
        self.close(e).await
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
        self.reclaiming(e).await?;
        let Some(r) = self.reclaimers.get(&e.kind).cloned() else {
            let err = ReclaimError::Unsupported(e.kind).to_string();
            return self.fail(e, &err).await;
        };
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
            Authority::NothingToUndo => self.close(e).await,
            Authority::Unconfirmed => {
                self.fail(
                    e,
                    &format!("{INDETERMINATE}present but its credential could not be read"),
                )
                .await
            }
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
            Authority::Delete | Authority::Restore | Authority::ByReclaimer => {
                match r.reclaim(e).await {
                    Err(ReclaimError::CredentialMismatch) => self.conflict(e, &found).await,
                    Err(err) => self.fail(e, &err.to_string()).await,
                    Ok(done) => self.verify(e, r.as_ref(), done).await,
                }
            }
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
    /// `gate`: why a delete must wait (lower ranks, kernel not verified
    /// dead), computed by the caller over the record's group.
    pub async fn decide(
        &mut self,
        e: &Effect,
        action: CandidateAction,
        gate: Option<String>,
    ) -> Result<(), LedgerError> {
        let id = &e.id.0;
        match (e.state, action) {
            (EffectState::Candidate | EffectState::Conflict, CandidateAction::Keep) => {
                self.close(e).await?;
            }
            (EffectState::Candidate, CandidateAction::Delete) => {
                if let Some(why) = gate {
                    self.notes.push(format!("{id}: delete refused, {why}"));
                    return Ok(());
                }
                let Some(r) = self.reclaimers.get(&e.kind).cloned() else {
                    self.notes
                        .push(format!("{id}: no reclaimer for {}", e.kind));
                    return Ok(());
                };
                // The decision covers the object as it was reported: same
                // key, same identity, confirmed right now.
                let reported = report::found_credential(e);
                match r.probe(e).await {
                    Probe::Absent => {
                        self.close(e).await?;
                        return Ok(());
                    }
                    Probe::Present(now)
                        if reported.is_some()
                            && now.credential == reported
                            && now.key.as_ref() == Some(report::lookup_key(e)) => {}
                    Probe::Present(_) => {
                        self.notes.push(format!(
                            "{id}: delete refused, the object changed since it was reported or its identity cannot be confirmed"
                        ));
                        return Ok(());
                    }
                    Probe::Indeterminate(m) => {
                        self.notes.push(format!(
                            "{id}: delete refused, cannot confirm the object: {m}"
                        ));
                        return Ok(());
                    }
                }
                // The approved, re-checked credential goes to the reclaimer
                // for this one call only; it is never persisted, so it never
                // becomes an automatic delete authority. A failure leaves the
                // record reclaiming; the next run lists it again.
                self.reclaiming(e).await?;
                let approved = Effect {
                    state: EffectState::Reclaiming,
                    observation: Some(Observation {
                        credential: reported,
                        key: Some(report::lookup_key(e).clone()),
                        observed_at: jiff::Timestamp::now(),
                        detail: Some("approved by an administrator".into()),
                    }),
                    ..e.clone()
                };
                let outcome = match r.reclaim(&approved).await {
                    Ok(done) => self.verify(&approved, r.as_ref(), done).await?,
                    Err(err) => self.fail(e, &err.to_string()).await?,
                };
                if outcome != RecordOutcome::Closed {
                    self.notes.push(format!("{id}: delete did not complete"));
                }
            }
            (EffectState::Conflict, _) => self
                .notes
                .push(format!("{id}: a conflict can only be kept")),
            (state, _) => self.notes.push(format!(
                "{id}: record is {state:?}, not awaiting a decision"
            )),
        }
        Ok(())
    }
}

/// What the object a probe found authorises.
fn authority(e: &Effect, found: &Observation) -> Authority {
    // Exhaustive on purpose: a new undo form must be decided here before
    // this crate compiles.
    match &e.undo {
        Undo::RestoreIfOurs { ours, original } => {
            return if ours == original {
                Authority::NothingToUndo
            } else {
                Authority::Restore
            };
        }
        // Ruling msg#489: the reclaimer checks its own gate (no other
        // EasyTier process running) and refuses with a retryable error
        // otherwise; the record's key must probe absent afterwards.
        Undo::ReplayUpstreamRecovery => return Authority::ByReclaimer,
        Undo::EnsureAbsent => {}
    }
    if matches!(
        found.credential,
        Some(Credential::ExclusiveContainer { .. })
    ) {
        return Authority::Delete;
    }
    match (
        e.observation.as_ref().and_then(|o| o.credential.as_ref()),
        found.credential.as_ref(),
    ) {
        (Some(recorded), Some(now)) if now == recorded => Authority::Delete,
        (Some(_), Some(_)) => Authority::Conflict,
        (Some(_), None) => Authority::Unconfirmed,
        (None, _) => Authority::Candidate,
    }
}

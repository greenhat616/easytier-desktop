//! Shared transactional state machine. Storage adapters stage changes on a
//! copy and publish it only after the backing transaction succeeds.
use crate::*;
use etd_contract::{Desired, DesiredInstance, InstanceId, Receipt, RequestId, Revision};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default)]
#[doc(hidden)]
pub struct LedgerState {
    pub(super) revision: Revision,
    pub(super) instances: BTreeMap<InstanceId, (DesiredInstance, Vec<String>)>,
    pub(super) spec_revisions: BTreeMap<InstanceId, Revision>,
    pub(super) removal_pending: BTreeSet<InstanceId>,
    pub(super) settings: HostSettings,
    pub(super) requests: BTreeMap<RequestId, (RequestRecord, Ticket)>,
    pub(super) high_water: BTreeMap<InstanceId, Epoch>,
    pub(super) generations: BTreeMap<(InstanceId, Epoch), GenerationEntry>,
    pub(super) effects: BTreeMap<EffectId, Effect>,
    pub(super) next_effect: u64,
}

#[derive(Clone)]
pub(super) struct GenerationEntry {
    pub(super) inputs: LaunchInputs,
    pub(super) claims: Vec<String>,
    pub(super) shared: Vec<EffectId>,
}

impl LedgerState {
    pub fn request_status(&self, request: &RequestRecord) -> RequestStatus {
        match self.requests.get(&request.request_id) {
            None => RequestStatus::New,
            Some((original, ticket))
                if original.digest == request.digest && original.caller == request.caller =>
            {
                RequestStatus::Done(ticket.receipt.clone())
            }
            Some(_) => RequestStatus::Reused,
        }
    }

    pub fn receipt(&self, request: &RequestId) -> Option<Receipt> {
        self.receipt_for(request, None)
    }

    pub fn receipt_for(&self, request: &RequestId, caller: Option<&str>) -> Option<Receipt> {
        self.requests
            .get(request)
            .filter(|(r, _)| caller.is_none_or(|c| r.caller == c))
            .map(|(_, t)| t.receipt.clone())
    }

    pub fn pending_tickets(&self) -> Vec<Ticket> {
        let mut tickets: Vec<_> = self
            .requests
            .values()
            .filter_map(|(_, t)| (!t.done).then_some(t.clone()))
            .collect();
        tickets.sort_by_key(|t| t.receipt.revision);
        tickets
    }

    pub fn complete_ticket(&mut self, ticket: &str) -> Result<(), LedgerError> {
        if self.is_purge_ticket(ticket)
            && let Some(instance) = self.removal_pending.iter().next()
        {
            return Err(LedgerError::RemovalPending {
                instance: instance.clone(),
            });
        }
        let (_, t) = self
            .requests
            .values_mut()
            .find(|(_, t)| t.receipt.ticket == ticket)
            .ok_or_else(|| LedgerError::UnknownTicket(ticket.to_owned()))?;
        t.done = true;
        // Completed tickets are not replayed; the request, caller, digest
        // and original receipt are enough for idempotency.
        t.changes.clear();
        t.generations.clear();
        Ok(())
    }

    pub(super) fn has_pending_purge(&self) -> bool {
        self.requests
            .values()
            .any(|(_, t)| !t.done && t.changes.iter().any(|c| matches!(c, Change::PurgeAll)))
    }

    pub(super) fn is_purge_request(&self, id: &RequestId) -> bool {
        self.requests.get(id).is_some_and(|(_, t)| {
            !t.done && t.changes.iter().any(|c| matches!(c, Change::PurgeAll))
        })
    }

    pub(super) fn is_purge_ticket(&self, ticket: &str) -> bool {
        self.requests.values().any(|(_, t)| {
            t.receipt.ticket == ticket
                && !t.done
                && t.changes.iter().any(|c| matches!(c, Change::PurgeAll))
        })
    }

    pub(super) fn scrub_completed(&mut self) -> bool {
        let mut changed = false;
        for (_, t) in self.requests.values_mut() {
            if t.done && (!t.changes.is_empty() || !t.generations.is_empty()) {
                t.changes.clear();
                t.generations.clear();
                changed = true;
            }
        }
        changed
    }

    pub fn desired(&self) -> (Revision, Vec<DesiredInstance>) {
        (
            self.revision,
            self.instances.values().map(|(i, _)| i.clone()).collect(),
        )
    }

    pub fn spec_revision(&self, instance: &InstanceId) -> Result<Revision, LedgerError> {
        self.spec_revisions
            .get(instance)
            .copied()
            .ok_or_else(|| LedgerError::UnknownInstance(instance.clone()))
    }

    pub fn settings(&self) -> HostSettings {
        self.settings.clone()
    }

    fn open_generation(&self, instance: &InstanceId, epoch: Epoch) -> bool {
        self.effects
            .values()
            .any(|e| e.scope.generation() == Some((instance, epoch)) && !e.state.is_closed())
    }

    pub fn claims(&self) -> Vec<ClaimHold> {
        let mut claims = Vec::new();
        for (instance, (desired, resources)) in &self.instances {
            if desired.desired() == Desired::Running {
                claims.extend(resources.iter().map(|resource| ClaimHold {
                    resource: resource.clone(),
                    instance: instance.clone(),
                    source: ClaimSource::Desired,
                }));
            }
        }
        for ((instance, epoch), entry) in &self.generations {
            if self.open_generation(instance, *epoch) {
                claims.extend(entry.claims.iter().map(|resource| ClaimHold {
                    resource: resource.clone(),
                    instance: instance.clone(),
                    source: ClaimSource::Generation(*epoch),
                }));
            }
        }
        claims
    }

    pub fn next_epoch(&self, instance: &InstanceId) -> Result<Epoch, LedgerError> {
        let previous = self.high_water.get(instance).map_or(0, |epoch| epoch.0);
        Ok(Epoch(
            previous
                .checked_add(1)
                .ok_or(LedgerError::CounterExhausted("epoch"))?,
        ))
    }

    fn ensure_closed(&self, instance: &InstanceId) -> Result<(), LedgerError> {
        if let Some((_, open)) = self
            .generations
            .keys()
            .find(|(i, e)| i == instance && self.open_generation(i, *e))
        {
            return Err(LedgerError::EpochOpen {
                instance: instance.clone(),
                open: *open,
            });
        }
        Ok(())
    }

    fn reject_pending_removal(&self, instance: &InstanceId) -> Result<(), LedgerError> {
        if self.removal_pending.contains(instance) {
            return Err(LedgerError::RemovalPending {
                instance: instance.clone(),
            });
        }
        Ok(())
    }

    fn remove_instance(&mut self, instance: &InstanceId) -> Result<(), LedgerError> {
        let (stored, _) = self
            .instances
            .get_mut(instance)
            .ok_or_else(|| LedgerError::UnknownInstance(instance.clone()))?;
        stored.desired = Desired::Stopped as i32;
        if self.ensure_closed(instance).is_ok() {
            self.instances.remove(instance);
            self.spec_revisions.remove(instance);
            self.removal_pending.remove(instance);
        } else {
            self.removal_pending.insert(instance.clone());
        }
        Ok(())
    }

    fn check_claims(
        &self,
        instance: &InstanceId,
        resources: &[String],
        desired_only: bool,
    ) -> Result<(), LedgerError> {
        for claim in self.claims() {
            if claim.instance != *instance
                && resources.contains(&claim.resource)
                && (!desired_only || claim.source == ClaimSource::Desired)
            {
                return Err(LedgerError::ExclusiveTaken {
                    resource: claim.resource,
                    holder: claim.instance,
                });
            }
        }
        Ok(())
    }

    fn apply_change(&mut self, change: &Change) -> Result<(), LedgerError> {
        match change {
            Change::PutInstance { instance, claims } => {
                self.reject_pending_removal(&InstanceId(instance.instance_id.clone()))?;
                let mut claims = claims.clone();
                claims.sort();
                claims.dedup();
                self.instances.insert(
                    InstanceId(instance.instance_id.clone()),
                    (*instance.clone(), claims),
                );
                self.spec_revisions
                    .insert(InstanceId(instance.instance_id.clone()), self.revision);
            }
            Change::SetDesired { instance, desired } => {
                self.reject_pending_removal(instance)?;
                let (stored, _) = self
                    .instances
                    .get_mut(instance)
                    .ok_or_else(|| LedgerError::UnknownInstance(instance.clone()))?;
                stored.desired = *desired as i32;
            }
            Change::RemoveInstance(instance) => {
                self.remove_instance(instance)?;
            }
            Change::RetryReclaim(instance) | Change::RetryStart(instance) => {
                if matches!(change, Change::RetryStart(_)) {
                    self.reject_pending_removal(instance)?;
                }
                if !self.instances.contains_key(instance) {
                    return Err(LedgerError::UnknownInstance(instance.clone()));
                }
            }
            Change::ResolveCandidates(_) => {}
            Change::SetAllowList(entries) => self.settings.allow_list.clone_from(entries),
            Change::SelectCore(core) => self.settings.selected_core.clone_from(core),
            Change::PurgeAll => {
                // Stop intent is durable before the orchestrator performs
                // reclaim. Do not discard open ownership records.
                let ids: Vec<_> = self.instances.keys().cloned().collect();
                for instance in ids {
                    self.remove_instance(&instance)?;
                }
                // The allow-list is host security configuration, not user data.
                self.settings.selected_core = None;
                self.requests.clear();
                self.compact_closed_effects();
            }
        }
        Ok(())
    }

    pub fn commit(
        &mut self,
        expected: Revision,
        change: ChangeSet,
        boot: &BootId,
        now: jiff::Timestamp,
    ) -> Result<Receipt, LedgerError> {
        match self.request_status(&change.request) {
            RequestStatus::Done(receipt) => return Ok(receipt),
            RequestStatus::Reused => {
                return Err(LedgerError::RequestReused(change.request.request_id));
            }
            RequestStatus::New => {}
        }
        if self.revision != expected {
            return Err(LedgerError::Conflict {
                current: self.revision,
            });
        }
        let mut staged = self.clone();
        staged.revision = staged
            .revision
            .checked_add(1)
            .ok_or(LedgerError::CounterExhausted("revision"))?;
        for item in &change.changes {
            staged.apply_change(item)?;
        }
        for (id, (instance, resources)) in &staged.instances {
            if instance.desired() == Desired::Running {
                staged.check_claims(id, resources, true)?;
            }
        }
        let generations = change
            .generations
            .iter()
            .map(|g| (g.instance.clone(), g.epoch))
            .collect();
        for plan in change.generations {
            staged.reserve(plan, boot, now)?;
        }
        let receipt = Receipt {
            request_id: change.request.request_id.0.clone(),
            revision: staged.revision,
            ticket: format!("ticket-{:020}", staged.revision),
            accepted_unix_ms: now.as_millisecond(),
        };
        staged.requests.insert(
            change.request.request_id.clone(),
            (
                change.request,
                Ticket {
                    receipt: receipt.clone(),
                    changes: change.changes,
                    generations,
                    done: false,
                },
            ),
        );
        *self = staged;
        Ok(receipt)
    }

    pub fn begin_epoch(
        &mut self,
        plan: GenerationPlan,
        boot: &BootId,
        now: jiff::Timestamp,
    ) -> Result<Vec<Effect>, LedgerError> {
        let mut staged = self.clone();
        let effects = staged.reserve(plan, boot, now)?;
        *self = staged;
        Ok(effects)
    }

    fn reserve(
        &mut self,
        plan: GenerationPlan,
        boot: &BootId,
        now: jiff::Timestamp,
    ) -> Result<Vec<Effect>, LedgerError> {
        let next = self.next_epoch(&plan.instance)?;
        if next != plan.epoch {
            return Err(LedgerError::EpochNotNext {
                instance: plan.instance,
                next,
                got: plan.epoch,
            });
        }
        let (desired, _) = self
            .instances
            .get(&plan.instance)
            .ok_or_else(|| LedgerError::UnknownInstance(plan.instance.clone()))?;
        self.reject_pending_removal(&plan.instance)?;
        self.ensure_closed(&plan.instance)?;
        if desired.desired() != Desired::Running {
            return Err(LedgerError::InvalidPlan {
                instance: plan.instance,
                reason: "instance is not desired RUNNING".into(),
            });
        }
        let config_revision = self.spec_revision(&plan.instance)?;
        if plan.inputs.spec_revision != config_revision {
            return Err(LedgerError::Conflict {
                current: config_revision,
            });
        }
        if desired.spec.as_ref() != Some(&plan.inputs.spec) {
            return Err(LedgerError::InvalidPlan {
                instance: plan.instance,
                reason: "planned spec differs from committed config".into(),
            });
        }
        self.check_claims(&plan.instance, &plan.claims, false)?;
        if !plan.effects.iter().any(|e| {
            e.kind == EffectKind::Process
                && e.scope.generation() == Some((&plan.instance, plan.epoch))
        }) {
            return Err(LedgerError::InvalidPlan {
                instance: plan.instance,
                reason: "missing generation-scoped process intent".into(),
            });
        }
        for intent in &plan.effects {
            if let Some((instance, epoch)) = intent.scope.generation()
                && (instance != &plan.instance || epoch != plan.epoch)
            {
                return Err(LedgerError::InvalidPlan {
                    instance: plan.instance,
                    reason: "effect scoped to wrong generation".into(),
                });
            }
        }
        let mut claims = plan.claims;
        claims.sort();
        claims.dedup();
        self.high_water.insert(plan.instance.clone(), plan.epoch);
        let effects: Vec<_> = plan
            .effects
            .into_iter()
            .map(|intent| self.insert_effect(intent, boot, now))
            .collect::<Result<_, _>>()?;
        let shared = effects
            .iter()
            .filter(|e| e.scope.generation().is_none())
            .map(|e| e.id.clone())
            .collect();
        self.generations.insert(
            (plan.instance, plan.epoch),
            GenerationEntry {
                inputs: plan.inputs,
                claims,
                shared,
            },
        );
        Ok(effects)
    }

    pub fn generation(&self, instance: &InstanceId, epoch: Epoch) -> Option<StoredGeneration> {
        let entry = self.generations.get(&(instance.clone(), epoch))?;
        let effects = self
            .effects
            .values()
            .filter(|e| {
                e.scope.generation() == Some((instance, epoch)) || entry.shared.contains(&e.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        Some(StoredGeneration {
            inputs: entry.inputs.clone(),
            claims: entry.claims.clone(),
            closed: !self.open_generation(instance, epoch),
            effects,
        })
    }

    pub fn record(
        &mut self,
        intent: EffectIntent,
        boot: &BootId,
        now: jiff::Timestamp,
    ) -> Result<Effect, LedgerError> {
        if let Some((instance, epoch)) = intent.scope.generation()
            && !self.open_generation(instance, epoch)
        {
            let next = self.next_epoch(instance)?;
            if epoch < next {
                return Err(LedgerError::InvalidTransition {
                    from: EffectState::Reclaimed,
                    to: EffectState::Planned,
                });
            }
            if !self.instances.contains_key(instance) {
                return Err(LedgerError::UnknownInstance(instance.clone()));
            }
            return Err(LedgerError::EpochNotNext {
                instance: instance.clone(),
                next,
                got: epoch,
            });
        }
        self.insert_effect(intent, boot, now)
    }

    fn insert_effect(
        &mut self,
        intent: EffectIntent,
        boot: &BootId,
        now: jiff::Timestamp,
    ) -> Result<Effect, LedgerError> {
        if intent.scope.generation().is_none()
            && let Some(existing) = self.effects.values().find(|e| {
                !e.state.is_closed()
                    && e.scope == intent.scope
                    && e.kind == intent.kind
                    && e.key == intent.key
            })
        {
            return Ok(existing.clone());
        }
        self.next_effect = self
            .next_effect
            .checked_add(1)
            .ok_or(LedgerError::CounterExhausted("effect id"))?;
        let effect = Effect {
            id: EffectId(format!("{:020}", self.next_effect)),
            scope: intent.scope,
            kind: intent.kind,
            key: intent.key,
            undo: intent.undo,
            persistence: intent.persistence,
            state: EffectState::Planned,
            boot: boot.clone(),
            observation: None,
            failures: 0,
            last_error: None,
            recorded_at: now,
        };
        self.effects.insert(effect.id.clone(), effect.clone());
        Ok(effect)
    }

    pub fn transition(
        &mut self,
        id: &EffectId,
        to: EffectState,
        obs: Option<Observation>,
    ) -> Result<(), LedgerError> {
        use EffectState::*;
        let e = self
            .effects
            .get_mut(id)
            .ok_or_else(|| LedgerError::UnknownEffect(id.clone()))?;
        let from = e.state;
        let allowed = from == to
            || matches!(
                (from, to),
                (Planned, Applied | Reclaiming | Reclaimed)
                    | (Applied, Reclaiming | Reclaimed)
                    | (Reclaiming, Reclaimed | Candidate | Conflict | Quarantined)
                    | (Quarantined, Reclaiming | Reclaimed)
                    | (Candidate, Reclaiming | Reclaimed)
                    | (Conflict, Reclaimed)
            );
        if !allowed {
            return Err(LedgerError::InvalidTransition { from, to });
        }
        if to == Reclaimed || (from == Quarantined && to != Quarantined) {
            e.failures = 0;
            e.last_error = None;
        }
        e.state = to;
        if obs.is_some() {
            e.observation = obs;
        }
        if to == Reclaimed
            && let Some((instance, _)) = e.scope.generation()
        {
            let instance = instance.clone();
            if self.removal_pending.contains(&instance) && self.ensure_closed(&instance).is_ok() {
                // Config removal is itself a desired-state change. Advance
                // revision so a pre-removal planner cannot revive it.
                self.revision = self
                    .revision
                    .checked_add(1)
                    .ok_or(LedgerError::CounterExhausted("revision"))?;
                self.instances.remove(&instance);
                self.spec_revisions.remove(&instance);
                self.removal_pending.remove(&instance);
            }
        }
        if to == Reclaimed && self.has_pending_purge() {
            self.compact_closed_effects();
        }
        Ok(())
    }

    pub fn record_failure(&mut self, id: &EffectId, error: &str) -> Result<u32, LedgerError> {
        let e = self
            .effects
            .get_mut(id)
            .ok_or_else(|| LedgerError::UnknownEffect(id.clone()))?;
        if e.state.is_closed() {
            return Err(LedgerError::InvalidTransition {
                from: e.state,
                to: EffectState::Reclaiming,
            });
        }
        e.failures = e.failures.saturating_add(1);
        e.last_error = Some(error.to_owned());
        Ok(e.failures)
    }

    pub fn open_effects(&self, filter: &ScopeFilter) -> Vec<Effect> {
        self.effects
            .values()
            .filter(|e| {
                !e.state.is_closed()
                    && (filter.kinds.is_empty() || filter.kinds.contains(&e.kind))
                    && (filter.states.is_empty() || filter.states.contains(&e.state))
                    && match &e.scope {
                        EffectScope::Instance { instance, epoch } => {
                            filter.instance.as_ref().is_none_or(|i| i == instance)
                                && filter.epoch.is_none_or(|n| n == *epoch)
                        }
                        EffectScope::Product => filter.product,
                        EffectScope::CoreBinary { .. } => filter.core_binary,
                    }
            })
            .cloned()
            .collect()
    }

    pub fn compact(&mut self) -> usize {
        self.compact_receipts(jiff::Timestamp::now());
        self.compact_closed_effects()
    }

    fn compact_receipts(&mut self, now: jiff::Timestamp) {
        const KEEP_COUNT: usize = 1000;
        const KEEP_MS: i64 = 7 * 24 * 60 * 60 * 1000;
        let cutoff = now.as_millisecond().saturating_sub(KEEP_MS);
        let mut done: Vec<_> = self
            .requests
            .iter()
            .filter_map(|(id, (_, t))| {
                t.done
                    .then_some((id.clone(), t.receipt.revision, t.receipt.accepted_unix_ms))
            })
            .collect();
        done.sort_by_key(|(_, rev, _)| std::cmp::Reverse(*rev));
        for (id, _, at) in done.into_iter().skip(KEEP_COUNT) {
            if at < cutoff {
                self.requests.remove(&id);
            }
        }
    }

    fn compact_closed_effects(&mut self) -> usize {
        let closed: Vec<_> = self
            .generations
            .keys()
            .filter(|(i, e)| !self.open_generation(i, *e))
            .cloned()
            .collect();
        for key in closed {
            self.generations.remove(&key);
        }
        let before = self.effects.len();
        // Preserve complete generation replay while any record is open.
        self.effects.retain(|_, e| {
            !e.state.is_closed()
                || e.scope
                    .generation()
                    .is_some_and(|(i, n)| self.generations.contains_key(&(i.clone(), n)))
                || self
                    .generations
                    .values()
                    .any(|entry| entry.shared.contains(&e.id))
        });
        before - self.effects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_keeps_recent_or_newest_thousand_and_pending() {
        let now = jiff::Timestamp::from_millisecond(1_000_000_000).unwrap();
        let mut state = LedgerState::default();
        for n in 0..1004 {
            let request_id = RequestId(format!("request-{n}"));
            let receipt = Receipt {
                request_id: request_id.0.clone(),
                revision: n + 1,
                ticket: format!("ticket-{n}"),
                accepted_unix_ms: if n == 1 { now.as_millisecond() } else { 0 },
            };
            state.requests.insert(
                request_id.clone(),
                (
                    RequestRecord {
                        request_id,
                        caller: "test".into(),
                        digest: RequestDigest([0; 32]),
                    },
                    Ticket {
                        receipt,
                        changes: vec![],
                        generations: vec![],
                        done: n != 0,
                    },
                ),
            );
        }
        state.compact_receipts(now);
        assert!(state.requests.contains_key(&"request-0".into())); // pending
        assert!(state.requests.contains_key(&"request-1".into())); // recent
        assert!(!state.requests.contains_key(&"request-2".into())); // old and outside 1000
        assert!(!state.requests.contains_key(&"request-3".into()));
        assert!(state.requests.contains_key(&"request-4".into()));
        assert_eq!(state.requests.len(), 1002);
    }
}

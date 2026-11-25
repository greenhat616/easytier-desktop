//! Fake system with injectable failures at every step. Owned by R1 (M1).
//!
//! One [`FakeSystem`] is an in-memory machine: a set of objects (interfaces,
//! rules, registry values, fences, ...) each with a concrete key, an
//! optional creation credential and an owner (ours or foreign). Handles
//! built from it implement every system-facing `etd_sysfx` trait over the
//! same state:
//!
//! | trait | handle |
//! |---|---|
//! | `Reclaimer` (one per kind) | [`FakeSystem::reclaimer`], [`FakeSystem::reclaimers`] |
//! | `Sweeper` | [`FakeSystem::sweeper`] |
//! | `BootIdSource` | [`FakeSystem::boot_id_source`] |
//! | `SystemObserver` | [`FakeSystem::observer`] |
//! | `PortFence` | [`FakeSystem::fence`] |
//!
//! Tests drive the world with [`FakeSystem::apply_intent`] (what the kernel
//! or host would create for a planned effect), [`FakeSystem::create_foreign`]
//! (third-party objects, possibly with our full derived name),
//! [`FakeSystem::vanish`], [`FakeSystem::reboot`] and friends, inject faults
//! with [`FakeSystem::inject`] / [`FakeSystem::crash_at`], and check the
//! outcome against the system itself: [`FakeSystem::ours`],
//! [`FakeSystem::foreign_deleted`], [`FakeSystem::stats`],
//! [`FakeSystem::ops`].
//!
//! The fake reclaimers behave like real ones: they act on whatever object
//! the key locates, without checking credentials (that is the engine's
//! job), so an engine that deletes on a name alone is caught by
//! [`FakeSystem::foreign_deleted`].
use async_trait::async_trait;
use etd_contract::InstanceId;
use etd_sysfx::{
    BootId, BootIdSource, Credential, DirectionResult, Effect, EffectIntent, EffectKind,
    EffectScope, FenceError, FenceSpec, FenceVerification, FoundBy, FoundObject, InstallKey,
    InterfaceInfo, ListenerCheck, ListenerInfo, ObjectKey, Observation, ObserveError, PortFence,
    Probe, ReclaimError, Reclaimed, Reclaimer, SettingValue, Sweeper, SystemClass, SystemEntry,
    SystemObserver, Undo, naming,
};
use futures_util::future::BoxFuture;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

/// Panic payload of an injected crash ([`FaultAction::Crash`],
/// [`FakeSystem::crash_at`]). A test runs the code under test in a task and
/// treats a panic with this message as "the process died here".
pub const CRASH: &str = "fake system: injected crash";

/// Default container name of the fake fence.
pub const FENCE_CONTAINER: &str = "etd-fence";
/// Container name of runtime directories in the fake system.
pub const RUN_CONTAINER: &str = "etd-run";

/// Who an object in the fake system belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Owner {
    /// Created by the product (or the kernel on its behalf).
    Ours,
    /// Created by someone else; the product must never delete it.
    Foreign,
}

/// Handle of one object in the fake system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

/// One object in the fake system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeObject {
    pub id: ObjectId,
    pub kind: EffectKind,
    /// Concrete key as the object exists (utun name assigned, router port
    /// assigned, ...).
    pub key: ObjectKey,
    /// Creation identity read back by probes; `None` where the object type
    /// has none (registry values).
    pub credential: Option<Credential>,
    pub owner: Owner,
    /// Current value of a setting (registry value); `None` for objects.
    pub value: Option<SettingValue>,
    /// Disappears on [`FakeSystem::reboot`].
    pub volatile: bool,
    /// Process holding the object (interfaces: `interfaces_owned_by`).
    pub pid: Option<u32>,
    /// Interface addresses (basic readiness).
    pub addresses: Vec<(IpAddr, u8)>,
    pub up: bool,
    /// Expires on its own at this time (router leases).
    pub expires: Option<jiff::Timestamp>,
}

/// A deleted object, as recorded by the fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deletion {
    pub object: FakeObject,
    /// Which path removed it.
    pub by: Step,
}

/// The system call an operation or a fault refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Probe,
    Reclaim,
    Sweep,
    BootId,
    Observe,
    FenceInstall,
    FenceVerify,
    FenceRemove,
}

impl Step {
    /// Steps that change the system.
    pub fn writes(self) -> bool {
        matches!(self, Step::Reclaim | Step::FenceInstall | Step::FenceRemove)
    }
}

/// What an injected fault does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultAction {
    /// Fail before touching the system. Probes report
    /// `Probe::Indeterminate`, observer and fence calls map the error to
    /// their own error type.
    Fail(ReclaimError),
    /// Apply the change, then report this error (the call went through, the
    /// answer was lost).
    FailAfterApply(ReclaimError),
    /// Panic with [`CRASH`] before touching the system.
    Crash,
    /// Apply the change, then panic with [`CRASH`].
    CrashAfterApply,
}

/// An injected fault: which calls it matches, how often, what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub step: Step,
    /// `None`: any kind.
    pub kind: Option<EffectKind>,
    /// `None`: any key; otherwise calls whose key locates this one.
    pub key: Option<ObjectKey>,
    /// `None`: forever.
    pub times: Option<u32>,
    pub action: FaultAction,
}

impl Fault {
    /// Fault on every call of `step`, failing with `Indeterminate`.
    pub fn on(step: Step) -> Self {
        Self {
            step,
            kind: None,
            key: None,
            times: None,
            action: FaultAction::Fail(ReclaimError::Indeterminate("injected".into())),
        }
    }
    pub fn kind(mut self, kind: EffectKind) -> Self {
        self.kind = Some(kind);
        self
    }
    pub fn key(mut self, key: ObjectKey) -> Self {
        self.key = Some(key);
        self
    }
    /// Only the next `n` matching calls.
    pub fn times(mut self, n: u32) -> Self {
        self.times = Some(n);
        self
    }
    pub fn once(self) -> Self {
        self.times(1)
    }
    pub fn fail(mut self, error: ReclaimError) -> Self {
        self.action = FaultAction::Fail(error);
        self
    }
    pub fn fail_after_apply(mut self, error: ReclaimError) -> Self {
        self.action = FaultAction::FailAfterApply(error);
        self
    }
    pub fn crash(mut self) -> Self {
        self.action = FaultAction::Crash;
        self
    }
    pub fn crash_after_apply(mut self) -> Self {
        self.action = FaultAction::CrashAfterApply;
        self
    }

    fn matches(&self, step: Step, kind: Option<EffectKind>, key: Option<&ObjectKey>) -> bool {
        self.step == step
            && self.times != Some(0)
            && self.kind.is_none_or(|k| Some(k) == kind)
            && self
                .key
                .as_ref()
                .is_none_or(|want| key.is_some_and(|key| locates(want, key) || locates(key, want)))
    }
}

/// One system call seen by the fake, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecord {
    /// 0-based position among all calls (the index [`FakeSystem::crash_at`]
    /// takes).
    pub index: u64,
    pub step: Step,
    pub kind: Option<EffectKind>,
    pub key: Option<ObjectKey>,
    pub outcome: String,
}

/// Call counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Every call of every step.
    pub calls: u64,
    pub probes: u64,
    /// Calls that may change the system (reclaim, fence install / remove),
    /// whatever their outcome. "No system write" means this stays put.
    pub write_calls: u64,
    /// Calls that actually changed the system.
    pub mutations: u64,
    pub sweeps: u64,
    pub observations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrashPoint {
    at: u64,
    after_apply: bool,
}

#[derive(Debug)]
struct State {
    next_id: u64,
    objects: BTreeMap<ObjectId, FakeObject>,
    deleted: Vec<Deletion>,
    boot: BootId,
    boots: u64,
    now: jiff::Timestamp,
    listeners: BTreeMap<SocketAddr, u32>,
    faults: Vec<Fault>,
    crash: Option<CrashPoint>,
    stats: Stats,
    ops: Vec<OpRecord>,
    fence_override: Option<FenceVerification>,
}

/// What a matched fault (or crash point) tells the caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Proceed,
    Fail(ReclaimError),
    FailAfterApply(ReclaimError),
    Crash,
    CrashAfterApply,
}

/// In-memory machine shared by every fake handle. Cheap to clone.
#[derive(Debug, Clone)]
pub struct FakeSystem {
    inner: Arc<Mutex<State>>,
}

impl Default for FakeSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeSystem {
    /// Empty system, boot id `boot-1`, clock at the current wall time.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                next_id: 1,
                objects: BTreeMap::new(),
                deleted: Vec::new(),
                boot: BootId("boot-1".into()),
                boots: 1,
                now: jiff::Timestamp::now(),
                listeners: BTreeMap::new(),
                faults: Vec::new(),
                crash: None,
                stats: Stats::default(),
                ops: Vec::new(),
                fence_override: None,
            })),
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ----- handles -------------------------------------------------------

    /// Reclaimer for one kind (rank = `kind.default_rank()`).
    pub fn reclaimer(&self, kind: EffectKind) -> Arc<dyn Reclaimer> {
        Arc::new(FakeReclaimer {
            sys: self.clone(),
            kind,
            rank: kind.default_rank(),
        })
    }

    /// Reclaimer for one kind with a non-default rank.
    pub fn reclaimer_with_rank(&self, kind: EffectKind, rank: u8) -> Arc<dyn Reclaimer> {
        Arc::new(FakeReclaimer {
            sys: self.clone(),
            kind,
            rank,
        })
    }

    /// One reclaimer per [`EffectKind`].
    pub fn reclaimers(&self) -> Vec<Arc<dyn Reclaimer>> {
        self.reclaimers_for(EffectKind::ALL)
    }

    pub fn reclaimers_for(&self, kinds: &[EffectKind]) -> Vec<Arc<dyn Reclaimer>> {
        kinds.iter().map(|k| self.reclaimer(*k)).collect()
    }

    pub fn sweeper(&self) -> Arc<dyn Sweeper> {
        Arc::new(self.clone())
    }

    pub fn boot_id_source(&self) -> Arc<dyn BootIdSource> {
        Arc::new(self.clone())
    }

    pub fn observer(&self) -> Arc<dyn SystemObserver> {
        Arc::new(self.clone())
    }

    /// Fence of the given kind (`WinFenceFilter`, `LinuxFenceRule` or
    /// `MacFenceRule`) in [`FENCE_CONTAINER`].
    pub fn fence(&self, kind: EffectKind) -> Arc<dyn PortFence> {
        Arc::new(FakeFence {
            sys: self.clone(),
            kind,
            container: FENCE_CONTAINER.into(),
        })
    }

    // ----- shaping the world --------------------------------------------

    /// Insert an object as given (its `id` is replaced). Returns its id.
    pub fn insert(&self, mut object: FakeObject) -> ObjectId {
        let mut st = self.st();
        let id = ObjectId(st.next_id);
        st.next_id += 1;
        object.id = id;
        st.objects.insert(id, object);
        id
    }

    /// What the kernel or host creates for a planned effect: an object of
    /// ours with a fresh credential, the concrete key filled in (utun name,
    /// router port), settings set to the value we write, volatile if the
    /// intent's persistence closes on reboot. Returns the observation the
    /// host would record when applying the record.
    pub fn apply_intent(&self, intent: &EffectIntent) -> Observation {
        self.apply_intent_with_pid(intent, None)
    }

    /// [`FakeSystem::apply_intent`] for an object held by process `pid`.
    pub fn apply_intent_with_pid(&self, intent: &EffectIntent, pid: Option<u32>) -> Observation {
        let mut st = self.st();
        let n = st.next_id;
        let now = st.now;
        let key = concrete_key(&intent.key, n);
        let value = match &intent.undo {
            Undo::RestoreIfOurs { ours, .. } => Some(ours.clone()),
            _ => None,
        };
        // Settings: change the existing value in place if there is one.
        if value.is_some()
            && let Some(obj) = st
                .objects
                .values_mut()
                .find(|o| o.kind == intent.kind && locates(&key, &o.key))
        {
            obj.value = value;
            obj.owner = Owner::Ours;
            let obs = observation_of(obj, now);
            st.stats.mutations += 1;
            return obs;
        }
        let credential = default_credential(intent.kind, &key, n, &st.boot);
        let expires = match intent.persistence {
            etd_sysfx::Persistence::Expiring { until } => Some(until),
            _ => None,
        };
        let object = FakeObject {
            id: ObjectId(n),
            kind: intent.kind,
            key,
            credential,
            owner: Owner::Ours,
            value,
            volatile: intent.persistence.closes_on_reboot(),
            pid,
            addresses: Vec::new(),
            up: true,
            expires,
        };
        st.next_id += 1;
        st.stats.mutations += 1;
        let obs = observation_of(&object, st.now);
        st.objects.insert(object.id, object);
        obs
    }

    /// An object of ours created outside any record (crash between action
    /// and record), with a fresh credential.
    pub fn create_ours(&self, kind: EffectKind, key: ObjectKey) -> ObjectId {
        self.create(kind, key, Owner::Ours)
    }

    /// A third-party object with this exact key (e.g. our full derived
    /// name) and its own fresh credential.
    pub fn create_foreign(&self, kind: EffectKind, key: ObjectKey) -> ObjectId {
        self.create(kind, key, Owner::Foreign)
    }

    fn create(&self, kind: EffectKind, key: ObjectKey, owner: Owner) -> ObjectId {
        let (n, boot) = {
            let st = self.st();
            (st.next_id, st.boot.clone())
        };
        let credential = default_credential(kind, &key, n, &boot);
        self.insert(FakeObject {
            id: ObjectId(0),
            kind,
            key,
            credential,
            owner,
            value: None,
            volatile: false,
            pid: None,
            addresses: Vec::new(),
            up: true,
            expires: None,
        })
    }

    /// Our object at `key` is gone and someone else created one with the
    /// same key (and a different identity). Returns the new object's id.
    pub fn replace_with_foreign(&self, kind: EffectKind, key: &ObjectKey) -> ObjectId {
        let concrete = {
            let mut st = self.st();
            let found = find_id(&st, kind, key);
            found.and_then(|id| st.objects.remove(&id)).map(|o| o.key)
        };
        self.create_foreign(kind, concrete.unwrap_or_else(|| key.clone()))
    }

    /// The object disappears on its own (the OS took it with the process).
    /// Returns whether one was there.
    pub fn vanish(&self, kind: EffectKind, key: &ObjectKey) -> bool {
        let mut st = self.st();
        match find_id(&st, kind, key) {
            Some(id) => st.objects.remove(&id).is_some(),
            None => false,
        }
    }

    /// Every object held by `pid` that is volatile disappears (process
    /// exit).
    pub fn exit_process(&self, pid: u32) {
        self.st()
            .objects
            .retain(|_, o| !(o.pid == Some(pid) && o.volatile));
    }

    /// Someone else changed a setting.
    pub fn set_value(&self, kind: EffectKind, key: &ObjectKey, value: SettingValue) {
        let mut st = self.st();
        if let Some(id) = find_id(&st, kind, key)
            && let Some(o) = st.objects.get_mut(&id)
        {
            o.value = Some(value);
        }
    }

    pub fn set_addresses(&self, kind: EffectKind, key: &ObjectKey, addresses: Vec<(IpAddr, u8)>) {
        let mut st = self.st();
        if let Some(id) = find_id(&st, kind, key)
            && let Some(o) = st.objects.get_mut(&id)
        {
            o.addresses = addresses;
        }
    }

    pub fn set_pid(&self, kind: EffectKind, key: &ObjectKey, pid: Option<u32>) {
        let mut st = self.st();
        if let Some(id) = find_id(&st, kind, key)
            && let Some(o) = st.objects.get_mut(&id)
        {
            o.pid = pid;
        }
    }

    pub fn set_listener(&self, address: SocketAddr, pid: u32) {
        self.st().listeners.insert(address, pid);
    }

    pub fn clear_listener(&self, address: SocketAddr) {
        self.st().listeners.remove(&address);
    }

    /// Force the result of `PortFence::verify` (`None`: derived from the
    /// listener and the installed fence).
    pub fn set_fence_verification(&self, verification: Option<FenceVerification>) {
        self.st().fence_override = verification;
    }

    /// Reboot: volatile objects and listeners disappear, the boot id
    /// changes. Returns the new boot id.
    pub fn reboot(&self) -> BootId {
        let mut st = self.st();
        st.boots += 1;
        st.boot = BootId(format!("boot-{}", st.boots));
        st.objects.retain(|_, o| !o.volatile);
        st.listeners.clear();
        st.boot.clone()
    }

    pub fn boot(&self) -> BootId {
        self.st().boot.clone()
    }

    pub fn now(&self) -> jiff::Timestamp {
        self.st().now
    }

    pub fn set_now(&self, now: jiff::Timestamp) {
        self.st().now = now;
    }

    /// Move the clock; expired objects disappear.
    pub fn advance(&self, by: std::time::Duration) {
        let mut st = self.st();
        st.now += jiff::SignedDuration::try_from(by).unwrap_or(jiff::SignedDuration::MAX);
        let now = st.now;
        st.objects.retain(|_, o| o.expires.is_none_or(|t| t > now));
    }

    // ----- faults -------------------------------------------------------

    /// Add a fault; faults are matched in insertion order, the first
    /// matching one with calls left applies.
    pub fn inject(&self, fault: Fault) {
        self.st().faults.push(fault);
    }

    /// Panic with [`CRASH`] at the call with this 0-based index
    /// ([`OpRecord::index`]); `after_apply`: let a write go through first.
    pub fn crash_at(&self, index: u64, after_apply: bool) {
        self.st().crash = Some(CrashPoint {
            at: index,
            after_apply,
        });
    }

    /// Remove every fault and crash point.
    pub fn clear_faults(&self) {
        let mut st = self.st();
        st.faults.clear();
        st.crash = None;
    }

    // ----- inspection ---------------------------------------------------

    pub fn objects(&self) -> Vec<FakeObject> {
        self.st().objects.values().cloned().collect()
    }

    /// Our objects still present.
    pub fn ours(&self) -> Vec<FakeObject> {
        self.objects()
            .into_iter()
            .filter(|o| o.owner == Owner::Ours)
            .collect()
    }

    pub fn foreign(&self) -> Vec<FakeObject> {
        self.objects()
            .into_iter()
            .filter(|o| o.owner == Owner::Foreign)
            .collect()
    }

    pub fn get(&self, id: ObjectId) -> Option<FakeObject> {
        self.st().objects.get(&id).cloned()
    }

    /// The object `key` locates, if present.
    pub fn find(&self, kind: EffectKind, key: &ObjectKey) -> Option<FakeObject> {
        let st = self.st();
        find_id(&st, kind, key).and_then(|id| st.objects.get(&id).cloned())
    }

    pub fn deleted(&self) -> Vec<Deletion> {
        self.st().deleted.clone()
    }

    /// Foreign objects deleted by any product path. Must stay empty.
    pub fn foreign_deleted(&self) -> Vec<Deletion> {
        self.deleted()
            .into_iter()
            .filter(|d| d.object.owner == Owner::Foreign)
            .collect()
    }

    pub fn stats(&self) -> Stats {
        self.st().stats
    }

    /// Every call so far, in order.
    pub fn ops(&self) -> Vec<OpRecord> {
        self.st().ops.clone()
    }

    /// Kinds of the reclaim calls so far, in call order.
    pub fn reclaim_order(&self) -> Vec<EffectKind> {
        self.ops()
            .into_iter()
            .filter(|o| o.step == Step::Reclaim)
            .filter_map(|o| o.kind)
            .collect()
    }

    // ----- internals ----------------------------------------------------

    /// Count the call, match faults and the crash point. Never panics with
    /// the lock held.
    fn enter(&self, step: Step, kind: Option<EffectKind>, key: Option<&ObjectKey>) -> Verdict {
        let verdict = {
            let mut st = self.st();
            let index = st.stats.calls;
            st.stats.calls += 1;
            match step {
                Step::Probe => st.stats.probes += 1,
                Step::Sweep => st.stats.sweeps += 1,
                Step::Observe => st.stats.observations += 1,
                _ => {}
            }
            if step.writes() {
                st.stats.write_calls += 1;
            }
            st.ops.push(OpRecord {
                index,
                step,
                kind,
                key: key.cloned(),
                outcome: String::new(),
            });
            if let Some(cp) = st.crash
                && cp.at == index
            {
                st.crash = None;
                if cp.after_apply && step.writes() {
                    Verdict::CrashAfterApply
                } else {
                    Verdict::Crash
                }
            } else if let Some(f) = st.faults.iter_mut().find(|f| f.matches(step, kind, key)) {
                if let Some(t) = f.times.as_mut() {
                    *t -= 1;
                }
                match f.action.clone() {
                    FaultAction::Fail(e) => Verdict::Fail(e),
                    FaultAction::FailAfterApply(e) if step.writes() => Verdict::FailAfterApply(e),
                    FaultAction::FailAfterApply(e) => Verdict::Fail(e),
                    FaultAction::Crash => Verdict::Crash,
                    FaultAction::CrashAfterApply if step.writes() => Verdict::CrashAfterApply,
                    FaultAction::CrashAfterApply => Verdict::Crash,
                }
            } else {
                Verdict::Proceed
            }
        };
        if verdict == Verdict::Crash {
            self.note("crash");
            panic!("{CRASH}");
        }
        verdict
    }

    /// Set the outcome of the latest call.
    fn note(&self, outcome: impl Into<String>) {
        if let Some(op) = self.st().ops.last_mut() {
            op.outcome = outcome.into();
        }
    }

    /// Finish a write call according to the verdict.
    fn finish<T: std::fmt::Debug>(
        &self,
        verdict: Verdict,
        result: Result<T, ReclaimError>,
    ) -> Result<T, ReclaimError> {
        match verdict {
            Verdict::CrashAfterApply => {
                self.note(format!("{result:?} then crash"));
                panic!("{CRASH}");
            }
            Verdict::FailAfterApply(e) => {
                self.note(format!("{result:?} then {e:?}"));
                Err(e)
            }
            _ => {
                self.note(format!("{result:?}"));
                result
            }
        }
    }

    fn remove_object(st: &mut State, id: ObjectId, by: Step) -> bool {
        match st.objects.remove(&id) {
            Some(object) => {
                st.stats.mutations += 1;
                st.deleted.push(Deletion { object, by });
                true
            }
            None => false,
        }
    }

    fn do_probe(&self, kind: EffectKind, e: &Effect) -> Probe {
        let key = lookup_key(e);
        match self.enter(Step::Probe, Some(kind), Some(&key)) {
            Verdict::Fail(err) => {
                self.note(format!("indeterminate: {err}"));
                return Probe::Indeterminate(err.to_string());
            }
            Verdict::Proceed => {}
            other => unreachable!("probe verdict {other:?}"),
        }
        let probe = {
            let st = self.st();
            match find_id(&st, kind, &key).and_then(|id| st.objects.get(&id)) {
                Some(o) => Probe::Present(observation_of(o, st.now)),
                None => Probe::Absent,
            }
        };
        self.note(format!("{probe:?}"));
        probe
    }

    fn do_reclaim(&self, kind: EffectKind, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        let key = lookup_key(e);
        let verdict = self.enter(Step::Reclaim, Some(kind), Some(&key));
        if let Verdict::Fail(err) = verdict {
            self.note(format!("{err:?}"));
            return Err(err);
        }
        let result = {
            let mut st = self.st();
            let found = find_id(&st, kind, &key);
            match (&e.undo, found) {
                (Undo::RestoreIfOurs { ours, original }, found) => {
                    let current = found
                        .and_then(|id| st.objects.get(&id))
                        .and_then(|o| o.value.clone())
                        .unwrap_or(SettingValue::Absent);
                    if current == *ours && current != *original {
                        match (original, found) {
                            (SettingValue::Absent, Some(id)) => {
                                Self::remove_object(&mut st, id, Step::Reclaim);
                            }
                            (value, Some(id)) => {
                                if let Some(o) = st.objects.get_mut(&id) {
                                    o.value = Some(value.clone());
                                }
                                st.stats.mutations += 1;
                            }
                            (value, None) => {
                                drop(st);
                                let id = self.create(kind, key.clone(), Owner::Ours);
                                st = self.st();
                                if let Some(o) = st.objects.get_mut(&id) {
                                    o.value = Some(value.clone());
                                    o.credential = None;
                                }
                                st.stats.mutations += 1;
                            }
                        }
                        Ok(Reclaimed::Restored)
                    } else if current == *original {
                        Ok(Reclaimed::AlreadyAbsent)
                    } else {
                        Ok(Reclaimed::LeftModified)
                    }
                }
                (_, Some(id)) => {
                    Self::remove_object(&mut st, id, Step::Reclaim);
                    Ok(Reclaimed::Removed)
                }
                (_, None) => Ok(Reclaimed::AlreadyAbsent),
            }
        };
        self.finish(verdict, result)
    }
}

/// Fake `Reclaimer` of one kind over a [`FakeSystem`].
struct FakeReclaimer {
    sys: FakeSystem,
    kind: EffectKind,
    rank: u8,
}

#[async_trait]
impl Reclaimer for FakeReclaimer {
    fn kind(&self) -> EffectKind {
        self.kind
    }
    fn rank(&self) -> u8 {
        self.rank
    }
    async fn probe(&self, e: &Effect) -> Probe {
        self.sys.do_probe(self.kind, e)
    }
    async fn reclaim(&self, e: &Effect) -> Result<Reclaimed, ReclaimError> {
        self.sys.do_reclaim(self.kind, e)
    }
}

impl Sweeper for FakeSystem {
    /// Product-marked objects: anything in an exclusive container; objects
    /// whose name contains the name derived for a known instance; objects
    /// whose name carries the product prefix. Foreign objects included, as a
    /// real sweeper cannot tell them apart. Process objects are left to the
    /// host's orphan scan.
    fn find_marked<'a>(
        &'a self,
        key: Option<&'a InstallKey>,
        known: &'a [InstanceId],
    ) -> BoxFuture<'a, Result<Vec<FoundObject>, ReclaimError>> {
        Box::pin(async move {
            if let Verdict::Fail(e) = self.enter(Step::Sweep, None, None) {
                self.note(format!("{e:?}"));
                return Err(e);
            }
            let derived: Vec<(InstanceId, String)> = match key {
                Some(k) => known
                    .iter()
                    .map(|i| (i.clone(), naming::interface_name(k, i)))
                    .collect(),
                None => Vec::new(),
            };
            let found: Vec<FoundObject> = {
                let st = self.st();
                st.objects
                    .values()
                    .filter(|o| o.kind != EffectKind::Process)
                    .filter_map(|o| {
                        let origin = if matches!(
                            o.credential,
                            Some(Credential::ExclusiveContainer { .. })
                        ) {
                            FoundBy::ExclusiveContainer
                        } else {
                            let name = name_of(&o.key).to_lowercase();
                            match derived.iter().find(|(_, d)| name.contains(d.as_str())) {
                                Some((instance, _)) => FoundBy::DerivedName {
                                    instance: instance.clone(),
                                },
                                None if name.contains(naming::INTERFACE_PREFIX) => {
                                    FoundBy::PrefixOnly
                                }
                                None => return None,
                            }
                        };
                        Some(FoundObject {
                            kind: o.kind,
                            key: o.key.clone(),
                            observation: observation_of(o, st.now),
                            origin,
                        })
                    })
                    .collect()
            };
            self.note(format!("{} found", found.len()));
            Ok(found)
        })
    }
}

impl BootIdSource for FakeSystem {
    fn current(&self) -> Result<BootId, ReclaimError> {
        if let Verdict::Fail(e) = self.enter(Step::BootId, None, None) {
            self.note(format!("{e:?}"));
            return Err(e);
        }
        let boot = self.boot();
        self.note(boot.0.clone());
        Ok(boot)
    }
}

fn observe_error(e: ReclaimError) -> ObserveError {
    match e {
        ReclaimError::PermissionDenied(m) => ObserveError::PermissionDenied(m),
        ReclaimError::Unsupported(k) => ObserveError::Unsupported(k),
        ReclaimError::Os { code, message } => ObserveError::Os { code, message },
        other => ObserveError::Os {
            code: -1,
            message: other.to_string(),
        },
    }
}

fn fence_error(e: ReclaimError) -> FenceError {
    match e {
        ReclaimError::PermissionDenied(m) => FenceError::PermissionDenied(m),
        ReclaimError::Os { code, message } => FenceError::Os { code, message },
        other => FenceError::Os {
            code: -1,
            message: other.to_string(),
        },
    }
}

fn is_interface(kind: EffectKind) -> bool {
    matches!(
        kind,
        EffectKind::WinTunAdapter | EffectKind::LinuxTun | EffectKind::MacUtun
    )
}

fn interface_info(o: &FakeObject) -> InterfaceInfo {
    InterfaceInfo {
        name: name_of(&o.key),
        credential: o.credential.clone().unwrap_or(Credential::Opaque {
            value: format!("object-{}", o.id.0),
        }),
        addresses: o.addresses.clone(),
        up: o.up,
    }
}

#[async_trait]
impl SystemObserver for FakeSystem {
    async fn observe(
        &self,
        kind: EffectKind,
        key: &ObjectKey,
    ) -> Result<Option<Observation>, ObserveError> {
        if let Verdict::Fail(e) = self.enter(Step::Observe, Some(kind), Some(key)) {
            self.note(format!("{e:?}"));
            return Err(observe_error(e));
        }
        let found = self.find(kind, key).map(|o| observation_of(&o, self.now()));
        self.note(format!("{found:?}"));
        Ok(found)
    }

    async fn interface(&self, key: &ObjectKey) -> Result<Option<InterfaceInfo>, ObserveError> {
        if let Verdict::Fail(e) = self.enter(Step::Observe, None, Some(key)) {
            self.note(format!("{e:?}"));
            return Err(observe_error(e));
        }
        let found = self
            .objects()
            .into_iter()
            .find(|o| is_interface(o.kind) && locates(key, &o.key))
            .map(|o| interface_info(&o));
        self.note(format!("{found:?}"));
        Ok(found)
    }

    async fn listener(&self, address: SocketAddr) -> Result<Option<ListenerInfo>, ObserveError> {
        if let Verdict::Fail(e) = self.enter(Step::Observe, None, None) {
            self.note(format!("{e:?}"));
            return Err(observe_error(e));
        }
        let found = self
            .st()
            .listeners
            .get(&address)
            .map(|pid| ListenerInfo { address, pid: *pid });
        self.note(format!("{found:?}"));
        Ok(found)
    }

    async fn interfaces_owned_by(&self, pid: u32) -> Result<Vec<InterfaceInfo>, ObserveError> {
        if let Verdict::Fail(e) = self.enter(Step::Observe, None, None) {
            self.note(format!("{e:?}"));
            return Err(observe_error(e));
        }
        let found: Vec<InterfaceInfo> = self
            .objects()
            .iter()
            .filter(|o| is_interface(o.kind) && o.pid == Some(pid))
            .map(interface_info)
            .collect();
        self.note(format!("{} interfaces", found.len()));
        Ok(found)
    }

    async fn enumerate(&self, class: SystemClass) -> Result<Vec<SystemEntry>, ObserveError> {
        if let Verdict::Fail(e) = self.enter(Step::Observe, None, None) {
            self.note(format!("{e:?}"));
            return Err(observe_error(e));
        }
        let entries: Vec<SystemEntry> = self
            .objects()
            .into_iter()
            .filter(|o| class_of(o.kind) == Some(class))
            .map(|o| SystemEntry {
                class,
                description: format!(
                    "{:?} value={:?} up={} addrs={:?}",
                    o.kind, o.value, o.up, o.addresses
                ),
                identity: o.credential.clone(),
                key: o.key,
            })
            .collect();
        self.note(format!("{} entries", entries.len()));
        Ok(entries)
    }
}

/// System class an effect kind is enumerated under (`None`: not on this
/// machine, e.g. router mappings).
pub fn class_of(kind: EffectKind) -> Option<SystemClass> {
    Some(match kind {
        EffectKind::WinTunAdapter | EffectKind::LinuxTun | EffectKind::MacUtun => {
            SystemClass::Interfaces
        }
        EffectKind::Route => SystemClass::Routes,
        EffectKind::WinNrptRule | EffectKind::LinuxResolvedLink => SystemClass::DnsPolicy,
        EffectKind::WinFirewallRule
        | EffectKind::WinProgramFirewallRule
        | EffectKind::WinFenceFilter
        | EffectKind::LinuxFenceRule
        | EffectKind::MacFenceRule => SystemClass::FirewallRules,
        EffectKind::WinRegistryValue => SystemClass::RegistryValues,
        EffectKind::Driver | EffectKind::ServiceRegistration => SystemClass::Services,
        EffectKind::RuntimeDir => SystemClass::RuntimeDirs,
        EffectKind::Process => SystemClass::Processes,
        _ => return None,
    })
}

/// Fake `PortFence`: one rule per fenced port in [`FENCE_CONTAINER`].
struct FakeFence {
    sys: FakeSystem,
    kind: EffectKind,
    container: String,
}

impl FakeFence {
    fn key(&self, spec: &FenceSpec) -> ObjectKey {
        ObjectKey::Fence {
            container: self.container.clone(),
            rule: format!("{}-{}", spec.instance.as_str(), spec.epoch.0),
            port: spec.address.port(),
        }
    }
}

#[async_trait]
impl PortFence for FakeFence {
    fn plan(&self, spec: &FenceSpec) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: spec.instance.clone(),
                epoch: spec.epoch,
            },
            kind: self.kind,
            key: self.key(spec),
            undo: Undo::EnsureAbsent,
            persistence: etd_sysfx::Persistence::Persistent,
        }
    }

    async fn install(&self, spec: &FenceSpec) -> Result<Observation, FenceError> {
        let key = self.key(spec);
        let verdict = self
            .sys
            .enter(Step::FenceInstall, Some(self.kind), Some(&key));
        if let Verdict::Fail(e) = verdict {
            self.sys.note(format!("{e:?}"));
            return Err(fence_error(e));
        }
        let existing = self.sys.find(self.kind, &key);
        let obs = match existing {
            Some(o) => observation_of(&o, self.sys.now()),
            None => {
                let intent = self.plan(spec);
                self.sys.apply_intent(&intent)
            }
        };
        self.sys.finish(verdict, Ok(obs)).map_err(fence_error)
    }

    async fn verify(
        &self,
        spec: &FenceSpec,
        listener_pid: u32,
    ) -> Result<FenceVerification, FenceError> {
        let key = self.key(spec);
        if let Verdict::Fail(e) = self
            .sys
            .enter(Step::FenceVerify, Some(self.kind), Some(&key))
        {
            self.sys.note(format!("{e:?}"));
            return Err(fence_error(e));
        }
        let forced = self.sys.st().fence_override.clone();
        let result = forced.unwrap_or_else(|| {
            let listener = self.sys.st().listeners.get(&spec.address).copied();
            let fenced = self.sys.find(self.kind, &key).is_some();
            match listener {
                None => FenceVerification {
                    listener: ListenerCheck::NotListening,
                    host: DirectionResult::NoListener,
                    unprivileged: DirectionResult::NoListener,
                },
                Some(pid) => FenceVerification {
                    listener: if pid == listener_pid {
                        ListenerCheck::Expected
                    } else {
                        ListenerCheck::Other { pid }
                    },
                    host: DirectionResult::Connected,
                    unprivileged: if fenced {
                        DirectionResult::Refused
                    } else {
                        DirectionResult::Connected
                    },
                },
            }
        });
        self.sys.note(format!("{result:?}"));
        Ok(result)
    }

    async fn remove(&self, spec: &FenceSpec) -> Result<Reclaimed, FenceError> {
        let key = self.key(spec);
        let verdict = self
            .sys
            .enter(Step::FenceRemove, Some(self.kind), Some(&key));
        if let Verdict::Fail(e) = verdict {
            self.sys.note(format!("{e:?}"));
            return Err(fence_error(e));
        }
        let removed = {
            let mut st = self.sys.st();
            match find_id(&st, self.kind, &key) {
                Some(id) => FakeSystem::remove_object(&mut st, id, Step::FenceRemove),
                None => false,
            }
        };
        let result = Ok(if removed {
            Reclaimed::Removed
        } else {
            Reclaimed::AlreadyAbsent
        });
        self.sys.finish(verdict, result).map_err(fence_error)
    }
}

// ----- helpers -------------------------------------------------------------

/// The key a probe or reclaim looks for: the concrete key observed after
/// the action if any, else the planned key.
pub fn lookup_key(e: &Effect) -> ObjectKey {
    e.observation
        .as_ref()
        .and_then(|o| o.key.clone())
        .unwrap_or_else(|| e.key.clone())
}

/// Whether the recorded key `want` locates the object whose concrete key is
/// `actual`. Interfaces match on name or GUID (case-insensitive); planned
/// keys with an unknown part (utun name, router port) locate nothing but
/// their known parts.
pub fn locates(want: &ObjectKey, actual: &ObjectKey) -> bool {
    match (want, actual) {
        (ObjectKey::Interface { name, guid }, ObjectKey::Interface { name: an, guid: ag }) => {
            let eq = |a: &Option<String>, b: &Option<String>| match (a, b) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            };
            eq(name, an) || eq(guid, ag)
        }
        (
            ObjectKey::RoutesVia { interface: Some(w) },
            ObjectKey::RoutesVia { interface: Some(a) },
        ) => w == a,
        (ObjectKey::RoutesVia { interface: None }, _) => false,
        (
            ObjectKey::PortMapping {
                protocol,
                internal_port,
                external_port,
                description,
            },
            ObjectKey::PortMapping {
                protocol: ap,
                internal_port: ai,
                external_port: ae,
                description: ad,
            },
        ) => {
            protocol == ap
                && internal_port == ai
                && description == ad
                && (external_port.is_none() || external_port == ae)
        }
        _ => want == actual,
    }
}

fn find_id(st: &State, kind: EffectKind, key: &ObjectKey) -> Option<ObjectId> {
    st.objects
        .values()
        .find(|o| o.kind == kind && locates(key, &o.key))
        .map(|o| o.id)
}

/// Human-readable name of a key, for prefix and derived-name matching.
pub fn name_of(key: &ObjectKey) -> String {
    match key {
        ObjectKey::Interface { name, guid } => {
            name.clone().or_else(|| guid.clone()).unwrap_or_default()
        }
        ObjectKey::RoutesVia { interface } => interface.clone().unwrap_or_default(),
        ObjectKey::Rule { name, .. } => name.clone(),
        ObjectKey::Registry { key, value } => match value {
            Some(v) => format!("{key}\\{v}"),
            None => key.clone(),
        },
        ObjectKey::Fence { rule, .. } => rule.clone(),
        ObjectKey::ResolvedLink { interface } => interface.clone(),
        ObjectKey::PortMapping { description, .. } => description.clone(),
        ObjectKey::Service { name } => name.clone(),
        ObjectKey::Path { path } => path.display().to_string(),
        ObjectKey::Process { cmdline_marker, .. } => cmdline_marker.display().to_string(),
        _ => String::new(),
    }
}

/// Fill in what the system assigns: a utun name, a router port.
fn concrete_key(key: &ObjectKey, n: u64) -> ObjectKey {
    match key {
        ObjectKey::Interface { name: None, guid } => ObjectKey::Interface {
            name: Some(format!("utun{n}")),
            guid: guid.clone(),
        },
        ObjectKey::PortMapping {
            protocol,
            internal_port,
            external_port: None,
            description,
        } => ObjectKey::PortMapping {
            protocol: protocol.clone(),
            internal_port: *internal_port,
            external_port: Some(40000 + (n % 20000) as u16),
            description: description.clone(),
        },
        other => other.clone(),
    }
}

/// Fresh creation credential for a new object (`n` makes it unique).
fn default_credential(
    kind: EffectKind,
    key: &ObjectKey,
    n: u64,
    boot: &BootId,
) -> Option<Credential> {
    Some(match (kind, key) {
        (_, ObjectKey::Fence { container, .. }) => Credential::ExclusiveContainer {
            container: container.clone(),
        },
        (EffectKind::RuntimeDir, _) => Credential::ExclusiveContainer {
            container: RUN_CONTAINER.into(),
        },
        (EffectKind::WinTunAdapter, _) => Credential::WinAdapter {
            luid: n,
            device_instance_id: format!("SWD\\WINTUN\\{n}"),
        },
        (EffectKind::LinuxTun | EffectKind::MacUtun, _) => Credential::UnixInterface {
            index: n as u32,
            boot: boot.clone(),
        },
        (EffectKind::Process, _) => Credential::Process {
            pid: n as u32,
            start_token: format!("start-{n}"),
        },
        (EffectKind::WinRegistryValue, _) => return None,
        (_, ObjectKey::Path { .. }) => Credential::File {
            file_id: n,
            device: 1,
        },
        _ => Credential::Opaque {
            value: format!("id-{n}"),
        },
    })
}

fn observation_of(o: &FakeObject, now: jiff::Timestamp) -> Observation {
    Observation {
        credential: o.credential.clone(),
        key: Some(o.key.clone()),
        observed_at: now,
        detail: o.value.as_ref().map(|v| format!("value {v:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etd_sysfx::{EffectId, EffectState, Epoch, Persistence};

    fn intent(kind: EffectKind, key: ObjectKey, persistence: Persistence) -> EffectIntent {
        EffectIntent {
            scope: EffectScope::Instance {
                instance: InstanceId::from("a"),
                epoch: Epoch(1),
            },
            kind,
            key,
            undo: Undo::EnsureAbsent,
            persistence,
        }
    }

    fn effect(i: &EffectIntent, obs: Option<Observation>) -> Effect {
        Effect {
            id: EffectId("e1".into()),
            scope: i.scope.clone(),
            kind: i.kind,
            key: i.key.clone(),
            undo: i.undo.clone(),
            persistence: i.persistence,
            state: EffectState::Applied,
            boot: BootId("boot-1".into()),
            observation: obs,
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::UNIX_EPOCH,
        }
    }

    fn rule(name: &str) -> ObjectKey {
        ObjectKey::Rule {
            name: name.into(),
            group: None,
        }
    }

    #[tokio::test]
    async fn probe_reclaim_roundtrip_and_faults() {
        let sys = FakeSystem::new();
        let i = intent(
            EffectKind::WinFirewallRule,
            rule("r1"),
            Persistence::Persistent,
        );
        let obs = sys.apply_intent(&i);
        let e = effect(&i, Some(obs.clone()));
        let r = sys.reclaimer(EffectKind::WinFirewallRule);
        assert_eq!(r.probe(&e).await, Probe::Present(obs));

        sys.inject(
            Fault::on(Step::Reclaim)
                .times(2)
                .fail(ReclaimError::Busy("x".into())),
        );
        assert!(r.reclaim(&e).await.is_err());
        assert!(r.reclaim(&e).await.is_err());
        assert_eq!(r.reclaim(&e).await, Ok(Reclaimed::Removed));
        assert_eq!(r.reclaim(&e).await, Ok(Reclaimed::AlreadyAbsent));
        assert_eq!(r.probe(&e).await, Probe::Absent);
        assert!(sys.ours().is_empty());
        assert_eq!(sys.stats().write_calls, 4);
        assert_eq!(sys.stats().mutations, 2);

        sys.inject(Fault::on(Step::Probe).once());
        assert!(matches!(r.probe(&e).await, Probe::Indeterminate(_)));
    }

    #[tokio::test]
    async fn fail_after_apply_changes_the_system() {
        let sys = FakeSystem::new();
        let i = intent(
            EffectKind::LinuxTun,
            ObjectKey::Interface {
                name: Some("etd-1".into()),
                guid: None,
            },
            Persistence::WithProcess,
        );
        let obs = sys.apply_intent(&i);
        sys.inject(
            Fault::on(Step::Reclaim)
                .once()
                .fail_after_apply(ReclaimError::Timeout),
        );
        let r = sys.reclaimer(EffectKind::LinuxTun);
        assert_eq!(
            r.reclaim(&effect(&i, Some(obs))).await,
            Err(ReclaimError::Timeout)
        );
        assert!(sys.objects().is_empty());
    }

    #[tokio::test]
    async fn crash_at_panics_with_marker() {
        let sys = FakeSystem::new();
        let i = intent(
            EffectKind::WinFirewallRule,
            rule("r1"),
            Persistence::Persistent,
        );
        let obs = sys.apply_intent(&i);
        let e = effect(&i, Some(obs));
        sys.crash_at(1, true);
        let s2 = sys.clone();
        let task = tokio::spawn(async move {
            let r = s2.reclaimer(EffectKind::WinFirewallRule);
            let _ = r.probe(&e).await;
            let _ = r.reclaim(&e).await;
        });
        let err = task.await.unwrap_err();
        assert!(err.is_panic());
        // after_apply: the delete went through before the crash.
        assert!(sys.objects().is_empty());
    }

    #[tokio::test]
    async fn restore_if_ours() {
        let sys = FakeSystem::new();
        let key = ObjectKey::Registry {
            key: "HKLM\\X".into(),
            value: Some("V".into()),
        };
        let mut i = intent(
            EffectKind::WinRegistryValue,
            key.clone(),
            Persistence::Persistent,
        );
        i.undo = Undo::RestoreIfOurs {
            ours: SettingValue::U32(1),
            original: SettingValue::U32(0),
        };
        let obs = sys.apply_intent(&i);
        let e = effect(&i, Some(obs));
        let r = sys.reclaimer(EffectKind::WinRegistryValue);
        assert_eq!(r.reclaim(&e).await, Ok(Reclaimed::Restored));
        assert_eq!(
            sys.find(EffectKind::WinRegistryValue, &key).unwrap().value,
            Some(SettingValue::U32(0))
        );
        assert_eq!(r.reclaim(&e).await, Ok(Reclaimed::AlreadyAbsent));
        sys.set_value(EffectKind::WinRegistryValue, &key, SettingValue::U32(7));
        assert_eq!(r.reclaim(&e).await, Ok(Reclaimed::LeftModified));
    }

    #[tokio::test]
    async fn sweeper_classifies_and_reboot_drops_volatile() {
        let sys = FakeSystem::new();
        let k = InstallKey([3; 32]);
        let inst = InstanceId::from("a");
        let name = naming::interface_name(&k, &inst);
        sys.create_foreign(
            EffectKind::LinuxTun,
            ObjectKey::Interface {
                name: Some(name.clone()),
                guid: None,
            },
        );
        sys.create_foreign(
            EffectKind::LinuxTun,
            ObjectKey::Interface {
                name: Some("etd-zzzz".into()),
                guid: None,
            },
        );
        sys.create_foreign(
            EffectKind::LinuxTun,
            ObjectKey::Interface {
                name: Some("eth0".into()),
                guid: None,
            },
        );
        let fence = sys.fence(EffectKind::LinuxFenceRule);
        let spec = FenceSpec {
            instance: inst.clone(),
            epoch: Epoch(1),
            address: "127.0.0.1:15888".parse().unwrap(),
        };
        fence.install(&spec).await.unwrap();
        let found = sys
            .sweeper()
            .find_marked(Some(&k), std::slice::from_ref(&inst))
            .await
            .unwrap();
        let origins: Vec<_> = found.iter().map(|f| f.origin.clone()).collect();
        assert_eq!(origins.len(), 3);
        assert!(origins.contains(&FoundBy::DerivedName {
            instance: inst.clone()
        }));
        assert!(origins.contains(&FoundBy::PrefixOnly));
        assert!(origins.contains(&FoundBy::ExclusiveContainer));

        let v = intent(
            EffectKind::Route,
            ObjectKey::RoutesVia {
                interface: Some(name),
            },
            Persistence::UntilReboot,
        );
        sys.apply_intent(&v);
        let before = sys.boot_id_source().current().unwrap();
        let after = sys.reboot();
        assert_ne!(before, after);
        assert!(sys.find(EffectKind::Route, &v.key).is_none());
        assert_eq!(sys.objects().len(), 4);
    }

    #[tokio::test]
    async fn fence_verify_follows_listener_and_rule() {
        let sys = FakeSystem::new();
        let fence = sys.fence(EffectKind::WinFenceFilter);
        let spec = FenceSpec {
            instance: InstanceId::from("a"),
            epoch: Epoch(1),
            address: "127.0.0.1:15888".parse().unwrap(),
        };
        assert!(!fence.verify(&spec, 10).await.unwrap().passed());
        sys.set_listener(spec.address, 10);
        assert_eq!(
            fence.verify(&spec, 10).await.unwrap().unprivileged,
            DirectionResult::Connected
        );
        fence.install(&spec).await.unwrap();
        assert!(fence.verify(&spec, 10).await.unwrap().passed());
        assert_eq!(
            fence.verify(&spec, 11).await.unwrap().listener,
            ListenerCheck::Other { pid: 10 }
        );
        assert_eq!(fence.remove(&spec).await, Ok(Reclaimed::Removed));
        assert_eq!(fence.remove(&spec).await, Ok(Reclaimed::AlreadyAbsent));
    }

    #[tokio::test]
    async fn observer_sees_utun_by_pid() {
        let sys = FakeSystem::new();
        let i = intent(
            EffectKind::MacUtun,
            ObjectKey::Interface {
                name: None,
                guid: None,
            },
            Persistence::WithProcess,
        );
        let obs = sys.apply_intent_with_pid(&i, Some(42));
        let key = obs.key.clone().unwrap();
        sys.set_addresses(
            EffectKind::MacUtun,
            &key,
            vec![("10.0.0.1".parse().unwrap(), 24)],
        );
        let owned = sys.observer().interfaces_owned_by(42).await.unwrap();
        assert_eq!(owned.len(), 1);
        assert!(owned[0].name.starts_with("utun"));
        assert_eq!(owned[0].addresses.len(), 1);
        sys.exit_process(42);
        assert!(
            sys.observer()
                .interfaces_owned_by(42)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

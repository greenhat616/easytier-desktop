//! Our own supervisor state machine: reclaim is the precondition of every
//! restart (ProcessKit's supervisor leaves no room for it). Owned by H1.
//!
//! One task per instance. It owns the kernel process of the instance's live
//! generation and walks the instance state machine
//! (`crate::lifecycle::machine`):
//!
//! ```text
//! Stopped/Waiting/Backoff/GaveUp --start--> Starting --basic--> ReadyBasic --full--> ReadyFull
//!        ^                                     |  any exit, kill, failed launch   |
//!        |                                     v                                  v
//!        +-- closed + desired / policy -- Reclaiming <------- Stopping <-- stop --+
//!                                              |
//!                                  pending: retry; failing / uncertain: Quarantined
//! ```
//!
//! Rules it enforces:
//! - a generation is launched only from its committed inputs (`replay`),
//!   after the kernel hash is re-verified and the derived interface name is
//!   checked free;
//! - every exit, requested or not, is followed by `reclaim_generation`; the
//!   restart policy's delay starts only once that generation is closed, so
//!   an open generation never coexists with a new one;
//! - basic readiness comes from system observation only (process uptime and
//!   an addressed interface or the expected listener) and, on a fenced
//!   host, a verified fence; the management session is opened afterwards;
//! - a cut (stop not persisted) kills the kernel and reclaims nothing until
//!   a desired state is committed;
//! - the Windows program firewall rules a kernel deletes and recreates on
//!   every start (core-binary scope) must be absent or exactly as recorded
//!   before the spawn, else the start is refused; after basic readiness
//!   their credential is refreshed only from a single confirmed rule, else
//!   they become conflicts. Such starts run one at a time.
use crate::api::{ClientPresence, LogStream, Reply};
use crate::fence_seq::{self, FenceCheck};
use crate::lifecycle::logs::{self, LineBuffer, LogBook};
use crate::lifecycle::plan::{self, PlanFailure, error};
use crate::lifecycle::{Ctx, machine, view};
use crate::poller::{self, Poller};
use etd_contract::v1::{self, ManagementAccess, NoticeLevel};
use etd_contract::{
    Desired, DesiredInstance, ErrorCode, ErrorDetail, InstanceId, InstanceState, InstanceStatus,
    LogLine, QueryKind, QueryResponse,
};
use etd_core_api::{CoreEventCursor, CoreEventKind, CoreSession, LaunchPlan, ReadinessCondition};
use etd_proc::{
    Exit, ExitCause, KillOutcome, ProcessError, ProcessEvent, ProcessHandle, RestartDecision,
    RestartPolicy,
};
use etd_sysfx::{
    Credential, Effect, EffectId, EffectKind, EffectScope, EffectState, Epoch, FenceSpec,
    GenerationOutcome, GenerationReport, InterfaceInfo, LaunchInputs, LedgerError, ManagementGuard,
    ObjectKey, Observation, Persistence, ScopeFilter, StoredGeneration, SystemClass, Undo,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedMutexGuard, mpsc, oneshot, watch};

/// Actor -> supervisor.
pub(crate) enum SupCmd {
    /// The committed desired state (`None`: the instance was removed),
    /// optionally a committed generation to launch, and whether a RetryStart
    /// was accepted.
    Desire {
        desired: Option<Box<DesiredInstance>>,
        launch: Option<Epoch>,
        retry_start: bool,
    },
    RetryReclaim,
    /// Candidates were resolved: a quarantined generation is reclaimed
    /// again, a deferred start tries again.
    Recheck,
    /// Another generation closed: a single-writer claim may be free.
    ClaimsChanged,
    /// A kernel of this generation outside any record could not be killed
    /// (self-check re-sweep): quarantine, never reclaimed automatically.
    Quarantine {
        epoch: Epoch,
        reason: String,
    },
    Cut {
        reply: Reply<()>,
    },
    Query {
        kind: QueryKind,
        reply: Reply<QueryResponse>,
    },
    /// Stop the kernel (desired state unchanged), reclaim, end the task.
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Supervisor -> actor.
pub(crate) enum Report {
    Status(InstanceStatus),
    Exited(v1::InstanceExited),
    Notice(v1::Notice),
    /// A reclaim run finished (any outcome).
    Reclaimed(GenerationReport),
    /// The task ended.
    Gone(InstanceId),
}

/// How the supervisor starts.
pub(crate) enum Initial {
    Idle,
    /// An open generation found at start-up (pending reclaim).
    Reclaim(Epoch),
    Quarantined(Epoch, String),
}

/// What follows once the generation being reclaimed is closed.
#[derive(Debug, Clone, PartialEq)]
enum Then {
    /// Follow desired state: start if running, else stopped.
    Settle,
    Backoff(Instant),
    GiveUp(String),
    /// Plan the next generation with `ManagementGuard::DenyAll`.
    FenceFallback,
    /// Refused before the spawn (a foreign object holds the derived
    /// interface name): quarantine until a reclaim retry.
    Quarantine(String),
    /// End the task.
    Exit,
}

/// A launch that did not reach a running kernel.
enum LaunchFail {
    /// Will fail the same way again (replay mismatch, plan refused).
    Fatal(String),
    /// The fence could not be installed.
    Fence(String),
    /// Spawn or preparation failed; counts like an abnormal exit.
    Abnormal(String),
    /// The child started but exited before its identity was captured (its
    /// containment is confirmed empty): an abnormal exit.
    Exited(Exit),
    /// The process tree could not be confirmed empty: quarantine.
    Uncertain(String),
    /// A foreign object holds what this generation would create.
    Taken(String),
    /// The committed desired state no longer wants this generation.
    Superseded(String),
    /// Starting would let the kernel replace a system object that is not
    /// ours (a program firewall rule we did not record): no start until a
    /// RetryStart.
    Refused(String),
    /// A cut arrived before the spawn: nothing runs; the generation is
    /// reclaimed once a desired state is committed.
    Cut(Reply<()>),
}

struct Live {
    epoch: Epoch,
    inputs: LaunchInputs,
    plan: LaunchPlan,
    handle: Box<dyn ProcessHandle>,
    events: Option<mpsc::Receiver<ProcessEvent>>,
    pid: u32,
    spawned: Instant,
    start_deadline: Instant,
    fence: Option<FenceSpec>,
    fence_ok: bool,
    /// Next re-verification of a verified fence while the kernel runs.
    fence_due: Instant,
    /// Re-verifications in a row that found the fence definitely lost.
    fence_lost: u32,
    /// Re-verifications in a row that proved nothing either way.
    fence_unverifiable: u32,
    /// The re-verification under way (a background task).
    fence_task: Option<FenceTask>,
    basic: bool,
    session: Option<Arc<dyn CoreSession>>,
    attach_after: Instant,
    poller: Option<Poller>,
    cursor: Option<CoreEventCursor>,
    /// Kernel records still `Planned` (enumerated until they appear).
    pending: Vec<Effect>,
    /// Program firewall rule records (core-binary scope) this start may
    /// replace, as last recorded: left untouched while the kernel starts,
    /// settled after basic readiness ([`Supervisor::settle_rules`]).
    rules: Vec<Effect>,
    /// `Ctx::program_rules`, held until every rule is settled or
    /// `rules_deadline` passes.
    rule_gate: Option<OwnedMutexGuard<()>>,
    /// Next settling pass of `rules` (after basic readiness).
    rules_due: Instant,
    /// Settling gives up here (basic readiness + `start_timeout`), keeping
    /// the records as they were.
    rules_deadline: Option<Instant>,
    /// When several rules of a record's name were first seen in a row of
    /// snapshots; a second sighting `reclaim_retry` later makes it foreign.
    rules_several: HashMap<EffectId, Instant>,
    next_tick: Instant,
    /// Partial output lines (a secret may span chunks).
    stdout: LineBuffer,
    stderr: LineBuffer,
}

/// A fence re-verification running off the supervisor's task; aborted with
/// the generation it was started for.
struct FenceTask {
    rx: oneshot::Receiver<fence_seq::Recheck>,
    abort: tokio::task::AbortHandle,
}

impl Drop for FenceTask {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Unverifiable fence re-checks in a row before an administrator is told.
const FENCE_UNVERIFIABLE_NOTICE_AFTER: u32 = 5;

enum Phase {
    Idle,
    Live(Box<Live>),
    Reclaim {
        epoch: Epoch,
        then: Then,
        retry_at: Option<Instant>,
    },
    Backoff {
        until: Instant,
    },
    Quarantined {
        epoch: Epoch,
    },
    Cut {
        epoch: Option<Epoch>,
    },
}

enum Input {
    Cmd(SupCmd),
    Proc(Option<ProcessEvent>),
    Tick,
    Presence,
    /// A fence re-verification finished (`None`: its task ended without a
    /// result).
    Fence(Option<fence_seq::Recheck>),
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Exit,
}

pub(crate) struct Supervisor {
    ctx: Arc<Ctx>,
    id: InstanceId,
    desired: Option<Box<DesiredInstance>>,
    policy: Box<dyn RestartPolicy>,
    cmds: mpsc::UnboundedReceiver<SupCmd>,
    cmds_closed: bool,
    deferred: VecDeque<SupCmd>,
    /// Program rule records found with several rules of their name before
    /// a spawn, and since when (two snapshots `reclaim_retry` apart refuse
    /// the start).
    rules_several: HashMap<EffectId, Instant>,
    reports: mpsc::UnboundedSender<Report>,
    presence: watch::Receiver<ClientPresence>,
    presence_closed: bool,
    logs: Arc<LogBook>,
    status: InstanceStatus,
    abnormal: VecDeque<Instant>,
    phase: Phase,
    /// Plan the next generation with deny-all (fence failed).
    fence_failed: bool,
    gave_up: bool,
    waiting: bool,
    shutdown: Option<oneshot::Sender<()>>,
    stopping_for_exit: bool,
    /// Network secrets of the launched generations, redacted from every
    /// kernel-derived text.
    secrets: Vec<String>,
}

/// Wall-clock milliseconds of a monotonic instant.
fn wall_ms(ctx: &Ctx, at: Instant) -> i64 {
    let now = ctx.deps.clock.now();
    let wall = ctx.deps.clock.wall_now().as_millisecond();
    if at >= now {
        wall + i64::try_from((at - now).as_millis()).unwrap_or(i64::MAX / 2)
    } else {
        wall - i64::try_from((now - at).as_millis()).unwrap_or(0)
    }
}

fn exit_info(ctx: &Ctx, exit: &Exit) -> v1::ExitInfo {
    v1::ExitInfo {
        code: exit.code,
        signal: exit.signal,
        abnormal: exit.abnormal(),
        at_unix_ms: ctx.deps.clock.wall_now().as_millisecond(),
    }
}

fn management_of(guard: ManagementGuard, fence_ok: bool) -> ManagementAccess {
    match guard {
        ManagementGuard::Fence if fence_ok => ManagementAccess::Available,
        ManagementGuard::Fence => ManagementAccess::Pending,
        ManagementGuard::Unguarded => ManagementAccess::Available,
        ManagementGuard::DenyAll => ManagementAccess::DenyAll,
        ManagementGuard::LifecycleOnly => ManagementAccess::LifecycleOnly,
        _ => ManagementAccess::Unspecified,
    }
}

fn unavailable(instance: &InstanceId) -> ErrorDetail {
    error(
        ErrorCode::ManagementUnavailable,
        "the instance has no verified management access",
        instance.as_str(),
    )
}

fn is_fence_kind(kind: EffectKind) -> bool {
    matches!(
        kind,
        EffectKind::WinFenceFilter | EffectKind::LinuxFenceRule | EffectKind::MacFenceRule
    )
}

fn is_host_kind(kind: EffectKind) -> bool {
    matches!(kind, EffectKind::Process | EffectKind::RuntimeDir) || is_fence_kind(kind)
}

/// One of the Windows program firewall rules named after the kernel binary
/// (core-binary scope, shared by every instance launched from it). Upstream
/// deletes and recreates them on every start (easytier-core c97f36b
/// `arch/windows.rs` 230-232), so the recorded rule GUID goes stale with
/// each start: they are checked before the spawn and read back after basic
/// readiness instead of being read back once (ruling topic#36 msg#931).
fn is_program_rule(e: &Effect) -> bool {
    e.kind == EffectKind::WinProgramFirewallRule
        && matches!(e.scope, EffectScope::CoreBinary { .. })
}

/// The credential a record holds as ours: only an applied record has one
/// (a candidate or conflict keeps what it saw, which is not ours).
fn recorded_credential(e: &Effect) -> Option<&Credential> {
    (e.state == EffectState::Applied)
        .then(|| e.observation.as_ref().and_then(|o| o.credential.as_ref()))
        .flatten()
}

/// What is found under a program firewall rule's name, from one observer
/// call and one independent enumeration that agree (ruling topic#40
/// msg#1150 items 2-3).
enum RuleRead {
    /// No rule with that name in either.
    Absent,
    /// Exactly one rule with that name, confirmed by the observer as the
    /// one for the kernel binary it names, with the same identity in the
    /// enumeration.
    One(Observation),
    /// Several rules with that name in this snapshot (foreign only when a
    /// second snapshot `reclaim_retry` later agrees).
    Several(usize),
    /// Definitely not the kernel's: the observer found the single rule of
    /// that name and reports no identity of ours for it.
    Unconfirmed(String),
    /// Could not tell (an observer error, or the two views disagree):
    /// never taken as absent, ours or foreign.
    Unknown(String),
}

/// A kernel record whose creation credential the host reads back after the
/// spawn (lease and expiring records are record-only: never waited on).
fn needs_read_back(e: &Effect) -> bool {
    !is_host_kind(e.kind)
        && !is_program_rule(e)
        && e.state == EffectState::Planned
        && !matches!(
            e.persistence,
            Persistence::Lease { .. } | Persistence::Expiring { .. }
        )
}

/// Records with no creation credential to read back: routes via an
/// interface (removed with it), upstream's own recovery record (replayed,
/// never deleted by credential) and settings (restored only while the value
/// is still ours).
fn credential_less(e: &Effect) -> bool {
    matches!(e.key, ObjectKey::RoutesVia { .. })
        || matches!(
            e.undo,
            Undo::ReplayUpstreamRecovery | Undo::RestoreIfOurs { .. }
        )
}

/// A driver service shared by every kernel (wintun, WinDivert; product
/// scope). Upstream exposes no creation credential for it, so the read-back
/// records what was found without one: applied here means "absent before
/// the spawn, loaded while our kernel ran", which keeps the next start from
/// taking our own driver for a third party's. With no credential the record
/// never authorizes a deletion: a purge lists it as a candidate (ruling
/// topic#36 msg#932). One present before the spawn is flagged as a conflict
/// by [`Supervisor::flag_preexisting`] and never read back.
fn is_shared_driver(e: &Effect) -> bool {
    e.kind == EffectKind::Driver && e.scope == EffectScope::Product
}

impl Supervisor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ctx: Arc<Ctx>,
        id: InstanceId,
        desired: Box<DesiredInstance>,
        initial: Initial,
        cmds: mpsc::UnboundedReceiver<SupCmd>,
        reports: mpsc::UnboundedSender<Report>,
        presence: watch::Receiver<ClientPresence>,
        logs: Arc<LogBook>,
    ) -> Self {
        let policy = (ctx.deps.restart_policy)();
        let mut status = InstanceStatus {
            instance_id: id.to_string(),
            ..Default::default()
        };
        let (phase, state, message, epoch) = match initial {
            Initial::Idle => (Phase::Idle, None, String::new(), 0),
            Initial::Reclaim(epoch) => (
                Phase::Reclaim {
                    epoch,
                    then: Then::Settle,
                    retry_at: None,
                },
                Some(InstanceState::Reclaiming),
                "reclaiming a generation left open".into(),
                epoch.0,
            ),
            Initial::Quarantined(epoch, reason) => (
                Phase::Quarantined { epoch },
                Some(InstanceState::Quarantined),
                reason,
                epoch.0,
            ),
        };
        status.epoch = epoch;
        let mut s = Self {
            ctx,
            id,
            desired: Some(desired),
            policy,
            cmds,
            cmds_closed: false,
            deferred: VecDeque::new(),
            rules_several: HashMap::new(),
            reports,
            presence,
            presence_closed: false,
            logs,
            status,
            abnormal: VecDeque::new(),
            phase,
            fence_failed: false,
            gave_up: false,
            waiting: false,
            shutdown: None,
            stopping_for_exit: false,
            secrets: Vec::new(),
        };
        if let Some(state) = state {
            s.set_state(state, message);
        }
        s
    }

    pub(crate) async fn run(mut self) {
        // Commands queued at creation (a ticket's committed generation) come
        // before the supervisor drives toward desired state on its own.
        let mut exit = false;
        while let Ok(cmd) = self.cmds.try_recv() {
            if self.on_cmd(cmd).await == Flow::Exit {
                exit = true;
                break;
            }
        }
        while !exit {
            if self.drive().await == Flow::Exit {
                break;
            }
            let input = self.next_input().await;
            exit = self.handle(input).await == Flow::Exit;
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.reports.send(Report::Gone(self.id.clone()));
    }

    // ----- helpers -------------------------------------------------------

    fn now(&self) -> Instant {
        self.ctx.deps.clock.now()
    }

    fn wants_running(&self) -> bool {
        self.desired
            .as_ref()
            .is_some_and(|d| d.desired() == Desired::Running)
    }

    fn report(&self, r: Report) {
        let _ = self.reports.send(r);
    }

    fn publish(&self) {
        self.report(Report::Status(self.status.clone()));
    }

    fn notice(&self, level: NoticeLevel, code: &str, message: impl Into<String>) {
        let message = logs::redact(&message.into(), &self.secrets);
        self.report(Report::Notice(view::notice(
            level,
            code,
            message,
            self.id.as_str(),
        )));
    }

    /// Remember a launched generation's network secret for redaction (the
    /// previous one too: its kernel may still be writing).
    fn remember_secret(&mut self, spec: &etd_contract::NetworkSpec) {
        if let Some(s) = spec.network_secret.as_ref().filter(|s| !s.is_empty())
            && !self.secrets.contains(s)
        {
            self.secrets.push(s.clone());
            if self.secrets.len() > 2 {
                self.secrets.remove(0);
            }
        }
    }

    /// Move along an edge of the instance state machine and publish.
    fn set_state(&mut self, to: InstanceState, message: impl Into<String>) {
        let from = self.status.state();
        if !machine::allowed(from, to) {
            tracing::error!(instance = %self.id, ?from, ?to, "refused state edge");
            debug_assert!(
                false,
                "instance state edge {from:?} -> {to:?} is not allowed"
            );
            return;
        }
        if from != to {
            self.status.state_since_unix_ms = self.ctx.deps.clock.wall_now().as_millisecond();
        }
        self.status.set_state(to);
        self.status.message = logs::redact(&message.into(), &self.secrets);
        if !machine::is_live(to) {
            self.status.management = ManagementAccess::Unspecified as i32;
            if to != InstanceState::Backoff {
                self.status.next_restart_unix_ms = 0;
            }
        }
        if to != InstanceState::Reclaiming && to != InstanceState::Quarantined {
            self.status.open_residues = 0;
        }
        self.publish();
    }

    fn log(&self, source: v1::LogSource, epoch: Epoch, text: String) {
        self.logs.push(LogLine {
            at_unix_ms: self.ctx.deps.clock.wall_now().as_millisecond(),
            source: source as i32,
            text: logs::redact(&text, &self.secrets),
            instance_id: self.id.to_string(),
            epoch: epoch.0,
        });
    }

    fn attempts(&mut self, now: Instant) -> u32 {
        while self
            .abnormal
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > etd_proc::GIVE_UP_WINDOW)
        {
            self.abnormal.pop_front();
        }
        u32::try_from(self.abnormal.len()).unwrap_or(u32::MAX)
    }

    // ----- input ---------------------------------------------------------

    fn wake_at(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Live(l) => Some(l.next_tick),
            Phase::Backoff { until } => Some(*until),
            Phase::Reclaim { retry_at, .. } => *retry_at,
            _ => None,
        }
    }

    async fn next_input(&mut self) -> Input {
        if let Some(cmd) = self.deferred.pop_front() {
            return Input::Cmd(cmd);
        }
        let clock = self.ctx.deps.clock.clone();
        let sleep = match self.wake_at() {
            Some(at) => clock.sleep(at.saturating_duration_since(clock.now())),
            None => Box::pin(std::future::pending()),
        };
        let (events, fence) = match &mut self.phase {
            Phase::Live(l) => {
                let l = &mut **l;
                (l.events.as_mut(), l.fence_task.as_mut().map(|t| &mut t.rx))
            }
            _ => (None, None),
        };
        let has_events = events.is_some();
        let recv_events = async move {
            match events {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        let has_fence = fence.is_some();
        let recv_fence = async move {
            match fence {
                Some(rx) => rx.await.ok(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            ev = recv_events, if has_events => Input::Proc(ev),
            checked = recv_fence, if has_fence => Input::Fence(checked),
            cmd = self.cmds.recv(), if !self.cmds_closed => match cmd {
                Some(cmd) => Input::Cmd(cmd),
                None => {
                    // The orchestrator is gone: wind down.
                    self.cmds_closed = true;
                    let (tx, _) = oneshot::channel();
                    Input::Cmd(SupCmd::Shutdown { reply: tx })
                }
            },
            changed = self.presence.changed(), if !self.presence_closed => {
                if changed.is_err() {
                    self.presence_closed = true;
                }
                Input::Presence
            }
            () = sleep => Input::Tick,
        }
    }

    async fn handle(&mut self, input: Input) -> Flow {
        match input {
            Input::Cmd(cmd) => self.on_cmd(cmd).await,
            Input::Proc(ev) => self.on_process(ev).await,
            Input::Tick => self.on_tick().await,
            Input::Fence(checked) => self.on_fence(checked).await,
            Input::Presence => {
                let presence = *self.presence.borrow();
                let now = self.now();
                if let Phase::Live(l) = &mut self.phase
                    && let Some(p) = l.poller.as_mut()
                {
                    p.presence_changed(now, &presence);
                    l.next_tick = l.next_tick.min(p.deadline());
                }
                Flow::Continue
            }
        }
    }

    // ----- driving toward desired state ----------------------------------

    async fn drive(&mut self) -> Flow {
        loop {
            match &self.phase {
                Phase::Idle => {
                    if self.shutdown.is_some() || self.desired.is_none() {
                        if self.desired.is_none() && self.status.state() != InstanceState::Stopped {
                            self.set_state(InstanceState::Stopped, "removed");
                        }
                        return Flow::Exit;
                    }
                    if self.wants_running() {
                        if self.gave_up || self.waiting {
                            return Flow::Continue;
                        }
                        if self.try_start(None).await == Flow::Exit {
                            return Flow::Exit;
                        }
                        if matches!(self.phase, Phase::Idle) {
                            return Flow::Continue;
                        }
                        continue;
                    }
                    self.gave_up = false;
                    self.waiting = false;
                    if self.status.state() != InstanceState::Stopped {
                        self.set_state(InstanceState::Stopped, "");
                    }
                    return Flow::Continue;
                }
                Phase::Reclaim {
                    epoch,
                    then,
                    retry_at,
                } => {
                    if retry_at.is_some_and(|t| t > self.now()) {
                        return Flow::Continue;
                    }
                    let (epoch, then) = (*epoch, then.clone());
                    // No automatic reclaim before the self-check has
                    // accounted for every kernel of ours.
                    if let Some(why) = self.ctx.held() {
                        let retry = self.now() + self.ctx.config.reclaim_retry;
                        self.phase = Phase::Reclaim {
                            epoch,
                            then,
                            retry_at: Some(retry),
                        };
                        if self.status.message != why {
                            self.set_state(InstanceState::Reclaiming, why);
                        }
                        if self.shutdown.is_some() {
                            return Flow::Exit;
                        }
                        return Flow::Continue;
                    }
                    if self.reclaim(epoch, then, false).await == Flow::Exit {
                        return Flow::Exit;
                    }
                    if matches!(
                        self.phase,
                        Phase::Reclaim { .. } | Phase::Quarantined { .. }
                    ) {
                        if self.shutdown.is_some() {
                            return Flow::Exit;
                        }
                        return Flow::Continue;
                    }
                }
                Phase::Backoff { until } => {
                    if self.shutdown.is_some() {
                        return Flow::Exit;
                    }
                    if *until > self.now() {
                        return Flow::Continue;
                    }
                    self.phase = Phase::Idle;
                }
                Phase::Quarantined { .. } | Phase::Cut { .. } => {
                    return if self.shutdown.is_some() {
                        Flow::Exit
                    } else {
                        Flow::Continue
                    };
                }
                Phase::Live(_) => return Flow::Continue,
            }
        }
    }

    /// Start a generation: the committed one (`launch`) or a new one
    /// reserved with `begin_epoch`.
    async fn try_start(&mut self, launch: Option<Epoch>) -> Flow {
        // The self-check could not account for every kernel: nothing starts.
        if let Some(why) = self.ctx.held() {
            self.waiting = true;
            if self.status.state() != InstanceState::Waiting {
                self.set_state(InstanceState::Waiting, why);
            }
            return Flow::Continue;
        }
        let ledger = self.ctx.deps.ledger.clone();
        if let Some(epoch) = launch {
            match ledger.generation(&self.id, epoch).await {
                Ok(Some(stored)) if !stored.closed => {
                    if !self.wants_running() {
                        // Superseded by a later committed stop: close the
                        // never-spawned generation.
                        self.enter_reclaim(epoch, Then::Settle, "start superseded by a stop");
                        return Flow::Continue;
                    }
                    return self.launch(epoch, stored).await;
                }
                Ok(_) => {} // closed or compacted: reconcile with a new one
                Err(e) => {
                    self.retry_later(format!("ledger unavailable: {e}"));
                    return Flow::Continue;
                }
            }
            if !self.wants_running() {
                return Flow::Continue;
            }
        }
        let Some(spec) = self.desired.as_ref().and_then(|d| d.spec.clone()) else {
            self.give_up_now("the instance has no configuration".into());
            return Flow::Continue;
        };
        let epoch = match ledger.next_epoch(&self.id).await {
            Ok(e) => e,
            Err(e) => {
                self.retry_later(format!("ledger unavailable: {e}"));
                return Flow::Continue;
            }
        };
        // The revision that committed this configuration (begin_epoch
        // requires it to match).
        let revision = match ledger.spec_revision(&self.id).await {
            Ok(r) => r,
            Err(LedgerError::UnknownInstance(_)) => {
                self.waiting = true;
                return Flow::Continue;
            }
            Err(e) => {
                self.retry_later(format!("ledger unavailable: {e}"));
                return Flow::Continue;
            }
        };
        let planned = match plan::plan_generation(
            &self.ctx,
            &self.id,
            &spec,
            revision,
            epoch,
            self.fence_failed,
        )
        .await
        {
            Ok(p) => p,
            Err(PlanFailure::Ledger(e)) => {
                self.retry_later(format!("ledger unavailable: {e}"));
                return Flow::Continue;
            }
            Err(f) => {
                self.notice(NoticeLevel::Error, "start.refused", f.message());
                self.give_up_now(f.message());
                return Flow::Continue;
            }
        };
        match ledger.begin_epoch(planned.generation).await {
            Ok(_) => {}
            Err(LedgerError::ExclusiveTaken { resource, holder }) => {
                self.waiting = true;
                let message = format!("waiting for {resource}, held by instance {holder}");
                self.notice(NoticeLevel::Info, "start.deferred", message.clone());
                self.status.epoch = self.status.epoch.max(epoch.0.saturating_sub(1));
                self.set_state(InstanceState::Waiting, message);
                return Flow::Continue;
            }
            Err(LedgerError::EpochOpen { open, .. }) => {
                self.enter_reclaim(open, Then::Settle, "reclaiming an open generation first");
                return Flow::Continue;
            }
            Err(LedgerError::EpochNotNext { .. }) => {
                // A client commit reserved a generation meanwhile; its
                // ticket brings it here.
                return Flow::Continue;
            }
            Err(LedgerError::RemovalPending { .. } | LedgerError::UnknownInstance(_)) => {
                // Being removed: the removal ticket ends this task.
                self.waiting = true;
                return Flow::Continue;
            }
            Err(e @ (LedgerError::InvalidPlan { .. } | LedgerError::CounterExhausted(_))) => {
                let message = format!("cannot reserve a generation: {e}");
                self.notice(NoticeLevel::Error, "start.refused", message.clone());
                self.give_up_now(message);
                return Flow::Continue;
            }
            Err(e) => {
                self.retry_later(format!("cannot reserve a generation: {e}"));
                return Flow::Continue;
            }
        }
        match ledger.generation(&self.id, epoch).await {
            Ok(Some(stored)) => self.launch(epoch, stored).await,
            Ok(None) => {
                self.retry_later("reserved generation vanished".into());
                Flow::Continue
            }
            Err(e) => {
                self.enter_reclaim(epoch, Then::Settle, format!("ledger unavailable: {e}"));
                Flow::Continue
            }
        }
    }

    /// Transient problem before any generation exists: try again later.
    fn retry_later(&mut self, message: String) {
        let until = self.now() + self.ctx.config.reclaim_retry;
        self.status.next_restart_unix_ms = wall_ms(&self.ctx, until);
        self.phase = Phase::Backoff { until };
        self.set_state(InstanceState::Backoff, message);
    }

    fn give_up_now(&mut self, message: String) {
        self.gave_up = true;
        self.phase = Phase::Idle;
        self.set_state(InstanceState::GaveUp, message);
    }

    fn enter_reclaim(&mut self, epoch: Epoch, then: Then, message: impl Into<String>) {
        self.status.epoch = epoch.0;
        self.phase = Phase::Reclaim {
            epoch,
            then,
            retry_at: None,
        };
        self.set_state(InstanceState::Reclaiming, message);
    }

    // ----- launch --------------------------------------------------------

    async fn launch(&mut self, epoch: Epoch, stored: StoredGeneration) -> Flow {
        self.waiting = false;
        self.remember_secret(&stored.inputs.spec);
        self.status.epoch = epoch.0;
        self.status.core_version = stored.inputs.core.version.clone();
        self.status.last_exit = self.status.last_exit.take();
        self.status.interface_name.clear();
        self.status.addresses.clear();
        self.set_state(InstanceState::Starting, "");
        self.status.management = management_of(stored.inputs.guard, false) as i32;
        match self.prepare_and_spawn(epoch, &stored).await {
            Ok(live) => {
                self.phase = Phase::Live(live);
                self.publish();
                Flow::Continue
            }
            Err(fail) => {
                let then = match fail {
                    LaunchFail::Fatal(m) => {
                        self.notice(NoticeLevel::Error, "start.failed", m.clone());
                        Then::GiveUp(m)
                    }
                    LaunchFail::Fence(m) => {
                        self.notice(NoticeLevel::Warning, "fence.failed", m.clone());
                        Then::FenceFallback
                    }
                    LaunchFail::Abnormal(m) => {
                        self.notice(NoticeLevel::Warning, "start.failed", m.clone());
                        let exit = Exit {
                            code: None,
                            signal: None,
                            cause: ExitCause::Exited,
                        };
                        self.abnormal_then(&exit)
                    }
                    LaunchFail::Exited(exit) => {
                        self.notice(
                            NoticeLevel::Warning,
                            "start.failed",
                            format!("the kernel exited at once (code {:?})", exit.code),
                        );
                        let then = self.abnormal_then(&exit);
                        self.report_exit(epoch, &exit, &then);
                        then
                    }
                    LaunchFail::Uncertain(m) => {
                        self.quarantine_uncertain(epoch, m).await;
                        return Flow::Continue;
                    }
                    LaunchFail::Taken(m) => {
                        self.notice(NoticeLevel::Error, "start.refused", m.clone());
                        Then::Quarantine(m)
                    }
                    LaunchFail::Superseded(m) => {
                        self.notice(NoticeLevel::Info, "start.superseded", m);
                        Then::Settle
                    }
                    LaunchFail::Refused(m) => {
                        self.notice(NoticeLevel::Error, "start.refused", m.clone());
                        Then::GiveUp(m)
                    }
                    LaunchFail::Cut(reply) => {
                        // Nothing was spawned; like a cut of a live kernel,
                        // the generation waits for a committed desired state.
                        self.status.epoch = epoch.0;
                        self.phase = Phase::Cut { epoch: Some(epoch) };
                        self.set_state(InstanceState::CutUnconfirmed, "stop could not be recorded");
                        let _ = reply.send(Ok(()));
                        return Flow::Continue;
                    }
                };
                self.enter_reclaim(epoch, then, "launch failed");
                Flow::Continue
            }
        }
    }

    /// Re-read the persisted desired state right before a launch side
    /// effect: the instance must still be wanted RUNNING with exactly the
    /// configuration (and spec revision) this generation was planned from.
    async fn still_wanted(&mut self, stored: &StoredGeneration) -> Result<(), LaunchFail> {
        let ledger = self.ctx.deps.ledger.clone();
        let unavailable = |e: LedgerError| LaunchFail::Abnormal(format!("ledger unavailable: {e}"));
        let (_, desired) = ledger.desired().await.map_err(unavailable)?;
        let current = desired.into_iter().find(|d| d.instance_id == self.id.0);
        let revision = match &current {
            Some(_) => Some(ledger.spec_revision(&self.id).await.map_err(unavailable)?),
            None => None,
        };
        let wanted = current.as_ref().is_some_and(|d| {
            d.desired() == Desired::Running
                && d.spec.as_ref() == Some(&stored.inputs.spec)
                && revision == Some(stored.inputs.spec_revision)
        });
        if wanted {
            return Ok(());
        }
        let why = match &current {
            None => "the instance was removed".to_string(),
            Some(d) if d.desired() != Desired::Running => "a stop was committed".to_string(),
            Some(_) => "a new configuration was committed".to_string(),
        };
        self.desired = current.map(Box::new);
        Err(LaunchFail::Superseded(format!(
            "generation not started: {why} meanwhile"
        )))
    }

    fn record_of(stored: &StoredGeneration, pred: impl Fn(EffectKind) -> bool) -> Option<Effect> {
        stored.effects.iter().find(|e| pred(e.kind)).cloned()
    }

    async fn prepare_and_spawn(
        &mut self,
        epoch: Epoch,
        stored: &StoredGeneration,
    ) -> Result<Box<Live>, LaunchFail> {
        let deps = self.ctx.deps.clone();
        let inputs = stored.inputs.clone();
        let plan = plan::replay(&self.ctx, &self.id, epoch, stored)
            .await
            .map_err(|f| LaunchFail::Fatal(f.message()))?;

        // The derived interface name must be free: a foreign object holding
        // it (e.g. a conflict an administrator chose to keep) blocks starts.
        let named = plan.effects.iter().find_map(|e| match &e.key {
            ObjectKey::Interface { name: Some(n), .. } => Some(n.clone()),
            _ => None,
        });
        if let Some(name) = named {
            let key = ObjectKey::Interface {
                name: Some(name.clone()),
                guid: None,
            };
            match deps.observer.interface(&key).await {
                Ok(None) => {}
                Ok(Some(found)) => {
                    return Err(LaunchFail::Taken(format!(
                        "interface name {name} is held by another object ({:?})",
                        found.credential
                    )));
                }
                Err(e) => {
                    return Err(LaunchFail::Abnormal(format!(
                        "cannot check interface name {name}: {e}"
                    )));
                }
            }
        }

        // Program firewall rules the kernel will replace: one such start at
        // a time (`Ctx::program_rules`), held until they are read back.
        let has_rules = stored.effects.iter().any(is_program_rule);
        let rule_gate = if has_rules {
            Some(self.rule_gate().await?)
        } else {
            None
        };

        // No side effect for a generation the committed state no longer
        // wants (a stop or a new configuration committed meanwhile).
        self.still_wanted(stored).await?;
        let rules = if has_rules {
            self.check_program_rules(epoch).await?
        } else {
            Vec::new()
        };
        let pending = self
            .flag_preexisting(stored)
            .await
            .map_err(LaunchFail::Abnormal)?;

        // Fence before anything listens.
        let fence = if inputs.guard == ManagementGuard::Fence {
            let fence = deps
                .fence
                .clone()
                .ok_or_else(|| LaunchFail::Fatal("fence unavailable".into()))?;
            let spec = plan::fence_spec(&self.id, epoch, &inputs);
            let record = Self::record_of(stored, is_fence_kind)
                .ok_or_else(|| LaunchFail::Fatal("generation has no fence record".into()))?;
            fence_seq::install(fence.as_ref(), deps.ledger.as_ref(), &record, &spec)
                .await
                .map_err(LaunchFail::Fence)?;
            Some(spec)
        } else {
            None
        };

        // Runtime directory and the generated files.
        let dir_record = Self::record_of(stored, |k| k == EffectKind::RuntimeDir)
            .ok_or_else(|| LaunchFail::Fatal("generation has no runtime directory".into()))?;
        let dir = inputs.runtime_dir.clone();
        if !crate::reclaimers::inside(&deps.dirs.run_dir, &dir)
            || plan
                .files
                .iter()
                .any(|f| !crate::reclaimers::inside(&dir, &f.path))
        {
            return Err(LaunchFail::Fatal(
                "planned files escape the runtime directory".into(),
            ));
        }
        let files = plan.files.clone();
        let write_dir = dir.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            // The directory stays writable (the kernel's file log and panic
            // log go here); the generated files are read-only, because the
            // kernel rewrites its config file on RPC configuration changes.
            std::fs::create_dir_all(&write_dir)?;
            crate::reclaimers::make_writable(&write_dir)?;
            for f in files {
                if let Some(parent) = f.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&f.path, &f.contents)?;
                let mut perms = std::fs::metadata(&f.path)?.permissions();
                perms.set_readonly(true);
                std::fs::set_permissions(&f.path, perms)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| LaunchFail::Abnormal(e.to_string()))?
        .map_err(|e| LaunchFail::Abnormal(format!("cannot write {}: {e}", dir.display())))?;
        deps.ledger
            .transition(
                &dir_record.id,
                EffectState::Applied,
                Some(Observation {
                    credential: Some(Credential::ExclusiveContainer {
                        container: deps.dirs.run_dir.display().to_string(),
                    }),
                    key: Some(dir_record.key.clone()),
                    observed_at: deps.clock.wall_now(),
                    detail: None,
                }),
            )
            .await
            .map_err(|e| LaunchFail::Abnormal(format!("ledger: {e}")))?;

        // Spawn, then record its identity at once.
        self.still_wanted(stored).await?;
        let process_record = Self::record_of(stored, |k| k == EffectKind::Process)
            .ok_or_else(|| LaunchFail::Fatal("generation has no process record".into()))?;
        let mut handle = deps
            .process
            .spawn(plan.command.clone())
            .await
            .map_err(|e| match e {
                ProcessError::ExitedBeforeIdentity(exit) => LaunchFail::Exited(exit),
                ProcessError::CleanupUncertain(m) => LaunchFail::Uncertain(m),
                e => LaunchFail::Abnormal(format!("spawn failed: {e}")),
            })?;
        let identity = handle.identity().clone();
        let containment = handle.containment();
        let recorded = deps
            .ledger
            .transition(
                &process_record.id,
                EffectState::Applied,
                Some(Observation {
                    credential: Some(Credential::Process {
                        pid: identity.pid,
                        start_token: identity.start_token.clone(),
                    }),
                    key: Some(process_record.key.clone()),
                    observed_at: deps.clock.wall_now(),
                    detail: Some(crate::reclaimers::process_detail(identity.pid, containment)),
                }),
            )
            .await;
        if let Err(e) = recorded {
            // Never leave an unrecorded kernel running.
            return Err(match handle.kill().await {
                Err(ProcessError::CleanupUncertain(m)) => LaunchFail::Uncertain(m),
                Err(k) => LaunchFail::Uncertain(format!(
                    "kernel identity not recorded ({e}) and the kill failed: {k}"
                )),
                Ok(_) => LaunchFail::Abnormal(format!("kernel identity not recorded: {e}")),
            });
        }
        let events = handle.take_events();
        let now = self.now();

        Ok(Box::new(Live {
            epoch,
            inputs,
            plan,
            handle,
            events,
            pid: identity.pid,
            spawned: now,
            start_deadline: now + self.ctx.config.start_timeout,
            fence,
            fence_ok: false,
            fence_due: now,
            fence_lost: 0,
            fence_unverifiable: 0,
            fence_task: None,
            basic: false,
            session: None,
            attach_after: now,
            poller: None,
            cursor: None,
            pending,
            rules,
            rule_gate,
            rules_due: now,
            rules_deadline: None,
            rules_several: HashMap::new(),
            next_tick: now,
            stdout: LineBuffer::default(),
            stderr: LineBuffer::default(),
        }))
    }

    // ----- live generation -------------------------------------------------

    async fn on_tick(&mut self) -> Flow {
        let Phase::Live(_) = &self.phase else {
            return Flow::Continue; // timers of other phases are handled by drive
        };
        let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!()
        };
        match self.live_tick(&mut live).await {
            Ok(()) => {
                self.phase = Phase::Live(live);
                Flow::Continue
            }
            Err(kill) => self.kill_live(live, kill).await,
        }
    }

    /// A fence re-verification finished (see [`fence_seq::recheck`]).
    async fn on_fence(&mut self, checked: Option<fence_seq::Recheck>) -> Flow {
        let Phase::Live(_) = &self.phase else {
            return Flow::Continue;
        };
        let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            unreachable!()
        };
        live.fence_task = None;
        let checked = checked.unwrap_or_else(|| {
            fence_seq::Recheck::Unverifiable("the re-verification ended without a result".into())
        });
        match self.fence_rechecked(&mut live, checked) {
            Ok(()) => {
                self.phase = Phase::Live(live);
                Flow::Continue
            }
            Err(kill) => self.kill_live(live, kill).await,
        }
    }

    /// Ruling topic#40 msg#1150 item 5: two definite losses in a row kill;
    /// an unverifiable result is retried and never kills, and a run of them
    /// is reported once. The next check counts from now (this one's end).
    fn fence_rechecked(
        &mut self,
        live: &mut Live,
        checked: fence_seq::Recheck,
    ) -> Result<(), KillFor> {
        let now = self.now();
        let config = self.ctx.config.clone();
        match checked {
            fence_seq::Recheck::Verified => {
                live.fence_lost = 0;
                live.fence_unverifiable = 0;
                live.fence_due = now + config.fence_recheck;
            }
            fence_seq::Recheck::Lost(why) => {
                live.fence_unverifiable = 0;
                live.fence_lost += 1;
                if live.fence_lost >= 2 {
                    return Err(KillFor::FenceLost(why));
                }
                tracing::warn!(instance = %self.id, reason = %why, "fence lost once; verifying again");
                live.fence_due = now + config.fence_retry;
            }
            fence_seq::Recheck::Unverifiable(why) => {
                live.fence_lost = 0;
                live.fence_unverifiable += 1;
                live.fence_due = now + config.fence_unverifiable_retry;
                tracing::warn!(instance = %self.id, reason = %why, "fence could not be verified; retrying");
                if live.fence_unverifiable == FENCE_UNVERIFIABLE_NOTICE_AFTER {
                    self.notice(
                        NoticeLevel::Warning,
                        "fence.unverifiable",
                        format!(
                            "the management port fence could not be verified \
                             {FENCE_UNVERIFIABLE_NOTICE_AFTER} times in a row (last: {why}); \
                             the kernel keeps running and the check is retried"
                        ),
                    );
                }
            }
        }
        live.next_tick = live.next_tick.min(live.fence_due);
        Ok(())
    }

    /// One readiness / enumeration / fence / poll round. `Err` asks for
    /// the kernel to be killed with that consequence.
    async fn live_tick(&mut self, live: &mut Live) -> Result<(), KillFor> {
        let deps = self.ctx.deps.clone();
        let now = self.now();
        self.enumerate(live).await;

        if let Some(spec) = &live.fence
            && !live.fence_ok
            && let Some(fence) = deps.fence.as_ref()
        {
            match fence_seq::check(deps.observer.as_ref(), fence.as_ref(), spec, live.pid).await {
                FenceCheck::Verified => {
                    live.fence_ok = true;
                    live.fence_due = now + self.ctx.config.fence_recheck;
                    self.status.management = ManagementAccess::Available as i32;
                    self.publish();
                }
                FenceCheck::Failed(m) => return Err(KillFor::Fence(m)),
                FenceCheck::Pending => {}
            }
        } else if let Some(spec) = &live.fence
            && live.fence_ok
            && live.fence_task.is_none()
            && now >= live.fence_due
            && let Some(fence) = deps.fence.clone()
        {
            // While it runs: a firewall reload or another program can drop
            // the rule under the kernel. Verified off this task (a verify
            // can take seconds); the result arrives as `Input::Fence`.
            let observer = deps.observer.clone();
            let spec = spec.clone();
            let pid = live.pid;
            let (tx, rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                let _ = tx
                    .send(fence_seq::recheck(observer.as_ref(), fence.as_ref(), &spec, pid).await);
            });
            live.fence_task = Some(FenceTask {
                rx,
                abort: task.abort_handle(),
            });
        }

        if !live.basic {
            let uptime = now.saturating_duration_since(live.spawned);
            if uptime >= live.plan.readiness.minimum_uptime
                && (live.fence.is_none() || live.fence_ok)
                && self
                    .condition_met(&live.plan.readiness.condition.clone(), live.pid)
                    .await
            {
                live.basic = true;
                self.set_state(InstanceState::ReadyBasic, "");
            } else if now >= live.start_deadline {
                return Err(KillFor::NotReady);
            }
        }

        // Program firewall rules: nothing is recorded while the kernel
        // starts (a kernel gone before readiness leaves the records as they
        // were); they are settled once it is basically ready.
        if live.rules.is_empty() {
            live.rule_gate = None;
        } else if live.basic && self.now() >= live.rules_due {
            self.settle_rules(live).await;
        }

        let may_attach = live.basic
            && match live.inputs.guard {
                ManagementGuard::Fence => live.fence_ok,
                ManagementGuard::Unguarded => true,
                _ => false,
            };
        if may_attach && live.session.is_none() && now >= live.attach_after {
            self.attach(live).await;
        }

        if let (Some(session), Some(poller)) = (live.session.clone(), live.poller.as_mut())
            && poller.due(self.now())
        {
            match poller::poll_round(session.as_ref(), live.cursor).await {
                Ok((events, cursor)) => {
                    live.cursor = cursor;
                    for e in events {
                        self.on_core_event(live.epoch, e.kind);
                    }
                }
                Err(e) => {
                    live.session = None;
                    live.poller = None;
                    live.attach_after = self.now() + poller::SUBSCRIBED_INTERVAL;
                    self.set_state(
                        InstanceState::ReadyBasic,
                        format!("management session lost: {e}"),
                    );
                }
            }
            let presence = *self.presence.borrow();
            if let Some(p) = live.poller.as_mut() {
                p.rearm(self.now(), &presence);
            }
        }

        let now = self.now();
        live.next_tick = match (&live.poller, live.basic, may_attach) {
            (Some(p), true, _) => p.deadline(),
            (None, true, false) => now + poller::HEALTH_CHECK_INTERVAL,
            (None, true, true) => live.attach_after.max(now + self.ctx.config.readiness_tick),
            _ => now + self.ctx.config.readiness_tick,
        };
        if !live.basic {
            live.next_tick = live.next_tick.min(live.start_deadline.max(now));
        }
        if !live.pending.is_empty() {
            // Credentials still to read back: a crash meanwhile would leave
            // those records as candidates.
            live.next_tick = live.next_tick.min(now + self.ctx.config.readiness_tick);
        }
        if live.fence.is_some() && live.fence_ok && live.fence_task.is_none() {
            live.next_tick = live.next_tick.min(live.fence_due.max(now));
        }
        if !live.rules.is_empty() && live.basic {
            live.next_tick = live.next_tick.min(live.rules_due.max(now));
        }
        Ok(())
    }

    /// Read what is found under a program firewall rule's name: the
    /// observer locates the rule (it fails closed on several, or on one for
    /// another program, group or direction); an independent enumeration of
    /// every rule of that name must tell the same story, else the read is
    /// unknown. An observer error alone is never a verdict.
    async fn read_program_rule(&mut self, e: &Effect) -> RuleRead {
        let observer = self.ctx.deps.observer.clone();
        let ObjectKey::Rule { name, .. } = &e.key else {
            return RuleRead::Unknown("not a named rule".into());
        };
        let observed = observer.observe(e.kind, &e.key).await;
        let same_name: Vec<_> = match observer.enumerate(SystemClass::FirewallRules).await {
            Ok(entries) => entries
                .into_iter()
                .filter(|s| {
                    matches!(&s.key, ObjectKey::Rule { name: n, .. } if n.eq_ignore_ascii_case(name))
                })
                .collect(),
            Err(err) => return RuleRead::Unknown(format!("cannot enumerate firewall rules: {err}")),
        };
        if same_name.len() >= 2 {
            return RuleRead::Several(same_name.len());
        }
        match (observed, same_name.first()) {
            (Err(err), _) => RuleRead::Unknown(format!("cannot observe the rule: {err}")),
            (Ok(None), None) => RuleRead::Absent,
            (Ok(None), Some(_)) => {
                RuleRead::Unknown("the rule appeared while it was looked at".into())
            }
            (Ok(Some(_)), None) => {
                RuleRead::Unknown("the rule vanished while it was looked at".into())
            }
            (Ok(Some(o)), Some(one)) => match &o.credential {
                Some(found) if one.identity.as_ref() == Some(found) => RuleRead::One(o),
                Some(_) => RuleRead::Unknown("the rule changed while it was looked at".into()),
                None => {
                    RuleRead::Unconfirmed("no identity of the kernel's rule could be read".into())
                }
            },
        }
    }

    /// Wait for `Ctx::program_rules`. Commands meanwhile are deferred, except
    /// a cut or a shutdown, which abandon this launch (nothing is spawned).
    async fn rule_gate(&mut self) -> Result<OwnedMutexGuard<()>, LaunchFail> {
        let gate = self.ctx.program_rules.clone();
        if let Ok(held) = gate.clone().try_lock_owned() {
            return Ok(held);
        }
        self.status.message =
            "waiting for another start of this kernel to settle its firewall rules".into();
        self.publish();
        let acquire = gate.lock_owned();
        tokio::pin!(acquire);
        let abandoned =
            || LaunchFail::Superseded("generation not started: the host is shutting down".into());
        loop {
            tokio::select! {
                biased;
                held = &mut acquire => {
                    self.status.message.clear();
                    self.publish();
                    return Ok(held);
                }
                cmd = self.cmds.recv(), if !self.cmds_closed => match cmd {
                    Some(SupCmd::Cut { reply }) => return Err(LaunchFail::Cut(reply)),
                    Some(SupCmd::Shutdown { reply }) => {
                        self.shutdown = Some(reply);
                        self.stopping_for_exit = true;
                        return Err(abandoned());
                    }
                    Some(SupCmd::Query { reply, .. }) => {
                        let _ = reply.send(Err(unavailable(&self.id)));
                    }
                    Some(other) => self.deferred.push_back(other),
                    None => {
                        // The orchestrator is gone: wind down.
                        self.cmds_closed = true;
                        self.stopping_for_exit = true;
                        let (tx, _) = oneshot::channel();
                        self.shutdown = Some(tx);
                        return Err(abandoned());
                    }
                },
            }
        }
    }

    /// Before the spawn, holding `Ctx::program_rules`: the program firewall
    /// rules the kernel will delete and recreate must be absent or exactly
    /// the ones this host recorded (ruling topic#36 msg#931). A definite
    /// other state (a rule we never recorded, another identity, one the
    /// observer does not confirm, several of that name in two snapshots
    /// `reclaim_retry` apart, a record awaiting an administrator) refuses
    /// the start: the kernel would overwrite a rule that is not ours.
    /// Anything unknown backs off and tries again. Returns the records to
    /// settle after readiness.
    async fn check_program_rules(&mut self, epoch: Epoch) -> Result<Vec<Effect>, LaunchFail> {
        // Fresh states: another generation of this kernel may have
        // refreshed the shared records since this one was read.
        let stored = match self.ctx.deps.ledger.generation(&self.id, epoch).await {
            Ok(Some(stored)) => stored,
            Ok(None) => return Err(LaunchFail::Abnormal("reserved generation vanished".into())),
            Err(e) => return Err(LaunchFail::Abnormal(format!("ledger unavailable: {e}"))),
        };
        let mut settle = Vec::new();
        for e in stored.effects.into_iter().filter(is_program_rule) {
            let what = format!("{} {}", e.kind, view::key_text(&e.key));
            if !matches!(e.state, EffectState::Planned | EffectState::Applied) {
                return Err(LaunchFail::Refused(format!(
                    "{what} is {:?} in the ledger, awaiting an administrator; the kernel would replace it",
                    e.state
                )));
            }
            let read = self.read_program_rule(&e).await;
            let several_since = match read {
                RuleRead::Several(_) => self.rules_several.get(&e.id).copied(),
                _ => {
                    self.rules_several.remove(&e.id);
                    None
                }
            };
            match read {
                RuleRead::Absent => settle.push(e),
                RuleRead::One(o) if o.credential.as_ref() == recorded_credential(&e) => {
                    settle.push(e);
                }
                RuleRead::One(_) => {
                    return Err(LaunchFail::Refused(format!(
                        "{what} exists but is not the rule this host recorded; the kernel would replace it"
                    )));
                }
                RuleRead::Several(n) => {
                    let now = self.now();
                    match several_since {
                        Some(since)
                            if now.saturating_duration_since(since)
                                >= self.ctx.config.reclaim_retry =>
                        {
                            self.rules_several.remove(&e.id);
                            return Err(LaunchFail::Refused(format!(
                                "{n} rules with the name of {what} exist; the kernel would replace them"
                            )));
                        }
                        Some(_) => {}
                        None => {
                            self.rules_several.insert(e.id.clone(), now);
                        }
                    }
                    return Err(LaunchFail::Abnormal(format!(
                        "{n} rules with the name of {what} seen; looking again before deciding"
                    )));
                }
                RuleRead::Unconfirmed(m) => {
                    return Err(LaunchFail::Refused(format!(
                        "{what} exists and is not confirmed as this kernel's ({m}); the kernel would replace it"
                    )));
                }
                // An unknown baseline is never taken as absent: no start.
                RuleRead::Unknown(m) => {
                    return Err(LaunchFail::Abnormal(format!(
                        "cannot check {what} before the start: {m}"
                    )));
                }
            }
        }
        Ok(settle)
    }

    /// After basic readiness, holding `Ctx::program_rules` (rulings topic#40
    /// msg#967, msg#1150 items 1-3): a record takes the found credential
    /// only when exactly one rule of that name exists and the observer
    /// confirms it as the kernel binary's. Definitely foreign (several of
    /// that name in two snapshots `reclaim_retry` apart, or one not
    /// confirmed) is a conflict, never deleted. Absent: nothing to claim,
    /// the record stays as it was. Unknown, or a ledger write that failed:
    /// tried again every `reclaim_retry`, gate held, until
    /// `rules_deadline`; then the records stay as they were and the gate
    /// is released.
    async fn settle_rules(&mut self, live: &mut Live) {
        let now = self.now();
        let mut left = Vec::new();
        for mut e in std::mem::take(&mut live.rules) {
            let read = self.read_program_rule(&e).await;
            let several_since = match read {
                RuleRead::Several(_) => live.rules_several.get(&e.id).copied(),
                _ => {
                    live.rules_several.remove(&e.id);
                    None
                }
            };
            let settled = match read {
                RuleRead::One(o) => {
                    (e.state == EffectState::Applied
                        && recorded_credential(&e) == o.credential.as_ref())
                        || self.refresh_rule(&mut e, o).await
                }
                RuleRead::Absent => {
                    self.notice(
                        NoticeLevel::Info,
                        "program_rule.absent",
                        format!(
                            "{} {} is absent after the kernel started; its record is left as it was",
                            e.kind,
                            view::key_text(&e.key)
                        ),
                    );
                    true
                }
                RuleRead::Several(n) => match several_since {
                    Some(since)
                        if now.saturating_duration_since(since)
                            >= self.ctx.config.reclaim_retry =>
                    {
                        live.rules_several.remove(&e.id);
                        self.conflict_rule(
                            &mut e,
                            format!("{n} rules with this name after the kernel started"),
                        )
                        .await
                    }
                    Some(_) => false,
                    None => {
                        live.rules_several.insert(e.id.clone(), now);
                        false
                    }
                },
                RuleRead::Unconfirmed(m) => {
                    self.conflict_rule(
                        &mut e,
                        format!("not confirmed as the kernel's rule after it started: {m}"),
                    )
                    .await
                }
                RuleRead::Unknown(m) => {
                    tracing::debug!(instance = %self.id, error = %m, "program rule not read back yet");
                    false
                }
            };
            if !settled {
                left.push(e);
            }
        }
        let deadline = *live
            .rules_deadline
            .get_or_insert(now + self.ctx.config.start_timeout);
        if !left.is_empty() && now >= deadline {
            let names: Vec<_> = left.iter().map(|e| view::key_text(&e.key)).collect();
            self.notice(
                NoticeLevel::Warning,
                "program_rule.unsettled",
                format!(
                    "program firewall rules not read back in time, records left as they were: {}",
                    names.join(", ")
                ),
            );
            left.clear();
        }
        live.rules = left;
        if live.rules.is_empty() {
            live.rule_gate = None;
            live.rules_several.clear();
        }
        live.rules_due = now + self.ctx.config.reclaim_retry;
    }

    /// Record `o` as the rule's credential (planned or stale before).
    /// `true` once nothing is left to do for this record.
    async fn refresh_rule(&mut self, e: &mut Effect, o: Observation) -> bool {
        match self
            .ctx
            .deps
            .ledger
            .transition(&e.id, EffectState::Applied, Some(o.clone()))
            .await
        {
            Ok(()) => {
                e.state = EffectState::Applied;
                e.observation = Some(o);
                true
            }
            // Moved on meanwhile (e.g. settled as a conflict): not ours to
            // overwrite.
            Err(LedgerError::InvalidTransition { from, .. }) => {
                tracing::warn!(instance = %self.id, ?from, "program rule record moved on; not refreshed");
                true
            }
            Err(err) => {
                tracing::warn!(instance = %self.id, error = %err, "program rule not refreshed");
                false
            }
        }
    }

    /// The record's rule cannot be claimed: a conflict for an
    /// administrator, keeping the credential we recorded (if any) as the
    /// expected one. `true` once nothing is left to do for this record.
    async fn conflict_rule(&mut self, e: &mut Effect, reason: String) -> bool {
        let ledger = self.ctx.deps.ledger.clone();
        if e.state != EffectState::Reclaiming {
            match ledger
                .transition(&e.id, EffectState::Reclaiming, None)
                .await
            {
                Ok(()) => e.state = EffectState::Reclaiming,
                Err(LedgerError::InvalidTransition { .. }) => return true,
                Err(err) => {
                    tracing::warn!(instance = %self.id, error = %err, "program rule conflict not recorded");
                    return false;
                }
            }
        }
        let observation = Observation {
            credential: e.observation.as_ref().and_then(|o| o.credential.clone()),
            key: Some(e.key.clone()),
            observed_at: self.ctx.deps.clock.wall_now(),
            detail: Some(reason.clone()),
        };
        match ledger
            .transition(&e.id, EffectState::Conflict, Some(observation))
            .await
        {
            Ok(()) => {
                e.state = EffectState::Conflict;
                self.notice(
                    NoticeLevel::Warning,
                    "program_rule.conflict",
                    format!(
                        "{} {}: {reason}; left for an administrator",
                        e.kind,
                        view::key_text(&e.key)
                    ),
                );
                true
            }
            Err(LedgerError::InvalidTransition { .. }) => true,
            Err(err) => {
                tracing::warn!(instance = %self.id, error = %err, "program rule conflict not recorded");
                false
            }
        }
    }

    /// Record the creation credential of every kernel object that has
    /// appeared, as soon as it appears.
    async fn enumerate(&mut self, live: &mut Live) {
        let deps = self.ctx.deps.clone();
        if live.pending.is_empty() {
            return;
        }
        // System-assigned interface name (macOS utun): find it via the
        // process, then name both the interface and its routes record.
        let unnamed = live.pending.iter().any(|e| {
            matches!(
                e.key,
                ObjectKey::Interface { name: None, .. } | ObjectKey::RoutesVia { interface: None }
            )
        });
        let mut assigned: Option<InterfaceInfo> = None;
        if unnamed && let Ok(found) = deps.observer.interfaces_owned_by(live.pid).await {
            assigned = found.into_iter().next();
        }
        let mut still = Vec::new();
        for e in std::mem::take(&mut live.pending) {
            let obs = match (&e.key, &assigned) {
                (ObjectKey::Interface { name: None, guid }, Some(info)) => {
                    let key = ObjectKey::Interface {
                        name: Some(info.name.clone()),
                        guid: guid.clone(),
                    };
                    deps.observer
                        .observe(e.kind, &key)
                        .await
                        .ok()
                        .flatten()
                        .map(|mut o| {
                            o.key = Some(key);
                            o
                        })
                }
                (ObjectKey::RoutesVia { interface: None }, Some(info)) => {
                    let key = ObjectKey::RoutesVia {
                        interface: Some(info.name.clone()),
                    };
                    // The interface's credential from the same lookup, so
                    // the reclaimer can tell whether a later interface of
                    // that name (index reused) is still this one.
                    Some(Observation {
                        credential: Some(info.credential.clone()),
                        key: Some(key),
                        observed_at: deps.clock.wall_now(),
                        detail: None,
                    })
                }
                (ObjectKey::Interface { name: None, .. }, None)
                | (ObjectKey::RoutesVia { interface: None }, None) => None,
                (key, _) => deps.observer.observe(e.kind, key).await.ok().flatten(),
            };
            match obs {
                // Applied means "we hold its creation credential": without
                // one the record keeps waiting (a crash meanwhile leaves it a
                // candidate, never deletable by name alone). Shared drivers
                // have none to wait for.
                Some(o)
                    if o.credential.is_some() || credential_less(&e) || is_shared_driver(&e) =>
                {
                    if let Err(err) = deps
                        .ledger
                        .transition(&e.id, EffectState::Applied, Some(o))
                        .await
                    {
                        tracing::warn!(instance = %self.id, error = %err, "record not applied");
                        still.push(e);
                    }
                }
                _ => still.push(e),
            }
        }
        live.pending = still;
    }

    /// Before the spawn: a kernel object that already exists under a key
    /// this generation will read back is not ours. It is flagged as a
    /// conflict for the administrator (never claimed, never deleted) and
    /// left out of the read-back.
    async fn flag_preexisting(&mut self, stored: &StoredGeneration) -> Result<Vec<Effect>, String> {
        let deps = self.ctx.deps.clone();
        let mut pending = Vec::new();
        for e in stored.effects.iter().filter(|e| needs_read_back(e)) {
            // Unnamed keys (system-assigned names) cannot exist yet.
            if matches!(
                e.key,
                ObjectKey::Interface { name: None, .. } | ObjectKey::RoutesVia { interface: None }
            ) || credential_less(e)
            {
                pending.push(e.clone());
                continue;
            }
            match deps.observer.observe(e.kind, &e.key).await {
                Ok(None) => pending.push(e.clone()),
                Ok(Some(found)) => {
                    let message = format!(
                        "{} {} already exists before the kernel starts; left for an administrator",
                        e.kind,
                        view::key_text(&e.key)
                    );
                    deps.ledger
                        .transition(&e.id, EffectState::Reclaiming, None)
                        .await
                        .map_err(|err| format!("ledger: {err}"))?;
                    deps.ledger
                        .transition(&e.id, EffectState::Conflict, Some(found))
                        .await
                        .map_err(|err| format!("ledger: {err}"))?;
                    self.notice(NoticeLevel::Warning, "start.preexisting", message);
                }
                // An unknown baseline is never taken as absent: no start.
                Err(err) => {
                    return Err(format!(
                        "cannot check {} {} before the start: {err}",
                        e.kind,
                        view::key_text(&e.key)
                    ));
                }
            }
        }
        Ok(pending)
    }

    async fn condition_met(&mut self, condition: &ReadinessCondition, pid: u32) -> bool {
        let observer = self.ctx.deps.observer.clone();
        match condition {
            ReadinessCondition::InterfaceAddress(key) => match observer.interface(key).await {
                Ok(Some(info)) if !info.addresses.is_empty() => {
                    self.status.interface_name = info.name;
                    self.status.addresses = info
                        .addresses
                        .iter()
                        .map(|(ip, len)| format!("{ip}/{len}"))
                        .collect();
                    true
                }
                _ => false,
            },
            ReadinessCondition::OwnedInterfaceAddress => {
                match observer.interfaces_owned_by(pid).await {
                    Ok(found) => match found.into_iter().find(|i| !i.addresses.is_empty()) {
                        Some(info) => {
                            self.status.interface_name = info.name;
                            self.status.addresses = info
                                .addresses
                                .iter()
                                .map(|(ip, len)| format!("{ip}/{len}"))
                                .collect();
                            true
                        }
                        None => false,
                    },
                    Err(_) => false,
                }
            }
            ReadinessCondition::Listener(address) => {
                matches!(observer.listener(*address).await, Ok(Some(l)) if l.pid == pid)
            }
            _ => false,
        }
    }

    async fn attach(&mut self, live: &mut Live) {
        let deps = self.ctx.deps.clone();
        // Unfenced (user host): the port was free when planned, but another
        // process could have taken it since; only talk to our own kernel.
        if live.inputs.guard == ManagementGuard::Unguarded {
            match deps.observer.listener(live.plan.endpoint.0).await {
                Ok(Some(l)) if l.pid == live.pid => {}
                Ok(Some(l)) => {
                    if live.attach_after == live.spawned {
                        self.notice(
                            NoticeLevel::Warning,
                            "management.foreign_listener",
                            format!(
                                "management port {} is held by pid {}, not the kernel",
                                live.plan.endpoint.0, l.pid
                            ),
                        );
                    }
                    live.attach_after = self.now() + poller::SUBSCRIBED_INTERVAL;
                    return;
                }
                _ => {
                    live.attach_after = self.now() + poller::SUBSCRIBED_INTERVAL;
                    return;
                }
            }
        }
        let descriptor = etd_core_api::CoreDescriptor {
            version: live.inputs.core.version.clone(),
            proto_revision: live.inputs.core.proto_revision.clone(),
        };
        let result = match deps.core.attach(&live.plan.endpoint, &descriptor).await {
            Ok(session) => {
                let session: Arc<dyn CoreSession> = Arc::from(session);
                let deadline = self.now() + self.ctx.config.full_ready_timeout;
                session
                    .wait_ready(deadline)
                    .await
                    .map(|info| (session, info))
            }
            Err(e) => Err(e),
        };
        match result {
            Ok((session, info)) => {
                if let Some(name) = info.interface_name {
                    self.status.interface_name = name;
                }
                if let Some(cidr) = info.ipv4_cidr {
                    self.status.addresses = vec![cidr];
                }
                live.session = Some(session);
                let presence = *self.presence.borrow();
                live.poller = Some(Poller::new(self.now(), &presence));
                self.set_state(InstanceState::ReadyFull, "");
            }
            Err(e) => {
                live.attach_after = self.now() + poller::SUBSCRIBED_INTERVAL;
                tracing::debug!(instance = %self.id, error = %e, "management not ready");
            }
        }
    }

    fn on_core_event(&mut self, epoch: Epoch, kind: CoreEventKind) {
        match kind {
            CoreEventKind::InterfaceReady { name } => {
                self.status.interface_name = name;
                self.publish();
            }
            CoreEventKind::AddressChanged { ipv4_cidr } => {
                self.status.addresses = ipv4_cidr.into_iter().collect();
                self.publish();
            }
            CoreEventKind::ListenerFailed { url, message } => self.notice(
                NoticeLevel::Warning,
                "core.listener_failed",
                format!("{url}: {message}"),
            ),
            other => self.log(v1::LogSource::Host, epoch, format!("{other:?}")),
        }
    }

    /// Kernel output: complete lines only, so a secret split across chunks
    /// is redacted as a whole.
    fn output(&mut self, live: &mut Live, source: v1::LogSource, bytes: &[u8]) {
        let buffer = match source {
            v1::LogSource::CoreStderr => &mut live.stderr,
            _ => &mut live.stdout,
        };
        for line in buffer.push(bytes, &self.secrets) {
            self.log(source, live.epoch, line);
        }
    }

    /// The rest of the output once the kernel is gone.
    fn flush_output(&mut self, live: &mut Live) {
        if let Some(rx) = live.events.as_mut() {
            let mut queued = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                queued.push(ev);
            }
            for ev in queued {
                match ev {
                    ProcessEvent::Stdout(b) => self.output(live, v1::LogSource::CoreStdout, &b),
                    ProcessEvent::Stderr(b) => self.output(live, v1::LogSource::CoreStderr, &b),
                    _ => {}
                }
            }
        }
        for (source, rest) in [
            (v1::LogSource::CoreStdout, live.stdout.finish(&self.secrets)),
            (v1::LogSource::CoreStderr, live.stderr.finish(&self.secrets)),
        ] {
            if let Some(line) = rest {
                self.log(source, live.epoch, line);
            }
        }
    }

    async fn on_process(&mut self, event: Option<ProcessEvent>) -> Flow {
        let Phase::Live(live) = &self.phase else {
            return Flow::Continue;
        };
        let epoch = live.epoch;
        match event {
            Some(ProcessEvent::Stdout(bytes)) => {
                if let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) {
                    self.output(&mut live, v1::LogSource::CoreStdout, &bytes);
                    self.phase = Phase::Live(live);
                }
                Flow::Continue
            }
            Some(ProcessEvent::Stderr(bytes)) => {
                if let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) {
                    self.output(&mut live, v1::LogSource::CoreStderr, &bytes);
                    self.phase = Phase::Live(live);
                }
                Flow::Continue
            }
            Some(ProcessEvent::Exited(exit)) => {
                let Phase::Live(live) = std::mem::replace(&mut self.phase, Phase::Idle) else {
                    unreachable!()
                };
                self.exited(live, exit, None);
                Flow::Continue
            }
            Some(ProcessEvent::CleanupUncertain(reason)) => {
                // Terminal, not an exit: no restart, quarantine.
                if let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) {
                    self.flush_output(&mut live);
                }
                self.quarantine_uncertain(epoch, reason).await;
                Flow::Continue
            }
            Some(_) => Flow::Continue,
            None => {
                // The event channel closed without a terminal event: wait
                // for the exit only as long as a stop may take, then treat
                // the tree as unconfirmed.
                let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) else {
                    unreachable!()
                };
                live.events = None;
                let clock = self.ctx.deps.clock.clone();
                let grace = self.ctx.config.stop_grace;
                let exit = tokio::select! {
                    exit = live.handle.wait() => Some(exit),
                    () = clock.sleep(grace) => None,
                };
                match exit {
                    Some(exit) => self.exited(live, exit, None),
                    None => {
                        self.flush_output(&mut live);
                        self.quarantine_uncertain(
                            epoch,
                            "the kernel's event channel closed without an exit".into(),
                        )
                        .await;
                    }
                }
                Flow::Continue
            }
        }
    }

    /// The kernel's process tree could not be confirmed empty: never
    /// restart, never reclaim on our own. The process record is quarantined
    /// in the ledger so a host restart keeps it so; only a reclaim retry
    /// (`RetryReclaim`) leaves this state.
    async fn quarantine_uncertain(&mut self, epoch: Epoch, reason: String) {
        let reason = format!("process cleanup uncertain: {reason}");
        let ledger = self.ctx.deps.ledger.clone();
        if let Ok(Some(stored)) = ledger.generation(&self.id, epoch).await {
            for e in stored
                .effects
                .iter()
                .filter(|e| e.kind == EffectKind::Process && !e.state.is_closed())
            {
                if e.state == EffectState::Quarantined {
                    continue;
                }
                if e.state != EffectState::Reclaiming {
                    let _ = ledger
                        .transition(&e.id, EffectState::Reclaiming, None)
                        .await;
                }
                let _ = ledger.record_failure(&e.id, &reason).await;
                if let Err(err) = ledger
                    .transition(&e.id, EffectState::Quarantined, None)
                    .await
                {
                    tracing::warn!(instance = %self.id, error = %err, "quarantine not recorded");
                }
            }
        }
        self.notice(
            NoticeLevel::Error,
            "process.cleanup_uncertain",
            reason.clone(),
        );
        self.status.epoch = epoch.0;
        if self.status.state() != InstanceState::Reclaiming {
            self.set_state(InstanceState::Reclaiming, reason.clone());
        }
        self.phase = Phase::Quarantined { epoch };
        self.set_state(InstanceState::Quarantined, reason);
    }

    /// Stop (graceful with `grace`) or kill the kernel. `Err`: its tree
    /// could not be confirmed gone (quarantine); never waits on a handle
    /// whose cleanup is uncertain.
    async fn terminate(
        handle: &mut dyn ProcessHandle,
        grace: Option<Duration>,
    ) -> Result<Exit, String> {
        if let Some(grace) = grace {
            match handle.stop(grace).await {
                Ok(exit) => return Ok(exit),
                Err(ProcessError::CleanupUncertain(m)) => return Err(m),
                Err(e) => tracing::warn!(error = %e, "graceful stop failed; killing"),
            }
        }
        handle.kill().await.map_err(|e| match e {
            ProcessError::CleanupUncertain(m) => m,
            e => format!("kill failed: {e}"),
        })
    }

    fn report_exit(&mut self, epoch: Epoch, exit: &Exit, then: &Then) {
        self.status.last_exit = Some(exit_info(&self.ctx, exit));
        let (restart_at, gave_up) = match then {
            Then::Backoff(until) => (wall_ms(&self.ctx, *until), false),
            Then::GiveUp(_) => (0, true),
            _ => (0, false),
        };
        self.report(Report::Exited(v1::InstanceExited {
            instance_id: self.id.to_string(),
            epoch: epoch.0,
            exit: Some(exit_info(&self.ctx, exit)),
            attempt: self.status.restart_attempt,
            restart_at_unix_ms: restart_at,
            gave_up,
        }));
    }

    /// The restart decision for an abnormal exit; counts it.
    fn abnormal_then(&mut self, exit: &Exit) -> Then {
        let now = self.now();
        self.abnormal.push_back(now);
        self.status.restart_attempt = self.attempts(now);
        if !self.wants_running() {
            return Then::Settle;
        }
        match self.policy.on_exit(now, exit) {
            RestartDecision::After(d) => Then::Backoff(now + d),
            RestartDecision::GiveUp(reason) => Then::GiveUp(reason),
            RestartDecision::Stay => Then::Settle,
        }
    }

    /// The kernel of `live` is gone: publish, then reclaim its generation.
    fn exited(&mut self, mut live: Box<Live>, exit: Exit, then: Option<Then>) {
        // Output still queued behind the exit.
        self.flush_output(&mut live);
        let then = match then {
            Some(t) => t,
            None if exit.abnormal() => self.abnormal_then(&exit),
            None => Then::Settle,
        };
        self.report_exit(live.epoch, &exit, &then);
        let message = if exit.abnormal() {
            format!("kernel exited (code {:?}), reclaiming", exit.code)
        } else {
            String::new()
        };
        self.enter_reclaim(live.epoch, then, message);
    }

    async fn kill_live(&mut self, mut live: Box<Live>, why: KillFor) -> Flow {
        let then = match &why {
            KillFor::Fence(m) => {
                self.notice(NoticeLevel::Warning, "fence.failed", m.clone());
                Then::FenceFallback
            }
            KillFor::NotReady => {
                self.notice(
                    NoticeLevel::Warning,
                    "start.timeout",
                    "the kernel did not become ready in time",
                );
                let exit = Exit {
                    code: None,
                    signal: None,
                    cause: ExitCause::Exited,
                };
                self.abnormal_then(&exit)
            }
            KillFor::FenceLost(m) => {
                // Management stops at once; the kernel is killed below.
                live.session = None;
                live.poller = None;
                self.status.management = ManagementAccess::Pending as i32;
                self.notice(
                    NoticeLevel::Warning,
                    "fence.lost",
                    format!(
                        "the management port fence no longer holds ({m}); restarting the kernel"
                    ),
                );
                let exit = Exit {
                    code: None,
                    signal: None,
                    cause: ExitCause::Exited,
                };
                self.abnormal_then(&exit)
            }
        };
        let failed = matches!(why, KillFor::NotReady | KillFor::FenceLost(_));
        match Self::terminate(live.handle.as_mut(), None).await {
            // A kernel that never became ready failed on its own account,
            // although the host ended it: report it as abnormal.
            Ok(exit) if failed => self.exited(
                live,
                Exit {
                    cause: ExitCause::Exited,
                    ..exit
                },
                Some(then),
            ),
            Ok(exit) => self.exited(live, exit, Some(then)),
            Err(m) => self.quarantine_uncertain(live.epoch, m).await,
        }
        Flow::Continue
    }

    /// Requested stop: graceful, then tree kill after the grace period. A
    /// cut arriving meanwhile kills at once.
    async fn stop_live(&mut self, mut live: Box<Live>, then: Then) -> Flow {
        live.session = None;
        live.poller = None;
        self.phase = Phase::Idle;
        self.set_state(InstanceState::Stopping, "");
        let grace = self.ctx.config.stop_grace;
        let mut cut: Option<Reply<()>> = None;
        let result = {
            let stop = Self::terminate(live.handle.as_mut(), Some(grace));
            tokio::pin!(stop);
            loop {
                tokio::select! {
                    biased;
                    r = &mut stop => break Some(r),
                    cmd = self.cmds.recv(), if !self.cmds_closed => match cmd {
                        Some(SupCmd::Cut { reply }) => {
                            cut = Some(reply);
                            break None;
                        }
                        Some(SupCmd::Query { reply, .. }) => {
                            let _ = reply.send(Err(unavailable(&self.id)));
                        }
                        Some(other) => self.deferred.push_back(other),
                        None => self.cmds_closed = true,
                    },
                }
            }
        };
        let result = match result {
            Some(r) => r,
            None => Self::terminate(live.handle.as_mut(), None).await,
        };
        let exit = match result {
            Ok(exit) => exit,
            Err(m) => {
                if let Some(reply) = cut {
                    let _ = reply.send(Ok(()));
                }
                self.quarantine_uncertain(live.epoch, m).await;
                return Flow::Continue;
            }
        };
        if let Some(reply) = cut {
            self.cut_after_kill(live.epoch, exit, reply);
            return Flow::Continue;
        }
        self.exited(live, exit, Some(then));
        Flow::Continue
    }

    fn cut_after_kill(&mut self, epoch: Epoch, exit: Exit, reply: Reply<()>) {
        self.status.last_exit = Some(exit_info(&self.ctx, &exit));
        self.report(Report::Exited(v1::InstanceExited {
            instance_id: self.id.to_string(),
            epoch: epoch.0,
            exit: Some(exit_info(&self.ctx, &exit)),
            attempt: self.status.restart_attempt,
            restart_at_unix_ms: 0,
            gave_up: false,
        }));
        self.status.epoch = epoch.0;
        self.phase = Phase::Cut { epoch: Some(epoch) };
        self.set_state(
            InstanceState::CutUnconfirmed,
            "traffic cut; the stop could not be recorded and may be undone by a host restart",
        );
        let _ = reply.send(Ok(()));
    }

    // ----- reclaim ---------------------------------------------------------

    /// An orphan kernel of `epoch` survives: the instance is quarantined
    /// (records persisted by the self-check where a generation is open).
    fn quarantine_orphan(&mut self, epoch: Epoch, reason: String) {
        if matches!(self.phase, Phase::Quarantined { .. } | Phase::Live(_)) {
            return;
        }
        self.waiting = false;
        self.status.epoch = epoch.0;
        self.phase = Phase::Quarantined { epoch };
        if !machine::allowed(self.status.state(), InstanceState::Quarantined) {
            self.set_state(InstanceState::Reclaiming, reason.clone());
        }
        self.set_state(InstanceState::Quarantined, reason);
    }

    /// Kill the kernels running from any of this instance's runtime
    /// directories that no open record knows (orphans of open or closed
    /// generations). `Err`: one survives, or they cannot be looked for.
    async fn kill_instance_orphans(&mut self) -> Result<(), String> {
        let dir = self.ctx.deps.dirs.run_dir.join(self.id.as_str());
        let process = self.ctx.deps.process.clone();
        let found = process
            .find_marked(&crate::boot::kernel_marker(&self.ctx, dir))
            .await
            .map_err(|e| format!("process sweep failed: {e}"))?;
        let filter = ScopeFilter {
            kinds: vec![EffectKind::Process],
            ..ScopeFilter::instance(self.id.clone())
        };
        let recorded: Vec<(u32, String)> = self
            .ctx
            .deps
            .ledger
            .open_effects(&filter)
            .await
            .map_err(|e| format!("process records unreadable: {e}"))?
            .iter()
            .filter_map(crate::reclaimers::recorded_identity)
            .map(|id| (id.pid, id.start_token))
            .collect();
        for id in found {
            if recorded.contains(&(id.pid, id.start_token.clone())) {
                continue; // the reclaim engine handles recorded kernels
            }
            match process.kill_verified(&id).await {
                Ok(KillOutcome::Killed | KillOutcome::Gone | KillOutcome::Reused) => {}
                Ok(KillOutcome::Uncertain) => {
                    return Err(format!(
                        "kernel pid {} could not be killed with certainty",
                        id.pid
                    ));
                }
                Err(e) => return Err(format!("kernel pid {} not killed: {e}", id.pid)),
            }
        }
        Ok(())
    }
    async fn reclaim(&mut self, epoch: Epoch, then: Then, retry: bool) -> Flow {
        let engine = self.ctx.deps.reclaim.clone();
        let result = if retry {
            engine.retry(&self.id).await
        } else {
            engine.reclaim_generation(&self.id, epoch).await
        };
        let report = match result {
            Ok(r) => r,
            Err(e) => {
                self.phase = Phase::Reclaim {
                    epoch,
                    then,
                    retry_at: Some(self.now() + self.ctx.config.reclaim_retry),
                };
                self.set_state(InstanceState::Reclaiming, format!("reclaim failed: {e}"));
                return Flow::Continue;
            }
        };
        self.report(Report::Reclaimed(report.clone()));
        self.status.open_residues = u32::try_from(report.residues.len()).unwrap_or(u32::MAX);
        match report.outcome {
            GenerationOutcome::Closed => self.closed(epoch, then),
            GenerationOutcome::Quarantined(reason) => {
                self.phase = Phase::Quarantined { epoch };
                self.set_state(InstanceState::Quarantined, reason);
                Flow::Continue
            }
            _ => {
                self.phase = Phase::Reclaim {
                    epoch,
                    then,
                    retry_at: Some(self.now() + self.ctx.config.reclaim_retry),
                };
                self.set_state(InstanceState::Reclaiming, "residues remain; retrying");
                Flow::Continue
            }
        }
    }

    /// The generation is closed: follow `then` and desired state.
    fn closed(&mut self, epoch: Epoch, then: Then) -> Flow {
        self.phase = Phase::Idle;
        if then == Then::Exit || self.shutdown.is_some() {
            return Flow::Exit;
        }
        let running = self.wants_running();
        match then {
            Then::GiveUp(reason) if running => {
                self.notice(NoticeLevel::Error, "instance.gave_up", reason.clone());
                self.give_up_now(reason);
            }
            Then::Backoff(until) if running => {
                self.status.next_restart_unix_ms = wall_ms(&self.ctx, until);
                self.phase = Phase::Backoff { until };
                self.set_state(InstanceState::Backoff, "restarting after backoff");
            }
            Then::FenceFallback if running => self.fence_failed = true,
            Then::Quarantine(reason) => {
                self.phase = Phase::Quarantined { epoch };
                self.set_state(InstanceState::Quarantined, reason);
            }
            _ => {}
        }
        Flow::Continue
    }

    // ----- commands --------------------------------------------------------

    async fn on_cmd(&mut self, cmd: SupCmd) -> Flow {
        match cmd {
            SupCmd::Desire {
                desired,
                launch,
                retry_start,
            } => self.on_desire(desired, launch, retry_start).await,
            SupCmd::RetryReclaim => {
                match &self.phase {
                    Phase::Quarantined { epoch } => {
                        let epoch = *epoch;
                        // Kernels of this instance outside any record
                        // (orphans) must go first.
                        if let Err(why) = self.kill_instance_orphans().await {
                            self.notice(NoticeLevel::Error, "reclaim.orphan", why);
                            return Flow::Continue;
                        }
                        // No kernel of this instance is alive outside a
                        // record: automatic reclaim may include it again.
                        self.ctx.readmit(&self.id);
                        self.set_state(InstanceState::Reclaiming, "retrying reclaim");
                        return self.reclaim(epoch, Then::Settle, true).await;
                    }
                    Phase::Reclaim { epoch, then, .. } => {
                        self.phase = Phase::Reclaim {
                            epoch: *epoch,
                            then: then.clone(),
                            retry_at: None,
                        };
                    }
                    _ => {}
                }
                Flow::Continue
            }
            SupCmd::Recheck => {
                if let Phase::Quarantined { epoch } = &self.phase {
                    let epoch = *epoch;
                    self.enter_reclaim(epoch, Then::Settle, "re-checking after a decision");
                } else if self.waiting {
                    self.waiting = false;
                }
                Flow::Continue
            }
            SupCmd::ClaimsChanged => {
                self.waiting = false;
                Flow::Continue
            }
            SupCmd::Quarantine { epoch, reason } => {
                self.quarantine_orphan(epoch, reason);
                Flow::Continue
            }
            SupCmd::Cut { reply } => self.on_cut(reply).await,
            SupCmd::Query { kind, reply } => {
                let session = match &self.phase {
                    Phase::Live(l) if l.basic => l.session.clone(),
                    _ => None,
                };
                match session {
                    None => {
                        let _ = reply.send(Err(unavailable(&self.id)));
                    }
                    Some(session) => {
                        let id = self.id.clone();
                        let clock = self.ctx.deps.clock.clone();
                        tokio::spawn(async move {
                            let r = session.query(kind).await.map_err(|e| {
                                error(ErrorCode::ManagementUnavailable, e.to_string(), id.as_str())
                            });
                            let r = r.map(|mut q| {
                                if q.at_unix_ms == 0 {
                                    q.at_unix_ms = clock.wall_now().as_millisecond();
                                }
                                q
                            });
                            let _ = reply.send(r);
                        });
                    }
                }
                Flow::Continue
            }
            SupCmd::Shutdown { reply } => {
                self.shutdown = Some(reply);
                self.stopping_for_exit = true;
                match std::mem::replace(&mut self.phase, Phase::Idle) {
                    Phase::Live(live) => self.stop_live(live, Then::Exit).await,
                    Phase::Reclaim { epoch, .. } => {
                        self.phase = Phase::Reclaim {
                            epoch,
                            then: Then::Exit,
                            retry_at: None,
                        };
                        Flow::Continue
                    }
                    other => {
                        self.phase = other;
                        Flow::Continue
                    }
                }
            }
        }
    }

    async fn on_desire(
        &mut self,
        desired: Option<Box<DesiredInstance>>,
        launch: Option<Epoch>,
        retry_start: bool,
    ) -> Flow {
        let spec_changed = match (&self.desired, &desired) {
            (Some(old), Some(new)) => match (&old.spec, &new.spec) {
                (Some(a), Some(b)) => !plan::same_kernel_spec(a, b),
                _ => false,
            },
            _ => false,
        };
        self.desired = desired;
        self.waiting = false;
        if retry_start {
            self.policy.reset();
            self.abnormal.clear();
            self.status.restart_attempt = 0;
            self.gave_up = false;
            self.fence_failed = false;
        }
        let running = self.wants_running();
        if !running {
            self.gave_up = false;
        }
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => {
                if let Some(epoch) = launch {
                    return self.try_start(Some(epoch)).await;
                }
                if !running && self.status.state() == InstanceState::GaveUp {
                    self.set_state(InstanceState::Stopped, "");
                }
                Flow::Continue
            }
            Phase::Backoff { until } => {
                if let Some(epoch) = launch {
                    return self.try_start(Some(epoch)).await;
                }
                if running {
                    self.phase = Phase::Backoff { until };
                }
                Flow::Continue
            }
            Phase::Live(live) => {
                let current_spec_changed = match self.desired.as_ref().and_then(|d| d.spec.as_ref())
                {
                    Some(spec) => !plan::same_kernel_spec(spec, &live.inputs.spec),
                    None => spec_changed,
                };
                if self.desired.is_none() {
                    return self.stop_live(live, Then::Exit).await;
                }
                if !running || current_spec_changed {
                    return self.stop_live(live, Then::Settle).await;
                }
                self.phase = Phase::Live(live);
                Flow::Continue
            }
            Phase::Reclaim {
                epoch,
                then,
                retry_at,
            } => {
                let then = if !running || self.desired.is_none() || retry_start {
                    Then::Settle
                } else {
                    then
                };
                self.phase = Phase::Reclaim {
                    epoch,
                    then,
                    retry_at,
                };
                Flow::Continue
            }
            Phase::Quarantined { epoch } => {
                self.phase = Phase::Quarantined { epoch };
                Flow::Continue
            }
            Phase::Cut { epoch } => {
                match epoch {
                    Some(epoch) => {
                        self.enter_reclaim(epoch, Then::Settle, "stop confirmed; reclaiming")
                    }
                    None if !running => self.set_state(InstanceState::Stopped, ""),
                    None => {}
                }
                Flow::Continue
            }
        }
    }

    async fn on_cut(&mut self, reply: Reply<()>) -> Flow {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Live(mut live) => match Self::terminate(live.handle.as_mut(), None).await {
                Ok(exit) => self.cut_after_kill(live.epoch, exit, reply),
                Err(m) => {
                    // The kill was attempted; what is left is quarantined.
                    let _ = reply.send(Ok(()));
                    self.quarantine_uncertain(live.epoch, m).await;
                }
            },
            Phase::Reclaim { epoch, .. } => {
                self.phase = Phase::Cut { epoch: Some(epoch) };
                self.set_state(InstanceState::CutUnconfirmed, "stop could not be recorded");
                let _ = reply.send(Ok(()));
            }
            Phase::Quarantined { epoch } => {
                // Nothing we can verify is running; the quarantine stands.
                self.phase = Phase::Quarantined { epoch };
                let _ = reply.send(Ok(()));
            }
            Phase::Cut { epoch } => {
                self.phase = Phase::Cut { epoch };
                let _ = reply.send(Ok(()));
            }
            Phase::Idle | Phase::Backoff { .. } => {
                self.phase = Phase::Cut { epoch: None };
                self.set_state(InstanceState::CutUnconfirmed, "stop could not be recorded");
                let _ = reply.send(Ok(()));
            }
        }
        Flow::Continue
    }
}

/// Why a live kernel is killed by the supervisor itself.
enum KillFor {
    /// The fence failed its verification at the start: deny-all fallback.
    Fence(String),
    NotReady,
    /// A verified fence missed two re-verifications in a row while the
    /// kernel ran: normal restart policy (a new fence is installed).
    FenceLost(String),
}

/// The log stream of one instance.
pub(crate) fn instance_logs(logs: &LogBook, tail: u32, follow: bool) -> LogStream {
    logs.stream(tail as usize, follow)
}

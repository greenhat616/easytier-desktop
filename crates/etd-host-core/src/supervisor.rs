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
//!   a desired state is committed.
use crate::api::{ClientPresence, LogStream, Reply};
use crate::fence_seq::{self, FenceCheck};
use crate::lifecycle::logs::LogBook;
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
    Exit, ExitCause, ProcessError, ProcessEvent, ProcessHandle, RestartDecision, RestartPolicy,
};
use etd_sysfx::{
    Credential, Effect, EffectKind, EffectState, Epoch, FenceSpec, GenerationOutcome,
    GenerationReport, LaunchInputs, LedgerError, ManagementGuard, ObjectKey, Observation,
    Persistence, StoredGeneration,
};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};

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
    basic: bool,
    session: Option<Arc<dyn CoreSession>>,
    attach_after: Instant,
    poller: Option<Poller>,
    cursor: Option<CoreEventCursor>,
    /// Kernel records still `Planned` (enumerated until they appear).
    pending: Vec<Effect>,
    next_tick: Instant,
}

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
        self.report(Report::Notice(view::notice(
            level,
            code,
            message,
            self.id.as_str(),
        )));
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
        self.status.message = message.into();
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
            text,
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
        let events = match &mut self.phase {
            Phase::Live(l) => l.events.as_mut(),
            _ => None,
        };
        let has_events = events.is_some();
        let recv_events = async move {
            match events {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            ev = recv_events, if has_events => Input::Proc(ev),
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
                };
                self.enter_reclaim(epoch, then, "launch failed");
                Flow::Continue
            }
        }
    }

    fn record_of(stored: &StoredGeneration, pred: impl Fn(EffectKind) -> bool) -> Option<Effect> {
        stored.effects.iter().find(|e| pred(e.kind)).cloned()
    }

    async fn prepare_and_spawn(
        &mut self,
        epoch: Epoch,
        stored: &StoredGeneration,
    ) -> Result<Box<Live>, LaunchFail> {
        let deps = &self.ctx.deps;
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
        // Every kernel object whose creation credential must be read back
        // (lease and expiring records are record-only: never waited on).
        let pending = stored
            .effects
            .iter()
            .filter(|e| {
                !is_host_kind(e.kind)
                    && e.state == EffectState::Planned
                    && !matches!(
                        e.persistence,
                        Persistence::Lease { .. } | Persistence::Expiring { .. }
                    )
            })
            .cloned()
            .collect();
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
            basic: false,
            session: None,
            attach_after: now,
            poller: None,
            cursor: None,
            pending,
            next_tick: now,
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
                    self.status.management = ManagementAccess::Available as i32;
                    self.publish();
                }
                FenceCheck::Failed(m) => return Err(KillFor::Fence(m)),
                FenceCheck::Pending => {}
            }
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
        Ok(())
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
        let mut assigned: Option<String> = None;
        if unnamed && let Ok(found) = deps.observer.interfaces_owned_by(live.pid).await {
            assigned = found.into_iter().next().map(|i| i.name);
        }
        let mut still = Vec::new();
        for e in std::mem::take(&mut live.pending) {
            let obs = match (&e.key, &assigned) {
                (ObjectKey::Interface { name: None, guid }, Some(name)) => {
                    let key = ObjectKey::Interface {
                        name: Some(name.clone()),
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
                (ObjectKey::RoutesVia { interface: None }, Some(name)) => {
                    let key = ObjectKey::RoutesVia {
                        interface: Some(name.clone()),
                    };
                    Some(Observation {
                        credential: None,
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
                Some(o) => {
                    if let Err(err) = deps
                        .ledger
                        .transition(&e.id, EffectState::Applied, Some(o))
                        .await
                    {
                        tracing::warn!(instance = %self.id, error = %err, "record not applied");
                        still.push(e);
                    }
                }
                None => still.push(e),
            }
        }
        live.pending = still;
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

    async fn on_process(&mut self, event: Option<ProcessEvent>) -> Flow {
        let Phase::Live(live) = &self.phase else {
            return Flow::Continue;
        };
        let epoch = live.epoch;
        match event {
            Some(ProcessEvent::Stdout(bytes)) => {
                for line in LogBook::split_lines(&bytes) {
                    self.log(v1::LogSource::CoreStdout, epoch, line);
                }
                Flow::Continue
            }
            Some(ProcessEvent::Stderr(bytes)) => {
                for line in LogBook::split_lines(&bytes) {
                    self.log(v1::LogSource::CoreStderr, epoch, line);
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
                self.phase = Phase::Idle;
                self.quarantine_uncertain(epoch, reason).await;
                Flow::Continue
            }
            Some(_) => Flow::Continue,
            None => {
                let Phase::Live(mut live) = std::mem::replace(&mut self.phase, Phase::Idle) else {
                    unreachable!()
                };
                live.events = None;
                let exit = live.handle.wait().await;
                self.exited(live, exit, None);
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
        if let Some(rx) = live.events.as_mut() {
            while let Ok(ev) = rx.try_recv() {
                let (source, bytes) = match ev {
                    ProcessEvent::Stdout(b) => (v1::LogSource::CoreStdout, b),
                    ProcessEvent::Stderr(b) => (v1::LogSource::CoreStderr, b),
                    _ => continue,
                };
                for line in LogBook::split_lines(&bytes) {
                    self.log(source, live.epoch, line);
                }
            }
        }
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
        };
        let failed = matches!(why, KillFor::NotReady);
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
    Fence(String),
    NotReady,
}

/// The log stream of one instance.
pub(crate) fn instance_logs(logs: &LogBook, tail: u32, follow: bool) -> LogStream {
    logs.stream(tail as usize, follow)
}

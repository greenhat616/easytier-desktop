//! Instance state machine (basic / full readiness, backoff, gave up,
//! quarantine, cut-unconfirmed) and the orchestrator loop behind
//! [`crate::api::OrchestratorPort`]. Owned by H1.
//!
//! One actor owns the published state ([`view::Publisher`]): it runs the
//! startup self-check ([`crate::boot`]), answers H2's commands in order,
//! executes accepted tickets, and starts one supervisor task
//! ([`crate::supervisor`]) per instance. Supervisors report back over a
//! channel; only the actor publishes, so event sequence numbers stay
//! gap-free.
//!
//! Tickets are executed per instance as one message carrying the committed
//! desired state *as it is now* (never the ticket's own copy) and the
//! generation the ticket reserved, so a replayed ticket never revives a
//! receipted stop or an older configuration.
pub(crate) mod logs;
pub mod machine;
pub(crate) mod plan;
pub mod view;

use crate::api::{ClientPresence, Command, HostDeps, OrchestratorPort, Planned, Reply};
use crate::boot::{self, BootOutcome};
use crate::core_store::CoreSelector;
use crate::supervisor::{Initial, Report, SupCmd, Supervisor};
use etd_contract::v1::LeaseRelease;
use etd_contract::{
    DesiredInstance, ErrorCode, ErrorDetail, HostMode, HostPhase, InstanceId, InstanceState,
    InstanceStatus, LogLine, NetworkSpec,
};
use etd_sysfx::{Change, ClaimSource, LedgerError, ReclaimScope, RepairIndex, ScopeFilter, Ticket};
use logs::LogBook;
use plan::{PlanFailure, error, ledger_detail};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use view::Publisher;

/// Timing of the orchestrator. The defaults are the product's; tests
/// shorten them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleConfig {
    /// Graceful stop before the tree kill.
    pub stop_grace: Duration,
    /// Readiness / enumeration / fence check period while starting.
    pub readiness_tick: Duration,
    /// Basic readiness must be reached within this time of the spawn.
    pub start_timeout: Duration,
    /// `CoreSession::wait_ready` deadline per attach attempt.
    pub full_ready_timeout: Duration,
    /// Retry period of a pending reclaim, a ledger outage or a ticket.
    pub reclaim_retry: Duration,
    /// Kernel log lines kept per instance.
    pub log_lines: usize,
    /// Session-form host: how long no client may hold a lease before the
    /// host stops its instances and exits.
    pub lease_grace: Duration,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            stop_grace: Duration::from_secs(10),
            readiness_tick: Duration::from_millis(250),
            start_timeout: Duration::from_secs(60),
            full_ready_timeout: Duration::from_secs(10),
            reclaim_retry: Duration::from_secs(2),
            log_lines: 1000,
            lease_grace: Duration::from_secs(30),
        }
    }
}

/// Shared by the actor and every supervisor.
pub(crate) struct Ctx {
    pub deps: Arc<HostDeps>,
    pub config: LifecycleConfig,
    /// Set while the self-check's kernel sweep has not succeeded: no
    /// instance starts (the reason is shown while waiting).
    pub hold: std::sync::Mutex<Option<String>>,
}

impl Ctx {
    pub(crate) fn held(&self) -> Option<String> {
        self.hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set_hold(&self, hold: Option<String>) {
        *self
            .hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hold;
    }
}

/// Why [`Orchestrator::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunOutcome {
    /// `Command::Shutdown` was answered.
    Shutdown,
    /// Session-form host: the last lease was released with its instances
    /// stopped.
    LeaseReleased,
    /// H2 dropped its handle; instances were stopped and reclaimed.
    Closed,
}

/// The lifecycle orchestrator (H1's side of the frozen handle).
pub struct Orchestrator {
    ctx: Arc<Ctx>,
    port: OrchestratorPort,
}

impl Orchestrator {
    pub fn new(deps: Arc<HostDeps>, port: OrchestratorPort) -> Self {
        Self::with_config(deps, port, LifecycleConfig::default())
    }

    pub fn with_config(
        deps: Arc<HostDeps>,
        port: OrchestratorPort,
        config: LifecycleConfig,
    ) -> Self {
        Self {
            ctx: Arc::new(Ctx {
                deps,
                config,
                hold: std::sync::Mutex::new(None),
            }),
            port,
        }
    }

    /// Self-check, then serve until shut down.
    pub async fn run(self) -> RunOutcome {
        let OrchestratorPort {
            commands,
            events,
            view,
        } = self.port;
        let (reports_tx, reports_rx) = mpsc::unbounded_channel();
        let (presence, _) = watch::channel(ClientPresence::default());
        let mut actor = Actor {
            ctx: self.ctx.clone(),
            commands,
            commands_closed: false,
            publisher: Publisher::new(events, view),
            supervisors: BTreeMap::new(),
            logbooks: BTreeMap::new(),
            statuses: BTreeMap::new(),
            reports_tx,
            reports_rx,
            presence,
            host_logs: Arc::new(LogBook::new(self.ctx.config.log_lines)),
            phase: HostPhase::SelfCheck,
            tickets_due: None,
            resweep_due: None,
            lease_deadline: None,
            purge: None,
            ending: None,
            shutdown_replies: Vec::new(),
        };
        actor.run().await
    }
}

struct SupHandle {
    tx: mpsc::UnboundedSender<SupCmd>,
}

/// What ends the actor once every supervisor is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Shutdown,
    Lease,
    Closed,
}

struct Actor {
    ctx: Arc<Ctx>,
    commands: mpsc::Receiver<Command>,
    commands_closed: bool,
    publisher: Publisher,
    supervisors: BTreeMap<InstanceId, SupHandle>,
    /// Kept after a supervisor ends so `StreamLogs` still has its lines.
    logbooks: BTreeMap<InstanceId, Arc<LogBook>>,
    /// Latest status of every supervised instance.
    statuses: BTreeMap<InstanceId, InstanceStatus>,
    reports_tx: mpsc::UnboundedSender<Report>,
    reports_rx: mpsc::UnboundedReceiver<Report>,
    presence: watch::Sender<ClientPresence>,
    host_logs: Arc<LogBook>,
    phase: HostPhase,
    /// Pending tickets are executed again at this time (ledger outage).
    tickets_due: Option<Instant>,
    /// The self-check's kernel sweep is retried at this time.
    resweep_due: Option<Instant>,
    /// Session-form host: no lease since; the host winds down at this time.
    lease_deadline: Option<Instant>,
    /// A PurgeAll ticket waits for every supervisor to end.
    purge: Option<String>,
    ending: Option<Ending>,
    shutdown_replies: Vec<oneshot::Sender<()>>,
}

fn not_serving(instance: &str) -> ErrorDetail {
    error(
        ErrorCode::HostNotServing,
        "the host is not serving (self-check, diagnose-only or shutting down)",
        instance,
    )
}

impl Actor {
    fn now_ms(&self) -> i64 {
        self.ctx.deps.clock.wall_now().as_millisecond()
    }

    fn host_log(&self, text: String) {
        self.host_logs.push(LogLine {
            at_unix_ms: self.now_ms(),
            source: etd_contract::v1::LogSource::Host as i32,
            text,
            instance_id: String::new(),
            epoch: 0,
        });
    }

    fn set_phase(&mut self, phase: HostPhase) {
        self.phase = phase;
        let at = self.now_ms();
        self.publisher.phase(at, phase);
    }

    async fn run(&mut self) -> RunOutcome {
        self.set_phase(HostPhase::SelfCheck);
        let outcome = {
            let boot = boot::self_check(self.ctx.clone());
            tokio::pin!(boot);
            loop {
                tokio::select! {
                    biased;
                    out = &mut boot => break out,
                    cmd = self.commands.recv(), if !self.commands_closed => match cmd {
                        Some(cmd) => self.on_command_not_serving(cmd),
                        None => self.commands_closed = true,
                    },
                }
            }
        };
        self.after_boot(outcome).await;
        if self.commands_closed && self.ending.is_none() {
            self.begin_ending(Ending::Closed);
        }
        loop {
            if let Some(end) = self.ending
                && self.supervisors.is_empty()
            {
                return self.finish(end).await;
            }
            let clock = self.ctx.deps.clock.clone();
            let until = |at: Option<Instant>| match at {
                Some(at) => clock.sleep(at.saturating_duration_since(clock.now())),
                None => Box::pin(std::future::pending()),
            };
            let ticket_sleep = until(self.tickets_due);
            let resweep_sleep = until(self.resweep_due);
            let lease_sleep = until(self.lease_deadline);
            tokio::select! {
                biased;
                report = self.reports_rx.recv() => {
                    if let Some(report) = report {
                        self.on_report(report).await;
                    }
                }
                cmd = self.commands.recv(), if !self.commands_closed => match cmd {
                    Some(cmd) => self.on_command(cmd).await,
                    None => {
                        self.commands_closed = true;
                        if self.ending.is_none() {
                            self.begin_ending(Ending::Closed);
                        }
                    }
                },
                () = ticket_sleep => {
                    self.tickets_due = None;
                    self.execute_tickets().await;
                }
                () = resweep_sleep => {
                    self.resweep_due = None;
                    self.resweep().await;
                }
                () = lease_sleep => {
                    self.lease_deadline = None;
                    self.host_log("no client holds a lease: stopping instances and exiting".into());
                    self.begin_ending(Ending::Lease);
                }
            }
        }
    }

    // ----- self-check -------------------------------------------------------

    async fn after_boot(&mut self, outcome: BootOutcome) {
        for line in &outcome.log {
            self.host_log(line.clone());
        }
        if let Some(report) = &outcome.report {
            let at = self.now_ms();
            self.publisher.reclaim(at, view::reclaim_report(report));
        }
        if outcome.diagnostic {
            self.set_phase(HostPhase::DiagnosticOnly);
            return;
        }
        self.publisher
            .seed_desired(outcome.revision, outcome.desired.clone());
        self.refresh_default_core().await;
        self.store_repair_index(&outcome.desired);
        if let Some(why) = outcome.hold_starts {
            self.ctx.set_hold(Some(why));
            self.resweep_due = Some(self.ctx.deps.clock.now() + self.ctx.config.reclaim_retry);
        }
        let mut initial = outcome.initial;
        for desired in outcome.desired {
            let id = InstanceId(desired.instance_id.clone());
            let init = initial.remove(&id).unwrap_or(Initial::Idle);
            self.spawn_supervisor(id, Box::new(desired), init, None);
        }

        self.set_phase(HostPhase::Serving);
        let at = self.now_ms();
        for notice in outcome.notices {
            self.publisher.notice(at, notice);
        }
        self.presence_changed();
        self.execute_tickets().await;
    }

    /// The self-check's sweep failed: try it again; once it succeeds the
    /// held starts go ahead.
    async fn resweep(&mut self) {
        match boot::resweep(&self.ctx).await {
            Ok(done) => {
                for line in done.log {
                    self.host_log(line);
                }
                let at = self.now_ms();
                for notice in done.notices {
                    self.publisher.notice(at, notice);
                }
                if let Some(report) = &done.report {
                    self.publisher.reclaim(at, view::reclaim_report(report));
                }
                for (instance, (epoch, reason)) in done.quarantined {
                    if let Some(s) = self.supervisors.get(&instance) {
                        let _ = s.tx.send(SupCmd::Quarantine { epoch, reason });
                    }
                }
                self.ctx.set_hold(None);
                self.publisher.notice(
                    at,
                    view::notice(
                        etd_contract::v1::NoticeLevel::Info,
                        "selfcheck.complete",
                        "the kernel sweep succeeded; reclaim and starts go ahead",
                        "",
                    ),
                );
                for s in self.supervisors.values() {
                    let _ = s.tx.send(SupCmd::ClaimsChanged);
                }
            }
            Err(why) => {
                self.host_log(format!("kernel sweep retry failed: {why}"));
                self.resweep_due = Some(self.ctx.deps.clock.now() + self.ctx.config.reclaim_retry);
            }
        }
    }

    /// Session-form host lifetime: the grace period runs while no client
    /// holds a lease; the service form ignores leases.
    fn presence_changed(&mut self) {
        let session = matches!(
            self.ctx.deps.mode,
            HostMode::ElevatedSession | HostMode::User
        );
        if !session || self.phase != HostPhase::Serving {
            self.lease_deadline = None;
            return;
        }
        if self.presence.borrow().lease_holders > 0 {
            self.lease_deadline = None;
        } else if self.lease_deadline.is_none() {
            self.lease_deadline = Some(self.ctx.deps.clock.now() + self.ctx.config.lease_grace);
        }
    }

    fn store_repair_index(&self, desired: &[DesiredInstance]) {
        let index = RepairIndex {
            install_key: self.ctx.deps.install_key.clone(),
            instances: desired
                .iter()
                .map(|d| InstanceId(d.instance_id.clone()))
                .collect(),
        };
        if let Err(e) = self.ctx.deps.repair_index.store(&index) {
            tracing::warn!(error = %e, "repair index not stored");
        }
    }

    async fn refresh_default_core(&mut self) {
        let selected = match self.ctx.deps.ledger.settings().await {
            Ok(s) => s.selected_core,
            Err(_) => return,
        };
        let version = match self
            .ctx
            .deps
            .core_store
            .resolve(&CoreSelector { version: selected })
            .await
        {
            Ok(core) => core.descriptor.version,
            Err(_) => String::new(),
        };
        self.publisher.default_core(version);
    }

    /// `first` is handled before the supervisor drives toward its desired
    /// state (a ticket's committed generation, so it does not reserve one
    /// of its own first).
    fn spawn_supervisor(
        &mut self,
        id: InstanceId,
        desired: Box<DesiredInstance>,
        init: Initial,
        first: Option<SupCmd>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(cmd) = first {
            let _ = tx.send(cmd);
        }
        let logs = self
            .logbooks
            .entry(id.clone())
            .or_insert_with(|| Arc::new(LogBook::new(self.ctx.config.log_lines)))
            .clone();
        let sup = Supervisor::new(
            self.ctx.clone(),
            id.clone(),
            desired,
            init,
            rx,
            self.reports_tx.clone(),
            self.presence.subscribe(),
            logs,
        );
        tokio::spawn(sup.run());
        self.supervisors.insert(id, SupHandle { tx });
    }

    fn send(&self, id: &InstanceId, cmd: SupCmd) -> bool {
        self.supervisors
            .get(id)
            .is_some_and(|s| s.tx.send(cmd).is_ok())
    }

    // ----- supervisor reports --------------------------------------------

    async fn on_report(&mut self, report: Report) {
        let at = self.now_ms();
        match report {
            Report::Status(status) => {
                let id = InstanceId(status.instance_id.clone());
                if self.supervisors.contains_key(&id) {
                    self.statuses.insert(id, status.clone());
                }
                self.publisher.status(at, status);
            }
            Report::Exited(exited) => self.publisher.exited(at, exited),
            Report::Notice(notice) => {
                self.host_log(format!(
                    "[{}] {}: {}",
                    notice.instance_id, notice.code, notice.message
                ));
                self.publisher.notice(at, notice);
            }
            Report::Reclaimed(g) => {
                let mut report = self
                    .publisher
                    .snapshot()
                    .reclaim
                    .clone()
                    .unwrap_or_default();
                view::merge_generation(&mut report, &g, at);
                self.publisher.reclaim(at, report);
                if g.outcome == etd_sysfx::GenerationOutcome::Closed {
                    // A closed generation may release a single-writer claim.
                    for (id, s) in &self.supervisors {
                        if *id != g.instance {
                            let _ = s.tx.send(SupCmd::ClaimsChanged);
                        }
                    }
                }
            }
            Report::Gone(id) => {
                self.supervisors.remove(&id);
                self.statuses.remove(&id);
                self.instance_gone(&id).await;
                if self.supervisors.is_empty()
                    && let Some(ticket) = self.purge.take()
                {
                    self.finish_purge(ticket).await;
                }
            }
        }
    }

    /// A supervisor ended: publish the removal once the ledger dropped the
    /// configuration (after its last generation closed).
    async fn instance_gone(&mut self, id: &InstanceId) {
        if self.ending.is_some() {
            return;
        }
        match self.ctx.deps.ledger.desired().await {
            Ok((revision, desired)) => {
                if desired.iter().all(|d| d.instance_id != id.0) {
                    let at = self.now_ms();
                    self.publisher.removed(at, id.to_string(), revision);
                    self.store_repair_index(&desired);
                } else if let Some(d) = desired.into_iter().find(|d| d.instance_id == id.0) {
                    // Still configured (removal pending behind a
                    // quarantine, or the task ended early): supervise again.
                    let init = self.initial_for(id, None).await;
                    self.spawn_supervisor(id.clone(), Box::new(d), init, None);
                }
            }
            Err(e) => self.host_log(format!("instance {id} ended; ledger unavailable: {e}")),
        }
    }

    /// How a new supervisor starts: from the ledger's open records, except
    /// those of the committed generation it is about to launch.
    async fn initial_for(&self, id: &InstanceId, launch: Option<etd_sysfx::Epoch>) -> Initial {
        match self
            .ctx
            .deps
            .ledger
            .open_effects(&ScopeFilter::instance(id.clone()))
            .await
        {
            Ok(mut open) => {
                open.retain(|e| {
                    e.scope
                        .generation()
                        .is_none_or(|(_, ep)| Some(ep) != launch)
                });
                boot::initial_from_open(&open, None)
            }
            Err(_) => Initial::Idle,
        }
    }

    // ----- commands -------------------------------------------------------

    /// During the self-check (and after it in diagnose-only mode): only
    /// presence and logs are served.
    fn on_command_not_serving(&mut self, cmd: Command) {
        match cmd {
            Command::Plan {
                instance, reply, ..
            } => {
                let _ = reply.send(Err(not_serving(instance.as_str())));
            }
            Command::Committed { .. } => {} // replayed from the ledger later
            Command::Cut { instance, reply } => {
                let _ = reply.send(Err(not_serving(instance.as_str())));
            }
            Command::Query {
                instance, reply, ..
            } => {
                let _ = reply.send(Err(not_serving(instance.as_str())));
            }
            Command::Logs { request, reply } => self.on_logs(request, reply),
            Command::Clients(p) => {
                self.presence.send_replace(p);
            }
            Command::ReleaseLease { reply, .. } => {
                let _ = reply.send(Err(not_serving("")));
            }
            Command::Shutdown { reply } => {
                self.shutdown_replies.push(reply);
                if self.ending.is_none() {
                    self.ending = Some(Ending::Shutdown);
                }
            }
        }
    }

    async fn on_command(&mut self, cmd: Command) {
        if self.phase != HostPhase::Serving {
            return self.on_command_not_serving(cmd);
        }
        match cmd {
            Command::Plan {
                instance,
                spec,
                start,
                reply,
            } => {
                let result = self.on_plan(&instance, spec, start).await;
                let _ = reply.send(result);
            }
            Command::Committed { receipt } => {
                tracing::debug!(ticket = %receipt.ticket, "committed");
                self.execute_tickets().await;
            }
            Command::Cut { instance, reply } => {
                if let Some(s) = self.supervisors.get(&instance) {
                    if let Err(mpsc::error::SendError(SupCmd::Cut { reply })) =
                        s.tx.send(SupCmd::Cut { reply })
                    {
                        let _ = reply.send(Err(not_serving(instance.as_str())));
                    }
                } else {
                    let _ = reply.send(Err(unknown(&instance)));
                }
            }
            Command::Query {
                instance,
                kind,
                reply,
            } => {
                if let Some(s) = self.supervisors.get(&instance) {
                    if let Err(mpsc::error::SendError(SupCmd::Query { reply, .. })) =
                        s.tx.send(SupCmd::Query { kind, reply })
                    {
                        let _ = reply.send(Err(not_serving(instance.as_str())));
                    }
                } else {
                    let _ = reply.send(Err(unknown(&instance)));
                }
            }
            Command::Logs { request, reply } => self.on_logs(request, reply),
            Command::Clients(p) => {
                self.presence.send_replace(p);
                self.presence_changed();
            }
            Command::ReleaseLease { instances, reply } => {
                self.on_release_lease(instances, reply);
            }
            Command::Shutdown { reply } => {
                self.shutdown_replies.push(reply);
                self.begin_ending(Ending::Shutdown);
            }
        }
    }

    fn on_logs(
        &self,
        request: etd_contract::v1::StreamLogsRequest,
        reply: Reply<crate::api::LogStream>,
    ) {
        if request.instance_id.is_empty() {
            let _ = reply.send(Ok(self
                .host_logs
                .stream(request.tail_lines as usize, request.follow)));
            return;
        }
        let id = InstanceId(request.instance_id.clone());
        match self.logbooks.get(&id) {
            Some(book) => {
                let _ = reply.send(Ok(crate::supervisor::instance_logs(
                    book,
                    request.tail_lines,
                    request.follow,
                )));
            }
            None => {
                let _ = reply.send(Err(unknown(&id)));
            }
        }
    }

    /// Service hosts never exit on a lease. A session-form host whose
    /// lease comes back with "stop instances" stops them (desired state
    /// unchanged), reclaims and exits; "keep instances" keeps it running.
    fn on_release_lease(&mut self, instances: LeaseRelease, reply: Reply<bool>) {
        let session = matches!(
            self.ctx.deps.mode,
            HostMode::ElevatedSession | HostMode::User
        );
        let stop = instances == LeaseRelease::StopInstances;
        if session && stop {
            let _ = reply.send(Ok(true));
            self.begin_ending(Ending::Lease);
        } else {
            let _ = reply.send(Ok(false));
        }
    }

    fn begin_ending(&mut self, end: Ending) {
        if self.ending.is_none() {
            self.ending = Some(end);
        }
        if self.phase != HostPhase::ShuttingDown {
            self.set_phase(HostPhase::ShuttingDown);
        }
        for s in self.supervisors.values() {
            let (tx, _) = oneshot::channel();
            let _ = s.tx.send(SupCmd::Shutdown { reply: tx });
        }
    }

    async fn finish(&mut self, end: Ending) -> RunOutcome {
        if self.phase != HostPhase::ShuttingDown {
            self.set_phase(HostPhase::ShuttingDown);
        }
        for reply in self.shutdown_replies.drain(..) {
            let _ = reply.send(());
        }
        match end {
            Ending::Shutdown => RunOutcome::Shutdown,
            Ending::Lease => RunOutcome::LeaseReleased,
            Ending::Closed => RunOutcome::Closed,
        }
    }

    // ----- planning -------------------------------------------------------

    async fn on_plan(
        &mut self,
        instance: &InstanceId,
        spec: Option<Box<NetworkSpec>>,
        start: bool,
    ) -> Result<Planned, ErrorDetail> {
        let ledger = self.ctx.deps.ledger.clone();
        let (revision, desired) = ledger
            .desired()
            .await
            .map_err(|e| ledger_detail(&e, instance))?;
        let current = desired.iter().find(|d| d.instance_id == instance.0);
        let (spec, spec_revision) = match spec {
            // PutInstance: the commit's own revision.
            Some(new) => (
                plan::merge_secret(*new, current.and_then(|c| c.spec.as_ref())),
                revision.checked_add(1).ok_or_else(|| {
                    ledger_detail(&LedgerError::CounterExhausted("revision"), instance)
                })?,
            ),
            None => {
                let current = current.ok_or_else(|| unknown(instance))?;
                let spec = current.spec.clone().ok_or_else(|| {
                    error(
                        ErrorCode::InvalidSpec,
                        "the instance has no configuration",
                        instance.as_str(),
                    )
                })?;
                let rev = ledger
                    .spec_revision(instance)
                    .await
                    .map_err(|e| ledger_detail(&e, instance))?;
                (spec, rev)
            }
        };
        let epoch = ledger
            .next_epoch(instance)
            .await
            .map_err(|e| ledger_detail(&e, instance))?;
        let planned =
            match plan::plan_generation(&self.ctx, instance, &spec, spec_revision, epoch, false)
                .await
            {
                Ok(p) => p,
                // A stopped configuration may be saved without a usable kernel.
                Err(PlanFailure::Store(_) | PlanFailure::Port(_)) if !start => {
                    return Ok(Planned {
                        claims: Vec::new(),
                        generation: None,
                        revision,
                    });
                }
                Err(f) => return Err(f.detail(instance)),
            };
        let claims = planned.generation.claims.clone();
        if !start {
            return Ok(Planned {
                claims,
                generation: None,
                revision,
            });
        }
        let holds = ledger
            .claims()
            .await
            .map_err(|e| ledger_detail(&e, instance))?;
        if let Some(h) = holds.iter().find(|h| {
            h.instance != *instance
                && claims.contains(&h.resource)
                && h.source == ClaimSource::Desired
        }) {
            let mut d = error(
                ErrorCode::SingleWriterTaken,
                format!("{} is already used by instance {}", h.resource, h.instance),
                instance.as_str(),
            );
            d.features = vec![h.resource.clone()];
            return Err(d);
        }
        let held = holds
            .iter()
            .any(|h| h.instance != *instance && claims.contains(&h.resource));
        let idle = self.idle(instance).await?;
        Ok(Planned {
            claims,
            generation: (idle && !held).then_some(planned.generation),
            revision,
        })
    }

    /// No live, starting or open generation: a committed start may carry
    /// its own generation.
    async fn idle(&self, instance: &InstanceId) -> Result<bool, ErrorDetail> {
        let state_idle = match self.statuses.get(instance) {
            None => !self.supervisors.contains_key(instance),
            Some(s) => matches!(s.state(), InstanceState::Stopped | InstanceState::GaveUp),
        };
        if !state_idle {
            return Ok(false);
        }
        let open = self
            .ctx
            .deps
            .ledger
            .open_effects(&ScopeFilter::instance(instance.clone()))
            .await
            .map_err(|e| ledger_detail(&e, instance))?;
        Ok(open.is_empty())
    }

    // ----- tickets ----------------------------------------------------------

    fn retry_tickets(&mut self) {
        let at = self.ctx.deps.clock.now() + self.ctx.config.reclaim_retry;
        self.tickets_due = Some(self.tickets_due.map_or(at, |t| t.min(at)));
    }

    /// Execute every accepted ticket, oldest first.
    async fn execute_tickets(&mut self) {
        if self.phase != HostPhase::Serving {
            return;
        }
        let ledger = self.ctx.deps.ledger.clone();
        let tickets = match ledger.pending_tickets().await {
            Ok(t) => t,
            Err(e) => {
                self.host_log(format!("tickets not readable: {e}"));
                return self.retry_tickets();
            }
        };
        for ticket in tickets {
            if self.purge.as_deref() == Some(ticket.receipt.ticket.as_str()) {
                continue;
            }
            match self.execute(&ticket).await {
                Ok(true) => match ledger.complete_ticket(&ticket.receipt.ticket).await {
                    Ok(()) | Err(LedgerError::UnknownTicket(_)) => {}
                    Err(e) => {
                        self.host_log(format!(
                            "ticket {} not completed: {e}",
                            ticket.receipt.ticket
                        ));
                        self.retry_tickets();
                    }
                },
                Ok(false) => {} // completed later (purge)
                Err(e) => {
                    self.host_log(format!("ticket {} deferred: {e}", ticket.receipt.ticket));
                    return self.retry_tickets();
                }
            }
        }
    }

    /// `Ok(true)`: the ticket is done.
    async fn execute(&mut self, ticket: &Ticket) -> Result<bool, LedgerError> {
        let ledger = self.ctx.deps.ledger.clone();
        let (revision, desired) = ledger.desired().await?;
        let at = self.now_ms();
        let launch: BTreeMap<InstanceId, etd_sysfx::Epoch> =
            ticket.generations.iter().cloned().collect();
        let mut touched: Vec<(InstanceId, bool)> = Vec::new();
        let mut purge = false;
        let mut instances_changed = false;
        for change in &ticket.changes {
            match change {
                Change::PutInstance { instance, .. } => {
                    instances_changed = true;
                    touched.push((InstanceId(instance.instance_id.clone()), false));
                }
                Change::SetDesired { instance, .. } => touched.push((instance.clone(), false)),
                Change::RetryStart(instance) => touched.push((instance.clone(), true)),
                Change::RemoveInstance(instance) => {
                    instances_changed = true;
                    touched.push((instance.clone(), false));
                }
                Change::RetryReclaim(instance) => {
                    self.send(instance, SupCmd::RetryReclaim);
                }
                Change::ResolveCandidates(decisions) => {
                    match self.ctx.deps.reclaim.resolve(decisions).await {
                        Ok(report) => {
                            let at = self.now_ms();
                            self.publisher.reclaim(at, view::reclaim_report(&report));
                        }
                        Err(e) => return Err(e),
                    }
                    for s in self.supervisors.values() {
                        let _ = s.tx.send(SupCmd::Recheck);
                    }
                }
                Change::SelectCore(_) => self.refresh_default_core().await,
                Change::PurgeAll => {
                    purge = true;
                    instances_changed = true;
                    for id in self.supervisors.keys() {
                        touched.push((id.clone(), false));
                    }
                }
                _ => {}
            }
        }
        let removing: BTreeSet<InstanceId> = ticket
            .changes
            .iter()
            .filter_map(|c| match c {
                Change::RemoveInstance(id) => Some(id.clone()),
                _ => None,
            })
            .collect();
        let mut seen = BTreeSet::new();
        for (id, retry_start) in touched {
            let current = desired.iter().find(|d| d.instance_id == id.0).cloned();
            let retry_start = retry_start
                || ticket
                    .changes
                    .iter()
                    .any(|c| matches!(c, Change::RetryStart(i) if *i == id));
            if !seen.insert(id.clone()) {
                continue;
            }
            // A removal (or purge) stops and reclaims; the configuration
            // goes once the last generation is closed.
            let keep = !(purge || removing.contains(&id));
            let wanted = current.clone().filter(|_| keep).map(Box::new);
            if let Some(d) = &current
                && keep
            {
                self.publisher.desired(
                    at,
                    revision,
                    view::redact(d.clone()),
                    ticket.receipt.request_id.clone(),
                    ticket.receipt.ticket.clone(),
                );
            }
            let epoch = launch.get(&id).copied();
            if self.supervisors.contains_key(&id) {
                self.send(
                    &id,
                    SupCmd::Desire {
                        desired: wanted,
                        launch: epoch,
                        retry_start,
                    },
                );
            } else if let Some(d) = wanted {
                let init = self.initial_for(&id, epoch).await;
                let first = SupCmd::Desire {
                    desired: Some(d.clone()),
                    launch: epoch,
                    retry_start,
                };
                self.spawn_supervisor(id.clone(), d, init, Some(first));
            } else if current.is_none() {
                self.publisher.removed(at, id.to_string(), revision);
            }
        }
        if instances_changed {
            self.store_repair_index(&desired);
        }
        if purge {
            self.purge = Some(ticket.receipt.ticket.clone());
            if self.supervisors.is_empty() {
                let ticket = self.purge.take().unwrap_or_default();
                self.finish_purge(ticket).await;
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// Every instance is gone: reclaim product and kernel-binary records
    /// too, then complete the purge ticket (refused while a removal is
    /// still pending behind an open generation).
    async fn finish_purge(&mut self, ticket: String) {
        match self
            .ctx
            .deps
            .reclaim
            .reclaim_all(ReclaimScope::Everything)
            .await
        {
            Ok(report) => {
                let at = self.now_ms();
                self.publisher.reclaim(at, view::reclaim_report(&report));
            }
            Err(e) => self.host_log(format!("purge reclaim failed: {e}")),
        }
        if let Err(e) = self.ctx.deps.ledger.complete_ticket(&ticket).await {
            self.host_log(format!("purge ticket {ticket} not completed: {e}"));
            self.retry_tickets();
        }
    }
}

fn unknown(instance: &InstanceId) -> ErrorDetail {
    error(
        ErrorCode::UnknownInstance,
        format!("unknown instance {instance}"),
        instance.as_str(),
    )
}

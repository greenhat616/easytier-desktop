//! Channel bridge between the gpui main thread and the background tokio
//! runtime; no task is shared between executors. Owned by A1.
//!
//! [`AppRuntime::start`] runs a tokio runtime on its own threads. The UI
//! sends [`UserCommand`]s and receives the latest [`StateStore`]; both ends
//! are `async-channel`s, so they work on any executor. Exit goes through the
//! [`crate::ExitGate`], which drives the runtime's [`ExitSteps`].
//!
//! All state lives in one actor that never waits on the host: every host
//! call runs in its own task and reports back as a message.
//!
//! Mutations are sent one at a time, each expecting the revision the store
//! shows when it is sent. A revision conflict is reported, never resolved by
//! resending with a newer revision. A request whose reply is lost is looked
//! up by its id and only ever resent unchanged, so it takes effect at most
//! once.
use crate::{
    AppServices, ExitSteps, Failure, HostLink, HostTarget, LaunchError, LaunchFailure, Operation,
    OperationKind, OperationStatus, Profile, SecretInput, StateStore, SyncState, WatchedInstance,
    new_instance_id,
    reducer::{self, Reduced},
    scrub_secret,
};
use etd_client::{CallError, ConnectionState, HostClient, new_request_id};
use etd_contract::v1::{
    ApplyRequest, LeaseRelease, MutationHeader, RemoveInstanceRequest, ResolveCandidatesRequest,
    RetryReclaimRequest, RetryStartRequest, SetDesiredRequest, query_response,
};
use etd_contract::{
    CandidateDecision, Desired, ErrorCode, Event, HostMode, HostSnapshot, InstanceId, NetworkSpec,
    QueryKind, QueryResponse, Receipt, RequestId, Revision,
};
use futures_util::StreamExt;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::{AbortHandle, JoinHandle as TaskHandle},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

/// A spec that cannot carry a secret: construction removes it. A secret
/// only travels as [`SecretInput`].
#[derive(Debug, Clone, PartialEq)]
pub struct SecretFreeSpec(Box<NetworkSpec>);

impl SecretFreeSpec {
    pub fn new(mut spec: NetworkSpec) -> Self {
        scrub_secret(&mut spec);
        spec.network_secret_set = false;
        Self(Box::new(spec))
    }

    pub fn get(&self) -> &NetworkSpec {
        &self.0
    }
}

/// Create or replace an instance configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplyDraft {
    /// [`new_instance_id`] for a new configuration.
    pub instance_id: InstanceId,
    pub spec: SecretFreeSpec,
    /// The user's choice; asked on every create and edit.
    pub secret: SecretInput,
    /// `Unspecified` keeps the current desired state.
    pub desired: Desired,
}

impl ApplyDraft {
    /// A new, stopped instance.
    pub fn create(spec: NetworkSpec, secret: SecretInput) -> Self {
        Self {
            instance_id: new_instance_id(),
            spec: SecretFreeSpec::new(spec),
            secret,
            desired: Desired::Unspecified,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UserCommand {
    /// Connect to whatever host is installed or running; starts nothing.
    AutoConnect,
    /// Find or start a host of this form and connect to it.
    Connect(HostMode),
    /// Take a new snapshot.
    Refresh,
    /// Also saves the configuration, without its secret, to the profiles.
    Apply(Box<ApplyDraft>),
    SetDesired {
        instance: InstanceId,
        desired: Desired,
    },
    /// "Retry confirm" of an instance shown as cut, unconfirmed.
    RetryConfirmStop(InstanceId),
    Remove {
        instance: InstanceId,
        /// Delete the saved profile once the host accepted the removal.
        forget_profile: bool,
    },
    RetryStart(InstanceId),
    RetryReclaim(InstanceId),
    ResolveCandidates(Vec<CandidateDecision>),
    /// Resend an unconfirmed operation unchanged.
    RetryOperation(RequestId),
    /// Drop an operation that is not in progress from the list.
    DismissOperation(RequestId),
    /// Poll the management pages of one instance (`None`: stop).
    Watch(Option<InstanceId>),
    SaveProfile {
        instance_id: InstanceId,
        spec: SecretFreeSpec,
    },
    DeleteProfile(InstanceId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeConfig {
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// Safety limit for one host call, above the client's own limits.
    pub call_timeout: Duration,
    /// Receipt lookups before a lost reply is reported as unconfirmed.
    pub recovery_attempts: u32,
    pub query_interval: Duration,
    /// Reconnect attempt from which a vanished user host is started again.
    pub relaunch_after: u32,
    /// At exit: wait for pending requests and profile writes.
    pub drain_timeout: Duration,
    /// At exit: wait for the lease to be handed back.
    pub release_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            retry_min: Duration::from_millis(200),
            retry_max: Duration::from_secs(5),
            call_timeout: Duration::from_secs(60),
            recovery_attempts: 5,
            query_interval: Duration::from_secs(1),
            relaunch_after: 2,
            drain_timeout: Duration::from_secs(1),
            release_timeout: Duration::from_millis(1200),
            shutdown_timeout: Duration::from_secs(1),
        }
    }
}

/// The UI's ends of the bridge.
#[derive(Debug, Clone)]
pub struct AppBridge {
    pub commands: async_channel::Sender<UserCommand>,
    /// Holds at most one value: the latest state. A slow reader skips
    /// intermediate ones.
    pub states: async_channel::Receiver<StateStore>,
}

enum Control {
    Settle {
        release: LeaseRelease,
        reply: async_channel::Sender<Result<(), String>>,
    },
    StopSubscriptions {
        reply: async_channel::Sender<Result<(), String>>,
    },
}

/// Owns the background runtime. Dropping it stops the runtime without
/// waiting; a clean exit goes through the [`crate::ExitGate`].
pub struct AppRuntime {
    control: mpsc::UnboundedSender<Control>,
    stop: CancellationToken,
    /// Closes when the runtime thread has finished.
    done: async_channel::Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl AppRuntime {
    pub fn start(services: AppServices, config: BridgeConfig) -> io::Result<(AppBridge, Self)> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("etd-tokio-worker")
            .enable_all()
            .build()?;
        let (command_tx, command_rx) = async_channel::unbounded();
        let (state_tx, state_rx) = async_channel::bounded(1);
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (done_tx, done_rx) = async_channel::bounded::<()>(1);
        let stop = CancellationToken::new();
        let root = stop.clone();
        let thread = thread::Builder::new()
            .name("etd-tokio".into())
            .spawn(move || {
                runtime.block_on(async {
                    let (actor, inbox) = Actor::new(services, config, state_tx, root);
                    actor.run(inbox, command_rx, control_rx).await;
                });
                // Bounded, so that a stuck connection cannot hang the exit.
                runtime.shutdown_timeout(config.shutdown_timeout);
                drop(done_tx);
            })?;
        Ok((
            AppBridge {
                commands: command_tx,
                states: state_rx,
            },
            Self {
                control: control_tx,
                stop,
                done: done_rx,
                thread: Some(thread),
            },
        ))
    }

    async fn ask(
        &self,
        control: impl FnOnce(async_channel::Sender<Result<(), String>>) -> Control,
    ) -> Result<(), String> {
        let gone = || "the background runtime is gone".to_owned();
        let (reply, answer) = async_channel::bounded(1);
        self.control.send(control(reply)).map_err(|_| gone())?;
        answer.recv().await.map_err(|_| gone())?
    }
}

impl ExitSteps for AppRuntime {
    async fn settle_instances(&mut self, release: LeaseRelease) -> Result<(), String> {
        self.ask(|reply| Control::Settle { release, reply }).await
    }

    async fn stop_subscriptions(&mut self) -> Result<(), String> {
        self.ask(|reply| Control::StopSubscriptions { reply }).await
    }

    async fn stop_runtime(&mut self) -> Result<(), String> {
        self.stop.cancel();
        // Never carries a value: it closes as the thread's last act, so the
        // join below does not block the caller.
        let _ = self.done.recv().await;
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| "the background runtime panicked".to_owned()),
            None => Ok(()),
        }
    }
}

impl Drop for AppRuntime {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

// ------------------------------------------------------------- requests

/// What the user asked for, before it gets a request id's header.
enum Intent {
    Apply(Box<ApplyDraft>),
    SetDesired(InstanceId, Desired),
    Remove(InstanceId),
    RetryStart(InstanceId),
    RetryReclaim(InstanceId),
    Resolve(Vec<CandidateDecision>),
}

impl Intent {
    fn describe(&self) -> (OperationKind, Option<InstanceId>) {
        match self {
            Self::Apply(draft) => (OperationKind::Apply, Some(draft.instance_id.clone())),
            Self::SetDesired(id, Desired::Stopped) => (OperationKind::Stop, Some(id.clone())),
            Self::SetDesired(id, _) => (OperationKind::Start, Some(id.clone())),
            Self::Remove(id) => (OperationKind::Remove, Some(id.clone())),
            Self::RetryStart(id) => (OperationKind::RetryStart, Some(id.clone())),
            Self::RetryReclaim(id) => (OperationKind::RetryReclaim, Some(id.clone())),
            Self::Resolve(_) => (OperationKind::ResolveCandidates, None),
        }
    }

    fn into_request(self, request_id: &RequestId, expected_revision: Revision) -> Request {
        let header = Some(MutationHeader {
            request_id: request_id.0.clone(),
            expected_revision,
        });
        match self {
            Self::Apply(draft) => {
                let mut spec = draft.spec.get().clone();
                spec.network_secret = match &draft.secret {
                    SecretInput::Keep => None,
                    SecretInput::Clear => Some(String::new()),
                    SecretInput::Set(secret) => Some(secret.expose().to_owned()),
                };
                Request::Apply(Box::new(ApplyRequest {
                    header,
                    instance_id: draft.instance_id.0,
                    spec: Some(spec),
                    desired: draft.desired as i32,
                }))
            }
            Self::SetDesired(id, desired) => Request::SetDesired(SetDesiredRequest {
                header,
                instance_id: id.0,
                desired: desired as i32,
            }),
            Self::Remove(id) => Request::Remove(RemoveInstanceRequest {
                header,
                instance_id: id.0,
            }),
            Self::RetryStart(id) => Request::RetryStart(RetryStartRequest {
                header,
                instance_id: id.0,
            }),
            Self::RetryReclaim(id) => Request::RetryReclaim(RetryReclaimRequest {
                header,
                instance_id: id.0,
            }),
            Self::Resolve(decisions) => {
                Request::Resolve(ResolveCandidatesRequest { header, decisions })
            }
        }
    }
}

/// A request as sent. An Apply holds the secret, so this type has no
/// `Debug` and lives only as long as the request may be resent.
#[derive(Clone)]
enum Request {
    Apply(Box<ApplyRequest>),
    SetDesired(SetDesiredRequest),
    Remove(RemoveInstanceRequest),
    RetryStart(RetryStartRequest),
    RetryReclaim(RetryReclaimRequest),
    Resolve(ResolveCandidatesRequest),
}

impl Request {
    async fn send(&self, client: &dyn HostClient) -> Result<Receipt, CallError> {
        match self.clone() {
            Self::Apply(request) => client.apply(*request).await,
            Self::SetDesired(request) => client.set_desired(request).await,
            Self::Remove(request) => client.remove_instance(request).await,
            Self::RetryStart(request) => client.retry_start(request).await,
            Self::RetryReclaim(request) => client.retry_reclaim(request).await,
            Self::Resolve(request) => client.resolve_candidates(request).await,
        }
    }
}

enum Body {
    New(Intent),
    /// An earlier request, unchanged.
    Resend(Request),
}

struct Job {
    id: RequestId,
    body: Body,
}

enum Outcome {
    Accepted(Receipt),
    Rejected(CallError),
    /// The reply is missing and the lookups did not settle it.
    Unconfirmed(CallError),
}

fn outcome_unknown(error: &CallError) -> bool {
    matches!(
        error,
        CallError::Unavailable(_) | CallError::Transport(_) | CallError::Cancelled
    )
}

fn unavailable(reason: &str) -> CallError {
    CallError::Unavailable(reason.into())
}

async fn limited<T>(
    limit: Duration,
    call: impl Future<Output = Result<T, CallError>>,
) -> Result<T, CallError> {
    timeout(limit, call)
        .await
        .unwrap_or_else(|_| Err(unavailable("the host did not answer in time")))
}

fn doubled(delay: Duration, config: &BridgeConfig) -> Duration {
    (delay * 2).min(config.retry_max)
}

/// Sends once. When the reply is lost: look the receipt up, and resend the
/// identical request only after the host said it has no record of it.
async fn execute(
    client: &dyn HostClient,
    request: &Request,
    id: &RequestId,
    config: BridgeConfig,
) -> Outcome {
    let mut last = match limited(config.call_timeout, request.send(client)).await {
        Ok(receipt) => return Outcome::Accepted(receipt),
        Err(error) if outcome_unknown(&error) => error,
        Err(error) => return Outcome::Rejected(error),
    };
    let mut delay = config.retry_min;
    for _ in 0..config.recovery_attempts {
        sleep(delay).await;
        delay = doubled(delay, &config);
        match limited(config.call_timeout, client.receipt(id.clone())).await {
            Ok(Some(receipt)) => return Outcome::Accepted(receipt),
            Ok(None) => match limited(config.call_timeout, request.send(client)).await {
                Ok(receipt) => return Outcome::Accepted(receipt),
                Err(error) if outcome_unknown(&error) => last = error,
                // The first send may still commit between the lookup and this
                // answer; a conflict is then about our own change.
                Err(error) => {
                    return match limited(config.call_timeout, client.receipt(id.clone())).await {
                        Ok(Some(receipt)) => Outcome::Accepted(receipt),
                        _ => Outcome::Rejected(error),
                    };
                }
            },
            Err(error) => last = error,
        }
    }
    Outcome::Unconfirmed(last)
}

// ---------------------------------------------------------------- actor

enum Msg {
    Probed {
        launch: u64,
        result: Result<Option<HostTarget>, LaunchError>,
    },
    Launched {
        launch: u64,
        mode: HostMode,
        result: Result<HostTarget, LaunchError>,
    },
    Relaunched {
        session: u64,
        result: Result<HostTarget, LaunchError>,
    },
    Connection {
        session: u64,
        state: ConnectionState,
    },
    Unverified {
        session: u64,
        reason: String,
    },
    Snapshot {
        session: u64,
        snapshot: Box<HostSnapshot>,
    },
    Event {
        session: u64,
        event: Box<Event>,
    },
    /// The event stream ended without asking for a new snapshot.
    StreamEnded {
        session: u64,
    },
    Finished {
        session: u64,
        id: RequestId,
        request: Box<Request>,
        outcome: Outcome,
    },
    LookedUp {
        session: u64,
        id: RequestId,
        receipt: Receipt,
    },
    Queried {
        watch: u64,
        kind: QueryKind,
        result: Result<QueryResponse, CallError>,
    },
    Saved {
        error: Option<String>,
    },
}

struct Session {
    id: u64,
    target: HostTarget,
    client: Arc<dyn HostClient>,
    cancel: CancellationToken,
    resync: watch::Sender<u64>,
}

/// Saves profiles one at a time, always the newest list.
struct ProfileWriter {
    queue: watch::Sender<(u64, Arc<Vec<Profile>>)>,
    saved: watch::Receiver<u64>,
    version: u64,
}

struct Actor {
    services: AppServices,
    config: BridgeConfig,
    store: StateStore,
    dirty: bool,
    states: async_channel::Sender<StateStore>,
    inbox: mpsc::Sender<Msg>,
    root: CancellationToken,
    /// Parent of everything that reads from the host continuously.
    subscriptions: CancellationToken,
    subscription_tasks: Vec<TaskHandle<()>>,
    next_id: u64,
    session: Option<Session>,
    /// The launch or probe in progress.
    launch: Option<(u64, AbortHandle)>,
    relaunching: bool,
    queue: VecDeque<Job>,
    in_flight: Option<(RequestId, AbortHandle)>,
    busy: watch::Sender<bool>,
    /// Requests that may still be resent unchanged.
    retained: BTreeMap<RequestId, Request>,
    /// The stop to resend for "retry confirm".
    stop_retry: BTreeMap<InstanceId, RequestId>,
    forget_on_accept: BTreeMap<RequestId, InstanceId>,
    watch: Option<(u64, CancellationToken)>,
    profiles: ProfileWriter,
    profiles_writable: bool,
    exiting: bool,
}

impl Actor {
    fn new(
        services: AppServices,
        config: BridgeConfig,
        states: async_channel::Sender<StateStore>,
        root: CancellationToken,
    ) -> (Self, mpsc::Receiver<Msg>) {
        let (inbox, receiver) = mpsc::channel(256);
        let mut store = StateStore::default();
        let profiles_writable = match services.profiles.load() {
            Ok(profiles) => {
                store.profiles = profiles;
                true
            }
            Err(error) => {
                store.profile_error = Some(error.to_string());
                false
            }
        };
        let (queue, mut queued) = watch::channel((0u64, Arc::new(Vec::new())));
        let (saved_tx, saved) = watch::channel(0u64);
        let (store_handle, reports) = (services.profiles.clone(), inbox.clone());
        tokio::spawn(async move {
            while queued.changed().await.is_ok() {
                let (version, list) = queued.borrow_and_update().clone();
                let target = store_handle.clone();
                let result = tokio::task::spawn_blocking(move || target.save(&list)).await;
                let error = match result {
                    Ok(result) => result.err().map(|error| error.to_string()),
                    Err(error) => Some(format!("saving profiles failed: {error}")),
                };
                // Report first: whoever waits for the version then finds the
                // result already queued.
                let _ = reports.send(Msg::Saved { error }).await;
                saved_tx.send_replace(version);
            }
        });
        let subscriptions = root.child_token();
        let actor = Self {
            services,
            config,
            store,
            dirty: true,
            states,
            inbox,
            root,
            subscriptions,
            subscription_tasks: Vec::new(),
            next_id: 0,
            session: None,
            launch: None,
            relaunching: false,
            queue: VecDeque::new(),
            in_flight: None,
            busy: watch::Sender::new(false),
            retained: BTreeMap::new(),
            stop_retry: BTreeMap::new(),
            forget_on_accept: BTreeMap::new(),
            watch: None,
            profiles: ProfileWriter {
                queue,
                saved,
                version: 0,
            },
            profiles_writable,
            exiting: false,
        };
        (actor, receiver)
    }

    async fn run(
        mut self,
        mut inbox: mpsc::Receiver<Msg>,
        commands: async_channel::Receiver<UserCommand>,
        mut control: mpsc::UnboundedReceiver<Control>,
    ) {
        let root = self.root.clone();
        let (mut commands_open, mut control_open) = (true, true);
        self.publish();
        loop {
            tokio::select! {
                biased;
                _ = root.cancelled() => break,
                next = control.recv(), if control_open => match next {
                    Some(next) => self.on_control(next, &commands),
                    None => control_open = false,
                },
                next = commands.recv(), if commands_open => match next {
                    Ok(command) => self.on_command(command),
                    Err(_) => commands_open = false,
                },
                Some(message) = inbox.recv() => {
                    self.on_message(message);
                    // Coalesce a burst into one published state.
                    for _ in 0..255 {
                        let Ok(message) = inbox.try_recv() else { break };
                        self.on_message(message);
                    }
                }
            }
            self.dispatch();
            self.publish();
        }
    }

    fn publish(&mut self) {
        if std::mem::take(&mut self.dirty) {
            // Replaces an unread state; fails only when the UI is gone.
            let _ = self.states.force_send(self.store.clone());
        }
    }

    fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn session_is(&self, id: u64) -> bool {
        self.session.as_ref().is_some_and(|s| s.id == id)
    }

    // ------------------------------------------------------ control/exit

    fn on_control(&mut self, control: Control, commands: &async_channel::Receiver<UserCommand>) {
        match control {
            Control::Settle { release, reply } => {
                // What the user did before choosing to exit still counts.
                while let Ok(command) = commands.try_recv() {
                    self.on_command(command);
                }
                self.dispatch();
                self.settle(release, reply);
            }
            Control::StopSubscriptions { reply } => {
                self.exiting = true;
                self.subscriptions.cancel();
                self.watch = None;
                let tasks = std::mem::take(&mut self.subscription_tasks);
                tokio::spawn(async move {
                    let mut result = Ok(());
                    for task in tasks {
                        if let Err(error) = task.await
                            && error.is_panic()
                        {
                            result = Err("a subscription task panicked".to_owned());
                        }
                    }
                    let _ = reply.send(result).await;
                });
            }
        }
    }

    /// Lets pending requests and profile writes finish, then hands the lease
    /// back to a session-form host.
    fn settle(&mut self, release: LeaseRelease, reply: async_channel::Sender<Result<(), String>>) {
        self.exiting = true;
        if let Some((_, launch)) = self.launch.take() {
            launch.abort();
        }
        self.stop_watch();
        let lease = self.session.as_ref().and_then(|session| {
            let mode = session
                .client
                .negotiated()
                .map_or(session.target.mode, |n| n.host_mode);
            matches!(mode, HostMode::User | HostMode::ElevatedSession)
                .then(|| session.client.clone())
        });
        let mut busy = self.busy.subscribe();
        let mut saved = self.profiles.saved.clone();
        let queued = self.profiles.queue.subscribe();
        let config = self.config;
        tokio::spawn(async move {
            let drained = timeout(config.drain_timeout, async {
                let _ = busy.wait_for(|busy| !*busy).await;
                // Read afterwards: an accepted removal queues a write too.
                let version = queued.borrow().0;
                let _ = saved.wait_for(|saved| *saved >= version).await;
            })
            .await
            .map_err(|_| "pending requests or profile writes did not finish".to_owned());
            let released = match lease {
                None => Ok(()),
                Some(client) => {
                    match limited(config.release_timeout, client.release_lease(release)).await {
                        // A service host holds no lease to give back.
                        Ok(_) | Err(CallError::Unsupported(_)) => Ok(()),
                        Err(error) => Err(format!("the lease was not released: {error}")),
                    }
                }
            };
            let _ = reply.send(released.and(drained)).await;
        });
    }

    // ---------------------------------------------------------- commands

    fn on_command(&mut self, command: UserCommand) {
        if self.exiting {
            return;
        }
        self.dirty = true;
        match command {
            UserCommand::AutoConnect => self.probe(),
            UserCommand::Connect(mode) => self.connect(mode),
            UserCommand::Refresh => self.request_resync(),
            UserCommand::Apply(draft) => {
                self.save_profile(draft.instance_id.clone(), draft.spec.clone());
                self.enqueue(Intent::Apply(draft));
            }
            UserCommand::SetDesired { instance, desired } => {
                if desired != Desired::Unspecified {
                    self.enqueue(Intent::SetDesired(instance, desired));
                }
            }
            UserCommand::RetryConfirmStop(instance) => self.retry_confirm_stop(instance),
            UserCommand::Remove {
                instance,
                forget_profile,
            } => {
                let id = self.enqueue(Intent::Remove(instance.clone()));
                if forget_profile {
                    self.forget_on_accept.insert(id, instance);
                }
            }
            UserCommand::RetryStart(instance) => {
                self.enqueue(Intent::RetryStart(instance));
            }
            UserCommand::RetryReclaim(instance) => {
                self.enqueue(Intent::RetryReclaim(instance));
            }
            UserCommand::ResolveCandidates(decisions) => {
                if !decisions.is_empty() {
                    self.enqueue(Intent::Resolve(decisions));
                }
            }
            UserCommand::RetryOperation(id) => self.retry_operation(id),
            UserCommand::DismissOperation(id) => self.dismiss(&id),
            UserCommand::Watch(instance) => self.start_watch(instance),
            UserCommand::SaveProfile { instance_id, spec } => self.save_profile(instance_id, spec),
            UserCommand::DeleteProfile(instance) => self.delete_profile(&instance),
        }
    }

    fn enqueue(&mut self, intent: Intent) -> RequestId {
        let id = new_request_id();
        let (kind, instance) = intent.describe();
        self.store.put_operation(Operation {
            request_id: id.clone(),
            kind,
            instance,
            status: OperationStatus::Queued,
        });
        self.queue.push_back(Job {
            id: id.clone(),
            body: Body::New(intent),
        });
        id
    }

    fn pending(&self, id: &RequestId) -> bool {
        self.queue.iter().any(|job| &job.id == id)
            || self
                .in_flight
                .as_ref()
                .is_some_and(|(current, _)| current == id)
    }

    fn resend(&mut self, id: RequestId, kind: OperationKind, instance: Option<InstanceId>) {
        let Some(request) = self.retained.get(&id).cloned() else {
            return;
        };
        self.store.put_operation(Operation {
            request_id: id.clone(),
            kind,
            instance,
            status: OperationStatus::Queued,
        });
        self.queue.push_back(Job {
            id,
            body: Body::Resend(request),
        });
    }

    fn retry_confirm_stop(&mut self, instance: InstanceId) {
        if let Some(id) = self.stop_retry.get(&instance).cloned()
            && self.retained.contains_key(&id)
        {
            if !self.pending(&id) {
                self.resend(id, OperationKind::Stop, Some(instance));
            }
            return;
        }
        // Nothing to resend (e.g. the UI restarted): a new stop request.
        let waiting = self.store.operations.iter().any(|op| {
            op.kind == OperationKind::Stop
                && op.instance.as_ref() == Some(&instance)
                && self.pending(&op.request_id)
        });
        if !waiting {
            self.enqueue(Intent::SetDesired(instance, Desired::Stopped));
        }
    }

    fn retry_operation(&mut self, id: RequestId) {
        let Some(op) = self.store.operation(&id) else {
            return;
        };
        if matches!(op.status, OperationStatus::Unconfirmed(_)) && !self.pending(&id) {
            let (kind, instance) = (op.kind, op.instance.clone());
            self.resend(id, kind, instance);
        }
    }

    fn dismiss(&mut self, id: &RequestId) {
        if self.pending(id) {
            return;
        }
        self.store.operations.retain(|op| &op.request_id != id);
        self.retained.remove(id);
        self.stop_retry.retain(|_, stop| stop != id);
        self.forget_on_accept.remove(id);
    }

    // --------------------------------------------------------- mutations

    fn fail_job(&mut self, job: Job, reason: &str) {
        let failure = Failure(unavailable(reason));
        let status = match job.body {
            // Never sent, so the outcome is known.
            Body::New(_) => {
                self.forget_on_accept.remove(&job.id);
                OperationStatus::Failed(failure)
            }
            // Sent before; still unknown.
            Body::Resend(_) => OperationStatus::Unconfirmed(failure),
        };
        self.store.set_operation_status(&job.id, status);
        self.dirty = true;
    }

    fn dispatch(&mut self) {
        while self.in_flight.is_none() && !self.queue.is_empty() {
            let usable = !matches!(
                self.store.link,
                HostLink::Reconnecting { .. } | HostLink::UpgradeRequired { .. } | HostLink::Closed
            );
            let Some((session, client)) = self
                .session
                .as_ref()
                .filter(|_| usable)
                .map(|s| (s.id, s.client.clone()))
            else {
                // Failing now beats running a click much later by surprise.
                while let Some(job) = self.queue.pop_front() {
                    self.fail_job(job, "not connected to a host");
                }
                break;
            };
            let ready = match self.queue.front().map(|job| &job.body) {
                // A new request needs a revision the user can see.
                Some(Body::New(_)) => {
                    self.store.link == HostLink::Connected && self.store.sync == SyncState::Synced
                }
                _ => self.store.link == HostLink::Connected,
            };
            if !ready {
                break;
            }
            let Some(job) = self.queue.pop_front() else {
                break;
            };
            let request = match job.body {
                Body::New(intent) => intent.into_request(&job.id, self.store.revision),
                Body::Resend(request) => request,
            };
            self.store
                .set_operation_status(&job.id, OperationStatus::Sending);
            self.dirty = true;
            let (id, inbox, config) = (job.id.clone(), self.inbox.clone(), self.config);
            let task = tokio::spawn(async move {
                let outcome = execute(client.as_ref(), &request, &id, config).await;
                let _ = inbox
                    .send(Msg::Finished {
                        session,
                        id,
                        request: Box::new(request),
                        outcome,
                    })
                    .await;
            });
            self.in_flight = Some((job.id, task.abort_handle()));
        }
        let busy = self.in_flight.is_some() || !self.queue.is_empty();
        self.busy.send_if_modified(|current| {
            let changed = *current != busy;
            *current = busy;
            changed
        });
    }

    fn accept(&mut self, id: &RequestId, receipt: Receipt) {
        self.store.revision = self.store.revision.max(receipt.revision);
        let finished = self
            .store
            .operation(id)
            .map(|op| (op.kind, op.instance.clone()));
        self.store
            .set_operation_status(id, OperationStatus::Accepted(receipt));
        self.retained.remove(id);
        self.stop_retry.retain(|_, stop| stop != id);
        // A later start supersedes a stop still waiting to be confirmed.
        if let Some((OperationKind::Start | OperationKind::RetryStart, Some(instance))) = finished {
            self.stop_retry.remove(&instance);
        }
        if let Some(instance) = self.forget_on_accept.remove(id) {
            self.delete_profile(&instance);
        }
    }

    fn finish(&mut self, id: RequestId, request: Request, outcome: Outcome) {
        let stop_of = match &request {
            Request::SetDesired(r) if r.desired() == Desired::Stopped => {
                Some(InstanceId(r.instance_id.clone()))
            }
            _ => None,
        };
        match outcome {
            Outcome::Accepted(receipt) => self.accept(&id, receipt),
            Outcome::Rejected(error) => {
                // These say the store is behind the host.
                let outdated = matches!(error, CallError::Conflict { .. });
                let failure = Failure(error);
                // The kernel is down but the stop is not durable: keep the
                // request for "retry confirm".
                let keep = failure.code() == Some(ErrorCode::LedgerUnavailable);
                self.store
                    .set_operation_status(&id, OperationStatus::Failed(failure));
                match stop_of.filter(|_| keep) {
                    Some(instance) => self.retain_stop(instance, id, request),
                    None => {
                        self.retained.remove(&id);
                        self.stop_retry.retain(|_, stop| stop != &id);
                        self.forget_on_accept.remove(&id);
                    }
                }
                if outdated {
                    self.request_resync();
                }
            }
            Outcome::Unconfirmed(error) => {
                self.store
                    .set_operation_status(&id, OperationStatus::Unconfirmed(Failure(error)));
                match stop_of {
                    Some(instance) => self.retain_stop(instance, id, request),
                    None => {
                        self.retained.insert(id, request);
                    }
                }
            }
        }
    }

    fn retain_stop(&mut self, instance: InstanceId, id: RequestId, request: Request) {
        if let Some(older) = self.stop_retry.insert(instance, id.clone())
            && older != id
        {
            self.retained.remove(&older);
        }
        self.retained.insert(id, request);
    }

    /// A confirmed stop needs no retry any more.
    fn drop_settled_stops(&mut self) {
        let store = &self.store;
        self.stop_retry.retain(|instance, _| {
            store
                .instance(instance)
                .is_some_and(|entry| entry.condition() != crate::InstanceCondition::Stopped)
        });
    }

    /// After a reconnect: ask (read only) what became of unconfirmed
    /// requests.
    fn look_up_unconfirmed(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        let ids: Vec<RequestId> = self
            .store
            .operations
            .iter()
            .filter(|op| matches!(op.status, OperationStatus::Unconfirmed(_)))
            .map(|op| op.request_id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        let (client, session, inbox, limit) = (
            session.client.clone(),
            session.id,
            self.inbox.clone(),
            self.config.call_timeout,
        );
        let cancel = self.subscriptions.clone();
        tokio::spawn(cancel.run_until_cancelled_owned(async move {
            for id in ids {
                if let Ok(Some(receipt)) = limited(limit, client.receipt(id.clone())).await {
                    let _ = inbox
                        .send(Msg::LookedUp {
                            session,
                            id,
                            receipt,
                        })
                        .await;
                }
            }
        }));
    }

    // ---------------------------------------------------------- sessions

    fn close_session(&mut self) {
        self.stop_watch();
        self.relaunching = false;
        if let Some(session) = self.session.take() {
            session.cancel.cancel();
        }
        if let Some((_, task)) = self.in_flight.take() {
            task.abort();
        }
        // Request ids, revisions and retries belong to that host's ledger.
        self.queue.clear();
        self.retained.clear();
        self.stop_retry.clear();
        self.forget_on_accept.clear();
    }

    fn open_session(&mut self, target: HostTarget) {
        self.close_session();
        self.store.reset_host_data();
        self.store.link = HostLink::Connecting;
        let client = self.services.clients.connect(&target);
        let id = self.fresh_id();
        let cancel = self.subscriptions.child_token();
        let (resync, resync_rx) = watch::channel(0u64);
        self.subscription_tasks.retain(|task| !task.is_finished());
        self.subscription_tasks.push(spawn_cancellable(
            cancel.clone(),
            follow_connection(id, client.clone(), self.inbox.clone()),
        ));
        self.subscription_tasks.push(spawn_cancellable(
            cancel.clone(),
            follow_events(
                id,
                client.clone(),
                resync_rx,
                self.inbox.clone(),
                self.config,
            ),
        ));
        self.session = Some(Session {
            id,
            target,
            client,
            cancel,
            resync,
        });
    }

    fn request_resync(&mut self) {
        if let Some(session) = &self.session {
            if self.store.sync == SyncState::Synced {
                self.store.sync = SyncState::Stale;
            }
            session.resync.send_modify(|n| *n += 1);
        }
    }

    fn start_launch(&mut self, launch: u64, task: impl Future<Output = Msg> + Send + 'static) {
        if let Some((_, previous)) = self.launch.take() {
            previous.abort();
        }
        let inbox = self.inbox.clone();
        let handle = tokio::spawn(async move {
            let message = task.await;
            let _ = inbox.send(message).await;
        });
        self.launch = Some((launch, handle.abort_handle()));
    }

    fn probe(&mut self) {
        if self.session.is_some() {
            return;
        }
        let launch = self.fresh_id();
        let launcher = self.services.launcher.clone();
        self.start_launch(launch, async move {
            Msg::Probed {
                launch,
                result: launcher.probe().await,
            }
        });
    }

    fn connect(&mut self, mode: HostMode) {
        if self.session.as_ref().is_some_and(|s| s.target.mode == mode)
            && self.store.link == HostLink::Connected
        {
            return;
        }
        self.close_session();
        self.store.reset_host_data();
        self.store.link = HostLink::Launching(mode);
        let launch = self.fresh_id();
        let launcher = self.services.launcher.clone();
        self.start_launch(launch, async move {
            Msg::Launched {
                launch,
                mode,
                result: launcher.ensure(mode).await,
            }
        });
    }

    /// A user host has no service manager: the UI starts it again.
    fn relaunch_if_needed(&mut self) {
        let HostLink::Reconnecting { attempt } = self.store.link else {
            return;
        };
        let Some(session) = &self.session else { return };
        if self.exiting
            || self.relaunching
            || session.target.mode != HostMode::User
            || attempt < self.config.relaunch_after
        {
            return;
        }
        self.relaunching = true;
        let (id, inbox) = (session.id, self.inbox.clone());
        let launcher = self.services.launcher.clone();
        let cancel = session.cancel.clone();
        tokio::spawn(cancel.run_until_cancelled_owned(async move {
            let result = launcher.ensure(HostMode::User).await;
            let _ = inbox
                .send(Msg::Relaunched {
                    session: id,
                    result,
                })
                .await;
        }));
    }

    // ------------------------------------------------------------- watch

    fn stop_watch(&mut self) {
        if let Some((_, cancel)) = self.watch.take() {
            cancel.cancel();
        }
        self.store.watched = None;
    }

    /// The watched instance is gone: the reducer dropped its data.
    fn stop_orphaned_watch(&mut self) {
        if self.store.watched.is_none() {
            self.stop_watch();
        }
    }

    fn start_watch(&mut self, instance: Option<InstanceId>) {
        self.stop_watch();
        let (Some(instance), Some(session)) = (instance, &self.session) else {
            return;
        };
        let (client, cancel) = (session.client.clone(), session.cancel.child_token());
        let watch = self.fresh_id();
        self.store.watched = Some(WatchedInstance::new(instance.clone()));
        self.subscription_tasks.retain(|task| !task.is_finished());
        self.subscription_tasks.push(spawn_cancellable(
            cancel.clone(),
            poll_queries(watch, instance, client, self.inbox.clone(), self.config),
        ));
        self.watch = Some((watch, cancel));
    }

    fn on_query(&mut self, kind: QueryKind, result: Result<QueryResponse, CallError>) {
        let Some(watched) = self.store.watched.as_mut() else {
            return;
        };
        watched.errors.retain(|(failed, _)| *failed != kind);
        match result {
            Ok(response) => match response.result {
                Some(query_response::Result::Nodes(list)) => watched.nodes = Some(list.nodes),
                Some(query_response::Result::Routes(list)) => watched.routes = Some(list.routes),
                Some(query_response::Result::Traffic(stats)) => watched.traffic = Some(stats),
                None => {}
            },
            Err(error) => {
                let failure = Failure(error);
                if failure.code() == Some(ErrorCode::ManagementUnavailable) {
                    match kind {
                        QueryKind::Nodes => watched.nodes = None,
                        QueryKind::Routes => watched.routes = None,
                        QueryKind::Traffic => watched.traffic = None,
                        QueryKind::Unspecified => {}
                    }
                }
                watched.errors.push((kind, failure));
            }
        }
    }

    // ---------------------------------------------------------- profiles

    fn schedule_save(&mut self) {
        self.profiles.version += 1;
        self.profiles
            .queue
            .send_replace((self.profiles.version, Arc::new(self.store.profiles.clone())));
    }

    fn save_profile(&mut self, instance_id: InstanceId, spec: SecretFreeSpec) {
        if !self.profiles_writable {
            // The load error stays visible; saving now would drop what the
            // unreadable library holds.
            return;
        }
        let profile = Profile {
            instance_id,
            spec: spec.get().clone(),
            updated_at: jiff::Timestamp::now(),
        };
        match self
            .store
            .profiles
            .iter_mut()
            .find(|p| p.instance_id == profile.instance_id)
        {
            Some(existing) => *existing = profile,
            None => self.store.profiles.push(profile),
        }
        self.schedule_save();
    }

    fn delete_profile(&mut self, instance: &InstanceId) {
        if !self.profiles_writable {
            return;
        }
        let before = self.store.profiles.len();
        self.store.profiles.retain(|p| &p.instance_id != instance);
        if self.store.profiles.len() != before {
            self.schedule_save();
        }
    }

    // ---------------------------------------------------------- messages

    fn on_reduced(&mut self, reduced: Reduced) {
        match reduced {
            Reduced::Changed => self.dirty = true,
            Reduced::Ignored => {}
            Reduced::Resync(cause) => {
                tracing::debug!(?cause, "taking a new snapshot");
                self.dirty = true;
                self.request_resync();
            }
        }
    }

    fn on_message(&mut self, message: Msg) {
        match message {
            Msg::Probed { launch, result } => {
                if self.launch.as_ref().is_none_or(|(id, _)| *id != launch) {
                    return;
                }
                self.launch = None;
                self.dirty = true;
                match result {
                    Ok(Some(target)) => self.open_session(target),
                    Ok(None) => self.store.link = HostLink::NoHost,
                    Err(error) => {
                        self.store.link = HostLink::LaunchFailed(LaunchFailure::new(None, &error));
                    }
                }
            }
            Msg::Launched {
                launch,
                mode,
                result,
            } => {
                if self.launch.as_ref().is_none_or(|(id, _)| *id != launch) {
                    return;
                }
                self.launch = None;
                self.dirty = true;
                match result {
                    Ok(target) => self.open_session(target),
                    Err(error) => {
                        self.store.link =
                            HostLink::LaunchFailed(LaunchFailure::new(Some(mode), &error));
                    }
                }
            }
            Msg::Relaunched { session, result } => {
                if !self.session_is(session) {
                    return;
                }
                self.relaunching = false;
                match result {
                    Ok(target) => {
                        if self.session.as_ref().is_some_and(|s| s.target != target) {
                            self.open_session(target);
                            self.dirty = true;
                        }
                    }
                    Err(error) => {
                        let failure = LaunchFailure::new(Some(HostMode::User), &error);
                        self.store.relaunch_failure = Some(failure);
                        self.dirty = true;
                    }
                }
            }
            Msg::Connection { session, state } => {
                if !self.session_is(session) {
                    return;
                }
                let was_connected = self.store.link == HostLink::Connected;
                let reduced = reducer::apply_connection(&mut self.store, state);
                self.on_reduced(reduced);
                if !was_connected && self.store.link == HostLink::Connected {
                    self.look_up_unconfirmed();
                }
                self.relaunch_if_needed();
            }
            Msg::Unverified { session, reason } => {
                if self.session_is(session) && self.store.link != HostLink::Connected {
                    self.store.unverified_host = Some(reason);
                    self.dirty = true;
                }
            }
            Msg::Snapshot { session, snapshot } => {
                if self.session_is(session) {
                    reducer::apply_snapshot(&mut self.store, *snapshot);
                    self.drop_settled_stops();
                    self.stop_orphaned_watch();
                    self.dirty = true;
                }
            }
            Msg::Event { session, event } => {
                if self.session_is(session) {
                    let reduced = reducer::apply_event(&mut self.store, *event);
                    self.drop_settled_stops();
                    self.stop_orphaned_watch();
                    self.on_reduced(reduced);
                }
            }
            Msg::StreamEnded { session } => {
                if self.session_is(session) && self.store.sync == SyncState::Synced {
                    self.store.sync = SyncState::Stale;
                    self.dirty = true;
                }
            }
            Msg::Finished {
                session,
                id,
                request,
                outcome,
            } => {
                if !self.session_is(session) {
                    return;
                }
                if self
                    .in_flight
                    .as_ref()
                    .is_some_and(|(current, _)| current == &id)
                {
                    self.in_flight = None;
                }
                self.finish(id, *request, outcome);
                self.dirty = true;
            }
            Msg::LookedUp {
                session,
                id,
                receipt,
            } => {
                let unconfirmed = self
                    .store
                    .operation(&id)
                    .is_some_and(|op| matches!(op.status, OperationStatus::Unconfirmed(_)));
                if self.session_is(session) && unconfirmed {
                    self.accept(&id, receipt);
                    self.dirty = true;
                }
            }
            Msg::Queried {
                watch,
                kind,
                result,
            } => {
                if self.watch.as_ref().is_some_and(|(id, _)| *id == watch) {
                    self.on_query(kind, result);
                    self.dirty = true;
                }
            }
            Msg::Saved { error } => {
                if self.profiles_writable && self.store.profile_error != error {
                    self.store.profile_error = error;
                    self.dirty = true;
                }
            }
        }
    }
}

// ------------------------------------------------------- session tasks

fn spawn_cancellable(
    cancel: CancellationToken,
    task: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle<()> {
    tokio::spawn(async move {
        let _ = cancel.run_until_cancelled(task).await;
    })
}

/// Without a connection a call answers at once; the limit covers the race
/// with a connection that just came up.
const REASON_PROBE: Duration = Duration::from_millis(200);

async fn follow_connection(session: u64, client: Arc<dyn HostClient>, inbox: mpsc::Sender<Msg>) {
    let mut connection = client.connection();
    loop {
        let state = connection.borrow_and_update().clone();
        let down = matches!(state, ConnectionState::Reconnecting { .. });
        if inbox
            .send(Msg::Connection { session, state })
            .await
            .is_err()
        {
            return;
        }
        // The state does not say why there is no connection; a call fails at
        // once with the reason.
        if down
            && let Ok(Err(CallError::HostNotVerified(reason))) =
                timeout(REASON_PROBE, client.snapshot()).await
        {
            let message = Msg::Unverified { session, reason };
            if inbox.send(message).await.is_err() {
                return;
            }
        }
        if connection.changed().await.is_err() {
            return;
        }
    }
}

/// Snapshot, then events from its cursor; again whenever the actor asks or
/// the stream ends.
async fn follow_events(
    session: u64,
    client: Arc<dyn HostClient>,
    mut resync: watch::Receiver<u64>,
    inbox: mpsc::Sender<Msg>,
    config: BridgeConfig,
) {
    let mut connection = client.connection();
    let mut delay = config.retry_min;
    loop {
        // The client fails calls at once while it has no connection.
        if connection
            .wait_for(|state| matches!(state, ConnectionState::Connected(_)))
            .await
            .is_err()
        {
            return;
        }
        // Requests made before this snapshot are satisfied by it.
        resync.borrow_and_update();
        let snapshot = match limited(config.call_timeout, client.snapshot()).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::debug!(%error, "snapshot failed");
                sleep(delay).await;
                delay = doubled(delay, &config);
                continue;
            }
        };
        let cursor = snapshot.cursor.clone();
        let message = Msg::Snapshot {
            session,
            snapshot: Box::new(snapshot),
        };
        if inbox.send(message).await.is_err() {
            return;
        }
        let mut events = client.subscribe(cursor);
        let mut received = false;
        let asked = loop {
            tokio::select! {
                biased;
                changed = resync.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    break true;
                }
                item = events.next() => match item {
                    Some(Ok(event)) => {
                        received = true;
                        let message = Msg::Event { session, event: Box::new(event) };
                        if inbox.send(message).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(error)) => {
                        tracing::debug!(%error, "event stream failed");
                        break false;
                    }
                    None => break false,
                }
            }
        };
        drop(events);
        if asked {
            // A floor, so a host that keeps breaking its stream cannot make
            // this loop spin.
            sleep(config.retry_min / 4).await;
            continue;
        }
        // After a `ResyncRequired` the actor's request is already on its way;
        // the delay lets it arrive first.
        if inbox.send(Msg::StreamEnded { session }).await.is_err() {
            return;
        }
        if received {
            delay = config.retry_min;
        }
        sleep(delay).await;
        delay = doubled(delay, &config);
    }
}

async fn poll_queries(
    watch: u64,
    instance: InstanceId,
    client: Arc<dyn HostClient>,
    inbox: mpsc::Sender<Msg>,
    config: BridgeConfig,
) {
    use etd_contract::capability;
    loop {
        let connected = matches!(*client.connection().borrow(), ConnectionState::Connected(_));
        if connected && let Some(negotiated) = client.negotiated() {
            for (kind, name) in [
                (QueryKind::Nodes, capability::QUERY_NODES),
                (QueryKind::Routes, capability::QUERY_ROUTES),
                (QueryKind::Traffic, capability::QUERY_TRAFFIC),
            ] {
                if !negotiated.has_capability(name) {
                    continue;
                }
                let result =
                    limited(config.call_timeout, client.query(instance.clone(), kind)).await;
                let message = Msg::Queried {
                    watch,
                    kind,
                    result,
                };
                if inbox.send(message).await.is_err() {
                    return;
                }
            }
        }
        sleep(config.query_interval).await;
    }
}

//! The background runtime against fake host, launcher and profile store,
//! driven only through the UI's two channels and the exit gate.
mod common;

use common::*;
use etd_app::bridge::{ApplyDraft, SecretFreeSpec};
use etd_app::{
    AppBridge, AppRuntime, AppServices, BridgeConfig, ExitDeadlines, ExitGate, ExitPhase,
    ExitReport, HostClientFactory, HostLink, HostTarget, InstanceCondition, LaunchError,
    LaunchFailureKind, OperationKind, OperationStatus, Profile, ProfileError, Secret, SecretInput,
    StateStore, SyncState, UserCommand,
};
use etd_client::{CallError, HostClient};
use etd_contract::v1::{ErrorDetail, LeaseRelease, Node, NodeList, query_response};
use etd_contract::{
    Desired, ErrorCode, HostMode, InstanceId, InstanceState, NetworkSpec, QueryKind, QueryResponse,
};
use etd_testkit::fakes::host::{FakeHostClient, HostCall, MutationReply};
use etd_testkit::fakes::launcher::{FakeHostLauncher, LauncherCall};
use etd_testkit::fakes::profiles::FakeProfileStore;
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

struct Factory {
    host: Arc<FakeHostClient>,
    targets: Mutex<Vec<HostTarget>>,
}

impl HostClientFactory for Factory {
    fn connect(&self, target: &HostTarget) -> Arc<dyn HostClient> {
        self.targets.lock().unwrap().push(target.clone());
        self.host.clone()
    }
}

struct App {
    host: Arc<FakeHostClient>,
    factory: Arc<Factory>,
    launcher: Arc<FakeHostLauncher>,
    profiles: Arc<FakeProfileStore>,
    bridge: AppBridge,
    runtime: Option<AppRuntime>,
    last: StateStore,
}

fn config() -> BridgeConfig {
    BridgeConfig {
        retry_min: Duration::from_millis(5),
        retry_max: Duration::from_millis(20),
        call_timeout: Duration::from_millis(500),
        recovery_attempts: 3,
        query_interval: Duration::from_millis(10),
        relaunch_after: 2,
        drain_timeout: Duration::from_millis(500),
        release_timeout: Duration::from_millis(300),
        shutdown_timeout: Duration::from_millis(500),
    }
}

impl App {
    fn start(mode: HostMode) -> Self {
        Self::with(mode, Arc::new(FakeProfileStore::default()))
    }

    fn with(mode: HostMode, profiles: Arc<FakeProfileStore>) -> Self {
        let host = Arc::new(FakeHostClient::new(mode));
        let factory = Arc::new(Factory {
            host: host.clone(),
            targets: Mutex::default(),
        });
        let launcher = Arc::new(FakeHostLauncher::default());
        let services = AppServices {
            clients: factory.clone(),
            launcher: launcher.clone(),
            profiles: profiles.clone(),
        };
        let (bridge, runtime) = AppRuntime::start(services, config()).unwrap();
        Self {
            host,
            factory,
            launcher,
            profiles,
            bridge,
            runtime: Some(runtime),
            last: StateStore::default(),
        }
    }

    /// Connected to a host holding these instances.
    fn connected(mode: HostMode, instances: &[(u32, Desired, InstanceState)]) -> Self {
        let mut app = Self::start(mode);
        app.host.set_snapshot(snapshot(
            1,
            0,
            instances
                .iter()
                .map(|(n, wanted, state)| view(*n, *wanted, *state))
                .collect(),
        ));
        app.connect(mode);
        app
    }

    fn connect(&mut self, mode: HostMode) {
        self.send(UserCommand::Connect(mode));
        self.wait("connected and subscribed", |app, s| {
            s.link == HostLink::Connected
                && s.sync == SyncState::Synced
                && app.host.subscriber_count() == 1
        });
    }

    fn send(&self, command: UserCommand) {
        self.bridge.commands.try_send(command).unwrap();
    }

    #[track_caller]
    fn wait(&mut self, what: &str, done: impl Fn(&Self, &StateStore) -> bool) -> StateStore {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(state) = self.bridge.states.try_recv() {
                self.last = state;
            }
            if done(self, &self.last) {
                return self.last.clone();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {:#?}\ncalls: {:#?}",
                self.last,
                self.host.calls()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[track_caller]
    fn wait_condition(&mut self, n: u32, condition: InstanceCondition) -> StateStore {
        self.wait(&format!("instance {n} {condition:?}"), |_, s| {
            s.instance(&InstanceId(id(n)))
                .is_some_and(|e| e.condition() == condition)
        })
    }

    /// Waits until the `index`-th operation has a status `done` accepts.
    #[track_caller]
    fn wait_operation(
        &mut self,
        index: usize,
        what: &str,
        done: impl Fn(&OperationStatus) -> bool,
    ) -> StateStore {
        self.wait(what, |_, s| {
            s.operations.get(index).is_some_and(|op| done(&op.status))
        })
    }

    fn exit(&mut self) -> ExitReport {
        let mut runtime = self.runtime.take().unwrap();
        let quit = std::cell::Cell::new(false);
        let report = block_on(ExitGate::new(ExitDeadlines::default()).run(
            &mut runtime,
            LeaseRelease::StopInstances,
            || quit.set(true),
        ))
        .unwrap();
        assert!(quit.get());
        report
    }

    fn snapshots(&self) -> usize {
        self.host
            .calls()
            .iter()
            .filter(|c| **c == HostCall::Snapshot)
            .count()
    }
}

/// The gate must not need tokio, so the tests do not give it one.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

fn accepted(status: &OperationStatus) -> bool {
    matches!(status, OperationStatus::Accepted(_))
}

fn failed(status: &OperationStatus) -> bool {
    matches!(status, OperationStatus::Failed(_))
}

fn unconfirmed(status: &OperationStatus) -> bool {
    matches!(status, OperationStatus::Unconfirmed(_))
}

fn stop(n: u32) -> UserCommand {
    UserCommand::SetDesired {
        instance: InstanceId(id(n)),
        desired: Desired::Stopped,
    }
}

fn start(n: u32) -> UserCommand {
    UserCommand::SetDesired {
        instance: InstanceId(id(n)),
        desired: Desired::Running,
    }
}

fn expected_revision(call: &HostCall) -> u64 {
    match call {
        HostCall::SetDesired(r) => r.header.as_ref().unwrap().expected_revision,
        HostCall::Apply(r) => r.header.as_ref().unwrap().expected_revision,
        other => panic!("{other:?}"),
    }
}

fn lost() -> CallError {
    CallError::Unavailable("connection reset".into())
}

const RUNNING: (u32, Desired, InstanceState) = (1, Desired::Running, InstanceState::ReadyFull);

#[test]
fn events_reach_the_ui_and_reconnecting_keeps_the_data() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host
        .emit(etd_contract::v1::event::Payload::InstanceStatus(status(
            1,
            InstanceState::Backoff,
        )));
    app.wait_condition(1, InstanceCondition::Backoff);

    app.host.reconnecting(1);
    let state = app.wait("reconnecting", |_, s| s.is_reconnecting());
    assert_eq!(state.instances.len(), 1);
    app.host.reconnected();
    app.wait("back", |_, s| s.link == HostLink::Connected);
    app.exit();
}

#[test]
fn a_gap_or_a_new_host_run_takes_a_new_snapshot() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    let first = app.snapshots();
    app.host.update_snapshot(|s| {
        s.instances = vec![view(1, Desired::Stopped, InstanceState::Stopped)];
    });
    app.host.skip_event();
    app.host
        .emit(etd_contract::v1::event::Payload::InstanceStatus(status(
            1,
            InstanceState::Backoff,
        )));
    app.wait_condition(1, InstanceCondition::Stopped);
    assert!(app.snapshots() > first);

    app.host.update_snapshot(|s| {
        s.instances = vec![view(1, Desired::Running, InstanceState::Starting)];
    });
    app.host.restart_host("second-run");
    app.wait_condition(1, InstanceCondition::Starting);

    // A broken stream alone also leads to a fresh snapshot.
    app.host.update_snapshot(|s| {
        s.instances = vec![view(1, Desired::Running, InstanceState::GaveUp)];
    });
    app.host.fail_streams(CallError::Transport("broken".into()));
    app.wait_condition(1, InstanceCondition::GaveUp);
    app.exit();
}

#[test]
fn mutations_go_one_at_a_time_with_the_latest_revision() {
    let mut app = App::connected(
        HostMode::Service,
        &[RUNNING, (2, Desired::Running, InstanceState::ReadyFull)],
    );
    app.send(stop(1));
    app.send(stop(2));
    let state = app.wait("both accepted", |_, s| {
        s.operations.len() == 2 && s.operations.iter().all(|op| accepted(&op.status))
    });
    assert_eq!(state.revision, 3);
    let revisions: Vec<_> = app.host.mutations().iter().map(expected_revision).collect();
    assert_eq!(revisions, [1, 2]);
    app.exit();
}

#[test]
fn a_conflict_is_reported_not_overridden() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    // Someone else changed something this client has not heard of.
    app.host.update_snapshot(|s| s.revision = 9);
    app.send(stop(1));
    let state = app.wait("conflict and resync", |_, s| {
        s.operations.first().is_some_and(|op| failed(&op.status)) && s.revision == 9
    });
    let OperationStatus::Failed(failure) = &state.operations[0].status else {
        unreachable!()
    };
    assert_eq!(failure.code(), Some(ErrorCode::RevisionConflict));
    thread::sleep(Duration::from_millis(50));
    assert_eq!(app.host.mutations().len(), 1);
    app.exit();
}

#[test]
fn a_lost_reply_is_recovered_by_receipt_without_resending() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.script(MutationReply::LoseReply(lost()));
    app.send(stop(1));
    app.wait_operation(0, "recovered", accepted);
    assert_eq!(app.host.mutations().len(), 1);
    assert_eq!(app.host.committed_count(), 1);
    app.exit();
}

#[test]
fn a_request_that_never_arrived_is_resent_unchanged() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.script(MutationReply::Reject(lost()));
    app.send(stop(1));
    app.wait_operation(0, "accepted", accepted);
    let sent = app.host.mutations();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1], "same id, same revision, same content");
    assert_eq!(app.host.committed_count(), 1);
    app.exit();
}

#[test]
fn an_unconfirmed_request_is_looked_up_after_reconnecting() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.script(MutationReply::LoseReply(lost()));
    for _ in 0..3 {
        app.host.fail_receipt_lookup(lost());
    }
    app.send(start(1));
    app.wait_operation(0, "unconfirmed", unconfirmed);

    app.host.reconnecting(1);
    app.wait("reconnecting", |_, s| s.is_reconnecting());
    app.host.reconnected();
    app.wait_operation(0, "found", accepted);
    assert_eq!(app.host.mutations().len(), 1, "looked up, not resent");
    app.exit();
}

#[test]
fn retrying_an_unconfirmed_request_cannot_apply_it_twice() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.script(MutationReply::LoseReply(lost()));
    for _ in 0..3 {
        app.host.fail_receipt_lookup(lost());
    }
    app.send(start(1));
    let state = app.wait_operation(0, "unconfirmed", unconfirmed);
    app.send(UserCommand::RetryOperation(
        state.operations[0].request_id.clone(),
    ));
    app.wait_operation(0, "accepted", accepted);
    let sent = app.host.mutations();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
    assert_eq!(app.host.committed_count(), 1);
    app.exit();
}

fn ledger_unavailable() -> CallError {
    CallError::Rejected(ErrorDetail {
        code: ErrorCode::LedgerUnavailable as i32,
        message: "ledger unavailable".into(),
        ..ErrorDetail::default()
    })
}

/// "Retry confirm" resends the very stop that could not be recorded.
#[test]
fn retry_confirm_resends_the_same_stop() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.script(MutationReply::Reject(ledger_unavailable()));
    app.send(stop(1));
    app.wait_operation(0, "rejected", failed);
    app.host
        .emit(etd_contract::v1::event::Payload::InstanceStatus(status(
            1,
            InstanceState::CutUnconfirmed,
        )));
    let state = app.wait_condition(1, InstanceCondition::CutUnconfirmed);
    assert!(
        state
            .instance(&InstanceId(id(1)))
            .unwrap()
            .needs_stop_confirm()
    );

    app.send(UserCommand::RetryConfirmStop(InstanceId(id(1))));
    app.wait_operation(0, "confirmed", accepted);
    let sent = app.host.mutations();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
    assert_eq!(app.last.operations.len(), 1);
    app.exit();
}

#[test]
fn retry_confirm_without_an_earlier_request_sends_a_new_stop() {
    let mut app = App::connected(
        HostMode::Service,
        &[(1, Desired::Running, InstanceState::CutUnconfirmed)],
    );
    app.send(UserCommand::RetryConfirmStop(InstanceId(id(1))));
    let state = app.wait_operation(0, "accepted", accepted);
    assert_eq!(state.operations[0].kind, OperationKind::Stop);
    assert!(matches!(
        &app.host.mutations()[..],
        [HostCall::SetDesired(r)] if r.desired() == Desired::Stopped
    ));
    app.exit();
}

/// A click while the host is away fails at once instead of running later.
#[test]
fn nothing_is_queued_while_disconnected() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.reconnecting(1);
    app.wait("reconnecting", |_, s| s.is_reconnecting());
    app.send(stop(1));
    app.wait_operation(0, "failed", failed);
    app.host.reconnected();
    app.wait("back", |_, s| s.link == HostLink::Connected);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(app.host.mutations(), []);
    app.exit();
}

#[test]
fn the_secret_goes_to_the_host_and_nowhere_else() {
    let mut app = App::connected(HostMode::Service, &[]);
    let mut spec = NetworkSpec {
        network_name: "office".into(),
        ..NetworkSpec::default()
    };
    // Even a secret put into the spec by mistake is dropped.
    spec.network_secret = Some("misplaced".into());
    let draft = ApplyDraft::create(spec, SecretInput::Set(Secret::new("hunter2")));
    let command = UserCommand::Apply(Box::new(draft.clone()));
    let printed = format!("{command:?}");
    assert!(!printed.contains("hunter2") && !printed.contains("misplaced"));
    app.send(command);
    let state = app.wait_operation(0, "applied", accepted);
    app.wait("profile saved", |app, _| !app.profiles.saved().is_empty());

    let edit = |secret| {
        UserCommand::Apply(Box::new(ApplyDraft {
            secret,
            ..draft.clone()
        }))
    };
    app.send(edit(SecretInput::Keep));
    app.send(edit(SecretInput::Clear));
    app.wait("three applied", |_, s| {
        s.operations.len() == 3 && s.operations.iter().all(|op| accepted(&op.status))
    });
    let secrets: Vec<_> = app
        .host
        .mutations()
        .into_iter()
        .map(|call| match call {
            HostCall::Apply(r) => r.spec.unwrap().network_secret,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(secrets, [Some("hunter2".into()), None, Some(String::new())]);
    for dump in [
        format!("{state:?}"),
        format!("{:?}", app.last),
        format!("{:?}", app.profiles.saved()),
    ] {
        assert!(
            !dump.contains("hunter2") && !dump.contains("misplaced"),
            "{dump}"
        );
    }
    assert_eq!(app.profiles.profiles().len(), 1);
    app.exit();
}

#[test]
fn removing_can_forget_the_profile_once_accepted() {
    let profiles = Arc::new(FakeProfileStore::new(vec![Profile {
        instance_id: InstanceId(id(1)),
        spec: NetworkSpec::default(),
        updated_at: jiff::Timestamp::UNIX_EPOCH,
    }]));
    let mut app = App::with(HostMode::Service, profiles);
    app.host.set_snapshot(snapshot(
        1,
        0,
        vec![view(1, Desired::Stopped, InstanceState::Stopped)],
    ));
    app.connect(HostMode::Service);
    assert_eq!(app.last.profiles.len(), 1);

    let remove = || UserCommand::Remove {
        instance: InstanceId(id(1)),
        forget_profile: true,
    };
    app.host
        .script(MutationReply::Reject(CallError::ElevationRequired));
    app.send(remove());
    app.wait_operation(0, "rejected", failed);
    assert_eq!(app.profiles.profiles().len(), 1);

    app.send(remove());
    app.wait_operation(1, "accepted", accepted);
    app.wait("profile gone", |app, s| {
        s.profiles.is_empty() && app.profiles.profiles().is_empty()
    });
    app.exit();
}

#[test]
fn profile_failures_are_visible_and_never_overwrite_the_library() {
    let profiles = Arc::new(FakeProfileStore::default());
    profiles.fail_load(ProfileError::Corrupt("bad file".into()));
    let mut app = App::with(HostMode::Service, profiles);
    app.send(UserCommand::SaveProfile {
        instance_id: InstanceId(id(1)),
        spec: SecretFreeSpec::new(NetworkSpec::default()),
    });
    app.wait("load error", |_, s| s.profile_error.is_some());
    app.exit();
    assert!(app.profiles.saved().is_empty());

    let mut app = App::start(HostMode::Service);
    app.profiles.fail_save(ProfileError::Io("disk full".into()));
    let save = |n| UserCommand::SaveProfile {
        instance_id: InstanceId(id(n)),
        spec: SecretFreeSpec::new(NetworkSpec::default()),
    };
    app.send(save(1));
    app.wait("save error", |_, s| {
        s.profile_error
            .as_ref()
            .is_some_and(|e| e.contains("disk full"))
    });
    app.send(save(2));
    app.wait("recovered", |_, s| s.profile_error.is_none());
    assert_eq!(app.profiles.profiles().len(), 2);
    app.exit();
}

#[test]
fn watched_pages_follow_capabilities_and_stop() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.host.set_query(
        QueryKind::Nodes,
        Ok(QueryResponse {
            result: Some(query_response::Result::Nodes(NodeList {
                nodes: vec![Node {
                    peer_id: 7,
                    ..Node::default()
                }],
            })),
            at_unix_ms: 1,
        }),
    );
    app.host.set_query(
        QueryKind::Routes,
        Err(CallError::Rejected(ErrorDetail {
            code: ErrorCode::ManagementUnavailable as i32,
            ..ErrorDetail::default()
        })),
    );
    app.send(UserCommand::Watch(Some(InstanceId(id(1)))));
    let state = app.wait("pages", |_, s| {
        s.watched
            .as_ref()
            .is_some_and(|w| w.nodes.is_some() && !w.errors.is_empty())
    });
    let watched = state.watched.unwrap();
    assert_eq!(watched.nodes.unwrap()[0].peer_id, 7);
    assert_eq!(watched.errors[0].0, QueryKind::Routes);

    app.send(UserCommand::Watch(None));
    app.wait("unwatched", |_, s| s.watched.is_none());
    thread::sleep(Duration::from_millis(30));
    let queries = |app: &App| {
        app.host
            .calls()
            .iter()
            .filter(|c| matches!(c, HostCall::Query(..)))
            .count()
    };
    let before = queries(&app);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(queries(&app), before);
    app.exit();
}

#[test]
fn watching_a_removed_instance_stops_polling() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    app.send(UserCommand::Watch(Some(InstanceId(id(1)))));
    app.wait("watching", |app, s| {
        s.watched.is_some()
            && app
                .host
                .calls()
                .iter()
                .any(|c| matches!(c, HostCall::Query(..)))
    });
    app.host.emit(removed(1, 2));
    app.wait("dropped", |_, s| {
        s.watched.is_none() && s.instances.is_empty()
    });
    thread::sleep(Duration::from_millis(30));
    let calls = app.host.calls().len();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(app.host.calls().len(), calls);
    app.exit();
}

#[test]
fn probing_and_launch_failures() {
    let mut app = App::start(HostMode::Service);
    app.send(UserCommand::AutoConnect);
    app.wait("no host", |_, s| s.link == HostLink::NoHost);

    app.launcher.script_ensure(Err(LaunchError::NotInstalled));
    app.send(UserCommand::Connect(HostMode::Service));
    app.wait("not installed", |_, s| {
        matches!(&s.link, HostLink::LaunchFailed(f) if f.kind == LaunchFailureKind::NotInstalled)
    });
    assert!(app.factory.targets.lock().unwrap().is_empty());

    app.launcher
        .script_probe(Ok(Some(FakeHostLauncher::target(HostMode::Service))));
    app.send(UserCommand::AutoConnect);
    app.wait("connected", |_, s| s.link == HostLink::Connected);
    assert_eq!(
        app.launcher.calls(),
        [
            LauncherCall::Probe,
            LauncherCall::Ensure(HostMode::Service),
            LauncherCall::Probe
        ]
    );
    app.exit();
}

#[test]
fn a_vanished_user_host_is_started_again() {
    let mut app = App::connected(HostMode::User, &[]);
    let ensures = |app: &App| {
        app.launcher
            .calls()
            .iter()
            .filter(|c| **c == LauncherCall::Ensure(HostMode::User))
            .count()
    };
    assert_eq!(ensures(&app), 1);
    app.host.reconnecting(1);
    app.wait("first retry", |_, s| s.is_reconnecting());
    thread::sleep(Duration::from_millis(30));
    assert_eq!(ensures(&app), 1, "one blip does not relaunch");
    app.host.reconnecting(2);
    app.wait("relaunch", |app, _| ensures(app) == 2);
    // Same endpoint: the same client keeps reconnecting.
    assert_eq!(app.factory.targets.lock().unwrap().len(), 1);
    app.exit();

    let mut app = App::connected(HostMode::Service, &[]);
    app.host.reconnecting(9);
    app.wait("reconnecting", |_, s| s.is_reconnecting());
    thread::sleep(Duration::from_millis(30));
    assert_eq!(app.launcher.calls().len(), 1, "the service manager's job");
    app.exit();
}

#[test]
fn an_impostor_is_named_while_reconnecting() {
    let mut app = App::connected(HostMode::Service, &[]);
    app.host
        .set_down_reason(CallError::HostNotVerified("wrong image".into()));
    app.host.reconnecting(1);
    app.wait("flagged", |_, s| {
        s.unverified_host.as_deref() == Some("wrong image")
    });
    app.host.reconnected();
    app.wait("cleared", |_, s| s.unverified_host.is_none());
    app.exit();
}

const ORDER: [ExitPhase; 4] = [
    ExitPhase::SettleInstances,
    ExitPhase::StopSubscriptions,
    ExitPhase::StopRuntime,
    ExitPhase::QuitUi,
];

fn releases(app: &App) -> Vec<LeaseRelease> {
    app.host
        .calls()
        .iter()
        .filter_map(|c| match c {
            HostCall::ReleaseLease(release) => Some(*release),
            _ => None,
        })
        .collect()
}

#[test]
fn exiting_a_user_host_session_releases_the_lease_in_order() {
    let mut app = App::connected(HostMode::User, &[RUNNING]);
    app.send(UserCommand::Watch(Some(InstanceId(id(1)))));
    let started = Instant::now();
    let report = app.exit();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.phases(), ORDER);
    assert_eq!(report.errors().count(), 0, "{report:?}");
    assert_eq!(releases(&app), [LeaseRelease::StopInstances]);
    assert_eq!(app.host.subscriber_count(), 0, "subscriptions stopped");
    // The runtime is gone: commands go nowhere and the state channel closed.
    assert!(app.bridge.commands.try_send(UserCommand::Refresh).is_err());
    while app.bridge.states.try_recv().is_ok() {}
    assert!(app.bridge.states.is_closed());
}

#[test]
fn exiting_a_service_session_only_disconnects() {
    let mut app = App::connected(HostMode::Service, &[RUNNING]);
    let report = app.exit();
    assert_eq!(report.phases(), ORDER);
    assert_eq!(report.errors().count(), 0, "{report:?}");
    assert_eq!(releases(&app), []);
    assert_eq!(app.host.mutations(), [], "instances keep running");
}

#[test]
fn a_host_that_never_answers_cannot_hold_the_exit() {
    let mut app = App::connected(HostMode::User, &[RUNNING]);
    app.host.hang_release();
    app.host.script(MutationReply::Hang);
    app.send(stop(1));
    app.wait("sending", |app, _| !app.host.mutations().is_empty());
    let started = Instant::now();
    let report = app.exit();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.phases(), ORDER);
    let errors: Vec<_> = report.errors().map(|(phase, _)| phase).collect();
    assert_eq!(errors, [ExitPhase::SettleInstances]);
}

#[test]
fn what_was_clicked_before_exit_is_still_done() {
    let mut app = App::connected(HostMode::User, &[RUNNING]);
    app.send(stop(1));
    app.send(UserCommand::SaveProfile {
        instance_id: InstanceId(id(1)),
        spec: SecretFreeSpec::new(NetworkSpec::default()),
    });
    let report = app.exit();
    assert_eq!(report.errors().count(), 0, "{report:?}");
    assert_eq!(app.host.committed_count(), 1);
    assert_eq!(app.profiles.profiles().len(), 1);
    // The stop was accepted before the lease went back.
    let calls = app.host.calls();
    let position = |wanted: fn(&HostCall) -> bool| calls.iter().position(wanted).unwrap();
    assert!(position(HostCall::is_mutation) < position(|c| matches!(c, HostCall::ReleaseLease(_))));
}

#[test]
fn exiting_an_elevated_session_releases_the_lease() {
    let mut app = App::connected(HostMode::ElevatedSession, &[RUNNING]);
    let report = app.exit();
    assert_eq!(report.phases(), ORDER);
    assert_eq!(report.errors().count(), 0, "{report:?}");
    assert_eq!(releases(&app), [LeaseRelease::StopInstances]);
}

/// doc#13 #sequence outcome 3: a lost session host is reported, never
/// restarted on its own (that would be an unrequested UAC prompt).
#[test]
fn a_vanished_session_host_is_reported_not_restarted() {
    let mut app = App::connected(HostMode::ElevatedSession, &[]);
    app.host.reconnecting(1);
    app.wait("first retry", |_, s| s.is_reconnecting());
    thread::sleep(Duration::from_millis(30));
    assert!(!app.last.session_host_exited, "one blip is not an exit");
    app.host.reconnecting(5);
    app.wait("exited", |_, s| s.session_host_exited);
    thread::sleep(Duration::from_millis(30));
    assert_eq!(
        app.launcher.calls(),
        [LauncherCall::Ensure(HostMode::ElevatedSession)],
        "no second start"
    );
    // The host comes back (e.g. started by another Connect): cleared.
    app.host.reconnected();
    app.wait("cleared", |_, s| !s.session_host_exited);
    app.exit();
}

#[test]
fn session_refusals_and_elevation_required_read_as_actions() {
    let mut app = App::start(HostMode::ElevatedSession);
    for (error, kind) in [
        (
            LaunchError::ElevationDenied,
            LaunchFailureKind::ElevationDenied,
        ),
        (
            LaunchError::SessionRefused(etd_app::SessionRefusal::NotConforming),
            LaunchFailureKind::SessionDirectory,
        ),
        (
            LaunchError::SessionRefused(etd_app::SessionRefusal::OtherUsersLeftovers),
            LaunchFailureKind::OtherUsersLeftovers,
        ),
        (
            LaunchError::SessionRefused(etd_app::SessionRefusal::EndpointOccupied),
            LaunchFailureKind::EndpointOccupied,
        ),
        (
            LaunchError::SessionRefused(etd_app::SessionRefusal::ServiceInstalled),
            LaunchFailureKind::ServiceInstalled,
        ),
    ] {
        app.launcher.script_ensure(Err(error));
        app.send(UserCommand::Connect(HostMode::ElevatedSession));
        app.wait("refused", |_, s| {
            matches!(&s.link, HostLink::LaunchFailed(f) if f.kind == kind && f.guidance().is_some())
        });
    }
    app.exit();
    let failure = etd_app::Failure(CallError::ElevationRequired);
    assert_eq!(
        failure.guidance(),
        Some(etd_app::ELEVATION_REQUIRED_GUIDANCE)
    );
    assert_eq!(etd_app::Failure(lost()).guidance(), None);
}

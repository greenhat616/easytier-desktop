//! The background runtime with the real `GrpcHostClient` over in-memory
//! connections to the scripted contract server.
mod common;

use common::*;
use etd_app::{
    AppBridge, AppRuntime, AppServices, BridgeConfig, ExitDeadlines, ExitGate, HostClientFactory,
    HostLink, HostTarget, InstanceCondition, OperationStatus, StateStore, SyncState, UserCommand,
};
use etd_client::{
    HostClient,
    grpc::{ClientOptions, GrpcHostClient},
};
use etd_contract::v1::{LeaseRelease, event::Payload};
use etd_contract::{Desired, HostMode, InstanceId, InstanceState};
use etd_testkit::fakes::launcher::FakeHostLauncher;
use etd_testkit::fakes::profiles::FakeProfileStore;
use etd_testkit::scripted_server::ScriptedHost;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

struct Factory(ScriptedHost);

impl HostClientFactory for Factory {
    fn connect(&self, _: &HostTarget) -> Arc<dyn HostClient> {
        Arc::new(GrpcHostClient::new(
            self.0.connector(),
            ScriptedHost::endpoint(),
            ClientOptions {
                backoff_min: Duration::from_millis(10),
                backoff_max: Duration::from_millis(40),
                recovery_timeout: Duration::from_secs(2),
                ..ClientOptions::default()
            },
        ))
    }
}

struct App {
    host: ScriptedHost,
    bridge: AppBridge,
    runtime: AppRuntime,
    last: StateStore,
    /// Runs the scripted server.
    _server: tokio::runtime::Runtime,
}

impl App {
    fn connected(mode: HostMode) -> Self {
        let server = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let host = {
            let _inside = server.enter();
            ScriptedHost::start()
        };
        host.edit_welcome(|welcome| welcome.host_mode = mode as i32);
        host.set_snapshot(snapshot(
            0,
            0,
            vec![view(1, Desired::Running, InstanceState::ReadyFull)],
        ));
        let services = AppServices {
            clients: Arc::new(Factory(host.clone())),
            launcher: Arc::new(FakeHostLauncher::default()),
            profiles: Arc::new(FakeProfileStore::default()),
        };
        let config = BridgeConfig {
            retry_min: Duration::from_millis(10),
            retry_max: Duration::from_millis(40),
            ..BridgeConfig::default()
        };
        let (bridge, runtime) = AppRuntime::start(services, config).unwrap();
        let mut app = Self {
            host,
            bridge,
            runtime,
            last: StateStore::default(),
            _server: server,
        };
        app.send(UserCommand::Connect(mode));
        app.wait("connected", |app, s| {
            s.link == HostLink::Connected
                && s.sync == SyncState::Synced
                && !app.host.subscriptions().is_empty()
        });
        app
    }

    fn send(&self, command: UserCommand) {
        self.bridge.commands.try_send(command).unwrap();
    }

    #[track_caller]
    fn wait(&mut self, what: &str, done: impl Fn(&Self, &StateStore) -> bool) -> StateStore {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(state) = self.bridge.states.try_recv() {
                self.last = state;
            }
            if done(self, &self.last) {
                return self.last.clone();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {:#?}\ncalls: {:?}",
                self.last,
                self.host.calls()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[track_caller]
    fn wait_condition(&mut self, condition: InstanceCondition) {
        self.wait(&format!("{condition:?}"), |_, s| {
            s.instance(&InstanceId(id(1)))
                .is_some_and(|e| e.condition() == condition)
        });
    }

    fn emit(&self, state: InstanceState) {
        self.host.emit(Payload::InstanceStatus(status(1, state)));
    }

    #[track_caller]
    fn stop_and_expect_accepted(&mut self) {
        self.send(UserCommand::SetDesired {
            instance: InstanceId(id(1)),
            desired: Desired::Stopped,
        });
        self.wait("accepted", |_, s| {
            s.operations
                .last()
                .is_some_and(|op| matches!(op.status, OperationStatus::Accepted(_)))
        });
    }
}

#[test]
fn the_stream_survives_a_dropped_connection_and_a_host_restart() {
    let mut app = App::connected(HostMode::Service);
    app.emit(InstanceState::Backoff);
    app.wait_condition(InstanceCondition::Backoff);

    app.host.set_refusing(true);
    app.host.disconnect();
    let state = app.wait("reconnecting", |_, s| s.is_reconnecting());
    assert_eq!(state.instances.len(), 1);
    app.emit(InstanceState::GaveUp);
    app.host.set_refusing(false);
    app.wait_condition(InstanceCondition::GaveUp);

    app.host.set_snapshot(snapshot(
        0,
        0,
        vec![view(1, Desired::Running, InstanceState::Quarantined)],
    ));
    app.host.restart("stream-2");
    app.wait_condition(InstanceCondition::Quarantined);
    app.emit(InstanceState::Stopped);
    app.wait_condition(InstanceCondition::Stopped);

    app.host.retain_from(100);
    app.host.set_snapshot(snapshot(
        0,
        0,
        vec![view(1, Desired::Running, InstanceState::Waiting)],
    ));
    app.host.end_streams();
    app.wait_condition(InstanceCondition::Waiting);
}

#[test]
fn a_lost_reply_applies_once() {
    let mut app = App::connected(HostMode::Service);
    app.host.lose_next_reply("SetDesired");
    app.stop_and_expect_accepted();
    assert_eq!(app.host.count("SetDesired"), 1);
    assert_eq!(app.host.executed().len(), 1);
}

#[test]
fn a_dropped_request_is_sent_again_and_applies_once() {
    let mut app = App::connected(HostMode::Service);
    app.host.drop_next_request("SetDesired");
    app.stop_and_expect_accepted();
    assert_eq!(app.host.count("SetDesired"), 2);
    assert_eq!(app.host.executed().len(), 1);
}

#[test]
fn an_impostor_is_named() {
    let mut app = App::connected(HostMode::Service);
    app.host.set_impostor(true);
    app.host.disconnect();
    app.wait("flagged", |_, s| s.unverified_host.is_some());
    app.host.set_impostor(false);
    app.wait("cleared", |_, s| {
        s.unverified_host.is_none() && s.link == HostLink::Connected
    });
}

#[test]
fn exit_releases_a_user_host_lease_and_is_clean() {
    for (mode, released) in [(HostMode::User, 1), (HostMode::Service, 0)] {
        let mut app = App::connected(mode);
        let started = Instant::now();
        let gate = ExitGate::new(ExitDeadlines::default());
        let helper = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let report = helper
            .block_on(gate.run(&mut app.runtime, LeaseRelease::StopInstances, || {}))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(report.errors().count(), 0, "{report:?}");
        assert_eq!(app.host.count("ReleaseLease"), released);
    }
}

//! GPUI view-binding tests for `etd-ui` (package U1).
//!
//! Runs real `MainView` + `UiController` inside GPUI's `TestAppContext` headless
//! window to verify bindings against `etd_app::StateStore`, `AppRuntime`,
//! `WindowTray`, `ExitGate`, capability-gated pages, secret non-storage,
//! suggested 11010 listeners (without faketcp), reclaim per-item confirmation,
//! banners, `NotInstalled`, and elevated user-host refusal.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use etd_app::{
    AppBridge, AppRuntime, AppServices, BridgeConfig, HostClientFactory, HostLauncher, HostLink,
    HostTarget, LaunchFailure, LaunchFailureKind, SUGGESTED_LISTENERS, Secret, SecretInput,
    StateStore, SyncState, TrayBackend, TrayError, TrayEvent, TrayIndicator, TrayMenu, UserCommand,
    window_tray::{WindowAction, WindowInput},
};
use etd_client::HostClient;
use etd_contract::{
    Desired, DesiredInstance, HostMode, HostPhase, InstanceId, InstanceState, InstanceStatus,
    Negotiated, NetworkSpec, ReclaimReport, Role, VERSION_MAJOR, VERSION_MINOR, capability,
    v1::{
        Candidate, CandidateAction, CandidateOrigin, Conflict, InstanceReclaim, ManagementAccess,
        Node, Notice, NoticeLevel, PeerTraffic, ReclaimStatus, Residue, ResidueState, Route,
        TrafficStats,
    },
};
use etd_testkit::fakes::{
    host::{FakeHostClient, HostCall},
    launcher::FakeHostLauncher,
    profiles::FakeProfileStore,
};
use etd_ui::{ElevatedAwareLauncher, MainView, SecretMode, ServiceInstaller, UiController};
use gpui_kit::{
    AppContext as _, Bounds, Point, TestAppContext, WindowBounds, WindowOptions, px, size,
    test::{TestAppContextExt as _, TestWindowExt as _},
};

type TrayUpdates = Arc<Mutex<Vec<(TrayIndicator, String)>>>;

#[derive(Default)]
struct FakeTray {
    unavailable: bool,
    installed: Arc<AtomicBool>,
    removed: Arc<AtomicUsize>,
    updates: TrayUpdates,
    events: VecDeque<TrayEvent>,
}

impl FakeTray {
    fn available() -> (Self, Arc<AtomicUsize>, TrayUpdates) {
        let removed = Arc::new(AtomicUsize::new(0));
        let updates = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                unavailable: false,
                installed: Arc::new(AtomicBool::new(false)),
                removed: removed.clone(),
                updates: updates.clone(),
                events: VecDeque::new(),
            },
            removed,
            updates,
        )
    }

    fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }
}

impl TrayBackend for FakeTray {
    fn install(&mut self, _: &str, _: &TrayMenu) -> Result<(), TrayError> {
        if self.unavailable {
            return Err(TrayError::Unavailable("no tray on test desktop".into()));
        }
        self.installed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn set_indicator(&mut self, indicator: TrayIndicator, tooltip: &str) -> Result<(), TrayError> {
        if !self.installed.load(Ordering::SeqCst) {
            return Err(TrayError::Unavailable("not installed".into()));
        }
        self.updates
            .lock()
            .expect("tray updates lock")
            .push((indicator, tooltip.to_owned()));
        Ok(())
    }

    fn set_menu(&mut self, _: &TrayMenu) -> Result<(), TrayError> {
        Ok(())
    }

    fn try_next_event(&mut self) -> Option<TrayEvent> {
        self.events.pop_front()
    }

    fn remove(&mut self) {
        if self.installed.swap(false, Ordering::SeqCst) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct FakeInstaller {
    calls: Arc<AtomicUsize>,
    result: Result<(), String>,
}

impl FakeInstaller {
    fn ok() -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                calls: calls.clone(),
                result: Ok(()),
            }),
            calls,
        )
    }
}

impl ServiceInstaller for FakeInstaller {
    fn command_preview(&self) -> String {
        "etd-host install --allow-user S-1-5-21-test".into()
    }

    fn install(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

struct TestHarness {
    window: gpui_kit::AnyWindowHandle,
    view: gpui_kit::Entity<MainView>,
    controller: UiController,
    commands_rx: async_channel::Receiver<UserCommand>,
}

impl TestHarness {
    fn new(
        cx: &mut TestAppContext,
        tray: Box<dyn TrayBackend>,
        installer: Arc<dyn ServiceInstaller>,
        is_elevated: bool,
    ) -> Self {
        cx.update(gpui_kit::init);
        let (cmd_tx, cmd_rx) = async_channel::unbounded();
        let (_state_tx, state_rx) = async_channel::bounded(1);
        let bridge = AppBridge {
            commands: cmd_tx,
            states: state_rx,
        };
        let (controller, window, view) = cx.update(|cx| {
            let controller = UiController::new_for_window(
                bridge,
                None,
                tray,
                installer,
                is_elevated,
                std::rc::Rc::new(|_| {}),
                cx,
            );
            let ctrl = controller.clone();
            let bounds = Bounds {
                origin: Point::default(),
                size: size(px(1200.), px(900.)),
            };
            let (window, view) = gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| MainView::new(ctrl, window, cx)),
            )
            .expect("open test window");
            (controller, window, view)
        });
        Self {
            window,
            view,
            controller,
            commands_rx: cmd_rx,
        }
    }

    fn push_store(&self, store: StateStore, cx: &mut TestAppContext) {
        cx.update(|cx| {
            self.controller.apply_store(store, cx);
        });
        cx.update_window(self.window, |_, window, cx| {
            window.render_frame(cx);
        })
        .unwrap();
    }

    fn drain_commands(&self) -> Vec<UserCommand> {
        let mut out = Vec::new();
        while let Ok(cmd) = self.commands_rx.try_recv() {
            out.push(cmd);
        }
        out
    }
}

fn negotiated_with(mode: HostMode, role: Role, caps: &[&str]) -> Negotiated {
    Negotiated {
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        capabilities: caps.iter().map(|s| (*s).to_owned()).collect(),
        role,
        host_mode: mode,
        host_phase: HostPhase::Serving,
        host_build: "test".into(),
        stream_id: "stream-1".into(),
    }
}

fn connected_store(caps: &[&str]) -> StateStore {
    StateStore {
        link: HostLink::Connected,
        negotiated: Some(negotiated_with(HostMode::Service, Role::Admin, caps)),
        sync: SyncState::Synced,
        phase: HostPhase::Serving,
        ..StateStore::default()
    }
}

fn make_entry(
    id: &str,
    name: &str,
    state: InstanceState,
    management: ManagementAccess,
    secret_set: bool,
) -> etd_app::InstanceEntry {
    etd_app::InstanceEntry {
        id: InstanceId(id.to_owned()),
        desired: Some(DesiredInstance {
            instance_id: id.to_owned(),
            spec: Some(NetworkSpec {
                display_name: name.to_owned(),
                network_name: format!("net-{id}"),
                network_secret: None,
                network_secret_set: secret_set,
                ..NetworkSpec::default()
            }),
            desired: if matches!(
                state,
                InstanceState::Stopped | InstanceState::CutUnconfirmed
            ) {
                Desired::Stopped as i32
            } else {
                Desired::Running as i32
            },
        }),
        status: Some(InstanceStatus {
            instance_id: id.to_owned(),
            state: state as i32,
            epoch: 3,
            management: management as i32,
            restart_attempt: if state == InstanceState::GaveUp { 5 } else { 0 },
            interface_name: format!("etd-{id}"),
            addresses: vec!["10.144.144.1/24".into()],
            core_version: "2.7.1".into(),
            ..InstanceStatus::default()
        }),
        last_exit: None,
        notice: if state == InstanceState::Waiting {
            Some(Notice {
                level: NoticeLevel::Warning as i32,
                code: "SINGLE_WRITER_DEFERRED".into(),
                message: "Waiting for Magic DNS held by inst-run".into(),
                instance_id: id.to_owned(),
            })
        } else {
            None
        },
    }
}

#[gpui_kit::test]
fn instance_list_waiting_gave_up_and_cut_unconfirmed_bindings(cx: &mut TestAppContext) {
    let (tray, _, _) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    let mut store = connected_store(&[capability::INSTANCES, capability::TUN]);
    for entry in [
        make_entry(
            "run",
            "Office Mesh",
            InstanceState::ReadyFull,
            ManagementAccess::Available,
            true,
        ),
        make_entry(
            "wait",
            "Deferred Net",
            InstanceState::Waiting,
            ManagementAccess::Pending,
            false,
        ),
        make_entry(
            "gave",
            "Flapping Net",
            InstanceState::GaveUp,
            ManagementAccess::Pending,
            false,
        ),
        make_entry(
            "cut",
            "Unconfirmed Net",
            InstanceState::CutUnconfirmed,
            ManagementAccess::Pending,
            false,
        ),
    ] {
        store.instances.insert(entry.id.clone(), entry);
    }
    harness.push_store(store, cx);
    let _ = harness.drain_commands();

    cx.update_window(harness.window, |_, window, cx| {
        // WAITING, GAVE_UP, and CutUnconfirmed states are all distinctly rendered.
        assert_eq!(window.find("state-waiting-wait").label(), Some("WAITING"));
        assert!(
            window
                .find("waiting-detail-wait")
                .label()
                .unwrap()
                .contains("Magic DNS")
        );
        assert_eq!(window.find("state-gave-up-gave").label(), Some("GAVE_UP"));
        assert_eq!(
            window.find("state-cut-unconfirmed-cut").label(),
            Some("Cut, unconfirmed")
        );

        // Global "Cut, unconfirmed · retry" banner is shown.
        let banner = window.find("banner-cut-unconfirmed");
        assert!(banner.visible());
        assert!(banner.label().unwrap().contains("Cut, unconfirmed · retry"));

        // Action buttons emit the expected UserCommands.
        window.click("btn-retry-start-gave", cx);
        window.click("btn-retry-confirm-cut", cx);
        window.click("btn-stop-run", cx);
    })
    .unwrap();

    let cmds = harness.drain_commands();
    assert!(cmds.contains(&UserCommand::RetryStart(InstanceId("gave".into()))));
    assert!(cmds.contains(&UserCommand::RetryConfirmStop(InstanceId("cut".into()))));
    assert!(cmds.contains(&UserCommand::SetDesired {
        instance: InstanceId("run".into()),
        desired: Desired::Stopped,
    }));
}

#[gpui_kit::test]
fn nodes_routes_traffic_pages_hide_when_capability_absent(cx: &mut TestAppContext) {
    let (tray, _, _) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    // Host exposes ONLY query.nodes (no routes, no traffic).
    let mut store = connected_store(&[capability::INSTANCES, capability::QUERY_NODES]);
    let entry = make_entry(
        "n1",
        "Primary",
        InstanceState::ReadyFull,
        ManagementAccess::Available,
        false,
    );
    store.instances.insert(entry.id.clone(), entry);
    harness.push_store(store.clone(), cx);

    cx.update_window(harness.window, |_, window, _cx| {
        assert!(window.try_find("tab-overview").is_some());
        assert!(window.try_find("tab-nodes").is_some());
        assert!(window.try_find("tab-routes").is_none());
        assert!(window.try_find("tab-traffic").is_none());
    })
    .unwrap();

    // Now advertise all three capabilities and attach watched management data.
    store.negotiated = Some(negotiated_with(
        HostMode::Service,
        Role::Control,
        &[
            capability::INSTANCES,
            capability::QUERY_NODES,
            capability::QUERY_ROUTES,
            capability::QUERY_TRAFFIC,
        ],
    ));
    store.watched = Some(etd_app::WatchedInstance {
        id: InstanceId("n1".into()),
        nodes: Some(vec![Node {
            peer_id: 7,
            hostname: "peer-seven".into(),
            ipv4_cidr: "10.144.144.7/24".into(),
            latency_us: 12_500,
            loss_rate: 0.0,
            nat_type: "FullCone".into(),
            tunnels: vec!["udp".into()],
            ..Node::default()
        }]),
        routes: Some(vec![Route {
            peer_id: 8,
            hostname: "peer-eight".into(),
            ipv4_cidr: "10.144.144.8/24".into(),
            next_hop_peer_id: 7,
            cost: 1,
            path_latency_us: 14_000,
            ..Route::default()
        }]),
        traffic: Some(TrafficStats {
            rx_bytes: 2048,
            tx_bytes: 4096,
            rx_packets: 10,
            tx_packets: 20,
            peers: vec![PeerTraffic {
                peer_id: 7,
                rx_bytes: 2048,
                tx_bytes: 4096,
            }],
        }),
        errors: Vec::new(),
    });
    harness.push_store(store.clone(), cx);

    cx.update_window(harness.window, |_, window, cx| {
        window.click("tab-nodes", cx);
        assert!(
            window
                .find("node-row-7")
                .label()
                .unwrap()
                .contains("peer-seven")
        );

        window.click("tab-routes", cx);
        assert!(
            window
                .find("route-row-8")
                .label()
                .unwrap()
                .contains("peer-eight")
        );

        window.click("tab-traffic", cx);
        assert!(
            window
                .find("traffic-totals")
                .label()
                .unwrap()
                .contains("2.0 KiB")
        );
        assert!(window.try_find("traffic-peer-7").is_some());
    })
    .unwrap();

    // Removing query.traffic hides the tab and returns the view to Overview.
    store.negotiated = Some(negotiated_with(
        HostMode::Service,
        Role::Control,
        &[capability::INSTANCES],
    ));
    harness.push_store(store.clone(), cx);

    cx.update_window(harness.window, |_, window, _cx| {
        assert!(window.try_find("tab-nodes").is_none());
        assert!(window.try_find("tab-routes").is_none());
        assert!(window.try_find("tab-traffic").is_none());
        assert!(window.try_find("page-overview").is_some());
    })
    .unwrap();

    // When host has capability but instance is DenyAll, page shows unavailable notice.
    store.negotiated = Some(negotiated_with(
        HostMode::Service,
        Role::Control,
        &[capability::INSTANCES, capability::QUERY_NODES],
    ));
    store
        .instances
        .get_mut(&InstanceId("n1".into()))
        .unwrap()
        .status
        .as_mut()
        .unwrap()
        .management = ManagementAccess::DenyAll as i32;
    harness.push_store(store, cx);

    cx.update_window(harness.window, |_, window, cx| {
        window.click("tab-nodes", cx);
        assert!(
            window
                .find("page-nodes")
                .label()
                .unwrap()
                .contains("deny-all")
        );
    })
    .unwrap();
}

#[gpui_kit::test]
fn editor_never_stores_secret_and_uses_suggested_11010_listeners_without_faketcp(
    cx: &mut TestAppContext,
) {
    let (tray, _, _) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    let mut store = connected_store(&[capability::INSTANCES, capability::TUN]);
    let existing = make_entry(
        "exist",
        "Existing Net",
        InstanceState::Stopped,
        ManagementAccess::Pending,
        true,
    );
    store.instances.insert(existing.id.clone(), existing);
    harness.push_store(store, cx);
    let _ = harness.drain_commands();

    // 1. Create a new network: enter secret + apply suggested 11010 listeners.
    cx.update_window(harness.window, |_, window, cx| {
        window.click("btn-new-network", cx);
        window.click("editor-display-name", cx);
        window.input("Mesh Alpha", cx);
        window.click("editor-network-name", cx);
        window.input("alpha-net", cx);
        window.click("editor-network-secret", cx);
        window.input("ephemeral-secret-99", cx);
        window.click("btn-suggested-listeners", cx);
        window.click("editor-submit-start", cx);
    })
    .unwrap();

    let cmds = harness.drain_commands();
    let applied = cmds.iter().find_map(|cmd| match cmd {
        UserCommand::Apply(draft) => Some(draft.as_ref()),
        _ => None,
    });
    let draft = applied.expect("expected Apply command");
    assert_eq!(draft.spec.get().display_name, "Mesh Alpha");
    assert_eq!(draft.spec.get().network_name, "alpha-net");
    assert_eq!(draft.spec.get().network_secret, None);
    assert_eq!(
        draft.secret,
        SecretInput::Set(Secret::new("ephemeral-secret-99"))
    );
    assert_eq!(draft.desired, Desired::Running);

    let expected_listeners: Vec<String> = SUGGESTED_LISTENERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(draft.spec.get().listeners, expected_listeners);
    assert!(
        draft
            .spec
            .get()
            .listeners
            .iter()
            .all(|uri| !uri.contains("faketcp")),
        "faketcp must never be in suggested listeners"
    );

    // Secret input must be scrubbed immediately after submit.
    cx.update(|cx| {
        let secret_val = harness.view.read(cx).editor.network_secret.read(cx).value();
        assert!(secret_val.is_empty(), "secret input was not cleared");
    });

    // 2. Edit existing instance with network_secret_set=true: defaults to Keep, empty input.
    cx.update_window(harness.window, |_, window, cx| {
        window.click("btn-edit-exist", cx);
    })
    .unwrap();

    cx.update(|cx| {
        let view = harness.view.read(cx);
        assert_eq!(view.editor.secret_mode, SecretMode::Keep);
        assert!(view.editor.network_secret.read(cx).value().is_empty());
    });

    cx.update_window(harness.window, |_, window, cx| {
        window.click("editor-submit-save", cx);
    })
    .unwrap();

    let edit_cmds = harness.drain_commands();
    let edit_draft = edit_cmds
        .iter()
        .find_map(|cmd| match cmd {
            UserCommand::Apply(draft) => Some(draft.as_ref()),
            _ => None,
        })
        .expect("expected Apply on edit");
    assert_eq!(edit_draft.instance_id, InstanceId("exist".into()));
    assert_eq!(edit_draft.secret, SecretInput::Keep);

    // 3. Edit again and choose Clear Secret.
    cx.update_window(harness.window, |_, window, cx| {
        window.click("btn-edit-exist", cx);
        window.click("secret-mode-clear", cx);
        window.click("editor-submit-save", cx);
    })
    .unwrap();

    let clear_cmds = harness.drain_commands();
    let clear_draft = clear_cmds
        .iter()
        .find_map(|cmd| match cmd {
            UserCommand::Apply(draft) => Some(draft.as_ref()),
            _ => None,
        })
        .expect("expected Apply on clear");
    assert_eq!(clear_draft.secret, SecretInput::Clear);
}

#[gpui_kit::test]
fn reclaim_report_per_item_candidate_confirmation(cx: &mut TestAppContext) {
    let (tray, _, _) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    let mut store = connected_store(&[
        capability::INSTANCES,
        capability::RECLAIM,
        capability::RECLAIM_CANDIDATES,
    ]);
    store.reclaim = ReclaimReport {
        generated_unix_ms: 1000,
        instances: vec![InstanceReclaim {
            instance_id: "q1".into(),
            epoch: 2,
            status: ReclaimStatus::Quarantined as i32,
            residues: vec![Residue {
                effect_id: "eff-1".into(),
                kind: "win.firewall_rule".into(),
                identity: "EasyTier etd-q1 - TCP".into(),
                failures: 5,
                last_error: "access denied".into(),
                state: ResidueState::Failing as i32,
            }],
            reason: "5 consecutive failures".into(),
        }],
        candidates: vec![
            Candidate {
                candidate_id: "cand-1".into(),
                kind: "win.firewall_rule".into(),
                identity: "EasyTier etd-abc - UDP".into(),
                origin: CandidateOrigin::NoCredential as i32,
                instance_id: "q1".into(),
                epoch: 2,
                detail: "planned record without credential".into(),
            },
            Candidate {
                candidate_id: "cand-2".into(),
                kind: "tun.interface".into(),
                identity: "etd-thirdparty".into(),
                origin: CandidateOrigin::PrefixMatch as i32,
                instance_id: String::new(),
                epoch: 0,
                detail: "prefix match only".into(),
            },
        ],
        conflicts: vec![Conflict {
            kind: "tun.interface".into(),
            identity: "etd-q1".into(),
            expected: "LUID=1".into(),
            found: "LUID=2".into(),
            effect_id: "eff-2".into(),
            conflict_id: "conf-1".into(),
        }],
        notes: Vec::new(),
    };
    harness.push_store(store, cx);
    let _ = harness.drain_commands();

    cx.update_window(harness.window, |_, window, cx| {
        window.click("nav-reclaim", cx);
        assert!(window.try_find("candidate-row-cand-1").is_some());
        assert!(window.try_find("candidate-row-cand-2").is_some());
        assert!(window.try_find("conflict-row-conf-1").is_some());

        // Per-item confirmation: Delete cand-1, Keep cand-2, Keep conf-1.
        window.click("candidate-delete-cand-1", cx);
        window.click("candidate-keep-cand-2", cx);
        window.click("conflict-keep-conf-1", cx);
        window.click("btn-submit-candidate-decisions", cx);

        // Retry reclaim for quarantined instance q1.
        window.click("btn-reclaim-retry-q1", cx);
    })
    .unwrap();

    let cmds = harness.drain_commands();
    let decisions = cmds
        .iter()
        .find_map(|cmd| match cmd {
            UserCommand::ResolveCandidates(d) => Some(d.clone()),
            _ => None,
        })
        .expect("expected ResolveCandidates command");
    assert_eq!(decisions.len(), 3);
    assert!(
        decisions
            .iter()
            .any(|d| { d.candidate_id == "cand-1" && d.action() == CandidateAction::Delete })
    );
    assert!(
        decisions
            .iter()
            .any(|d| { d.candidate_id == "cand-2" && d.action() == CandidateAction::Keep })
    );
    assert!(
        decisions
            .iter()
            .any(|d| { d.candidate_id == "conf-1" && d.action() == CandidateAction::Keep })
    );
    assert!(cmds.contains(&UserCommand::RetryReclaim(InstanceId("q1".into()))));
}

#[gpui_kit::test]
fn host_reconnecting_banner_keeps_last_known_data_and_tray_unchanged(cx: &mut TestAppContext) {
    let (tray, _, updates) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    let mut store = connected_store(&[capability::INSTANCES]);
    let entry = make_entry(
        "live",
        "Live Mesh",
        InstanceState::ReadyFull,
        ManagementAccess::Available,
        false,
    );
    store.instances.insert(entry.id.clone(), entry);
    harness.push_store(store.clone(), cx);
    assert_eq!(updates.lock().unwrap().len(), 1);
    assert_eq!(updates.lock().unwrap()[0].0, TrayIndicator::Connected);

    // Host drops into Reconnecting: banner appears, instance stays visible, tray unchanged.
    store.link = HostLink::Reconnecting { attempt: 3 };
    harness.push_store(store, cx);

    cx.update_window(harness.window, |_, window, _cx| {
        let banner = window.find("banner-reconnecting");
        assert!(banner.visible());
        assert!(banner.label().unwrap().contains("attempt 3"));
        assert!(window.try_find("instance-row-live").is_some());
    })
    .unwrap();

    assert_eq!(
        updates.lock().unwrap().len(),
        1,
        "tray indicator must not change while reconnecting"
    );
}

#[gpui_kit::test]
async fn not_installed_offers_service_install_and_connects_on_success(cx: &mut TestAppContext) {
    let (tray, _, _) = FakeTray::available();
    let (installer, install_calls) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, false);

    let store = StateStore {
        link: HostLink::LaunchFailed(LaunchFailure {
            mode: Some(HostMode::Service),
            kind: LaunchFailureKind::NotInstalled,
            message: "no host service is installed".into(),
        }),
        ..StateStore::default()
    };
    harness.push_store(store, cx);
    let _ = harness.drain_commands();

    cx.update_window(harness.window, |_, window, cx| {
        assert!(window.find("banner-not-installed").visible());
        window.click("btn-install-service", cx);
    })
    .unwrap();

    cx.wait_for(harness.window, Duration::from_secs(2), |_, _| {
        install_calls.load(Ordering::SeqCst) == 1
    })
    .await;

    // Wait briefly for the post-install Connect(Service) dispatch on foreground executor.
    cx.run_until_parked();
    let cmds = harness.drain_commands();
    assert!(cmds.contains(&UserCommand::Connect(HostMode::Service)));
}

#[gpui_kit::test]
fn elevated_user_host_refused_offers_the_service(cx: &mut TestAppContext) {
    // 1. Verify ElevatedAwareLauncher refuses User mode when elevated.
    let fake_launcher = Arc::new(FakeHostLauncher::default());
    let elevated_launcher = ElevatedAwareLauncher::new(fake_launcher, true);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let err = rt
        .block_on(elevated_launcher.ensure(HostMode::User))
        .expect_err("elevated user host must be refused");
    assert!(err.to_string().contains("elevated"));

    // 2. Verify UI shows elevated-refused banner offering the system service.
    let (tray, _, _) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(tray), installer, true);

    let store = StateStore {
        link: HostLink::LaunchFailed(LaunchFailure::new(Some(HostMode::User), &err)),
        ..StateStore::default()
    };
    harness.push_store(store, cx);
    let _ = harness.drain_commands();

    cx.update_window(harness.window, |_, window, cx| {
        let banner = window.find("banner-elevated-user-refused");
        assert!(banner.visible());
        assert!(
            banner
                .label()
                .unwrap()
                .contains("Elevated user host refused")
        );
        assert!(window.try_find("btn-offer-service-install").is_some());
        window.click("btn-offer-service-connect", cx);
    })
    .unwrap();

    let cmds = harness.drain_commands();
    assert!(cmds.contains(&UserCommand::Connect(HostMode::Service)));
}

#[gpui_kit::test]
async fn trayless_fallback_keeps_window_and_exit_gate_runs_before_quit(cx: &mut TestAppContext) {
    // Part 1: Without tray (Wayland / GNOME fallback), closing window is vetoed with notice.
    let (installer, _) = FakeInstaller::ok();
    let harness = TestHarness::new(cx, Box::new(FakeTray::unavailable()), installer, false);
    cx.update_window(harness.window, |_, window, cx| {
        window.render_frame(cx);
        assert!(window.try_find("header-no-tray-badge").is_some());
    })
    .unwrap();

    let action = cx.update(|cx| {
        harness
            .controller
            .handle_window_input(WindowInput::CloseRequested, cx)
    });
    assert_eq!(action, Some(WindowAction::KeepWindow));

    cx.update_window(harness.window, |_, window, cx| {
        window.render_frame(cx);
        assert!(window.find("banner-keep-window").visible());
    })
    .unwrap();

    // Part 2: Real AppRuntime + FakeHostClient(User) runs ExitGate (releasing lease,
    // stopping subscriptions/tokio, removing tray) strictly BEFORE invoking quit hook.
    struct StaticFactory(Arc<FakeHostClient>);
    impl HostClientFactory for StaticFactory {
        fn connect(&self, _: &HostTarget) -> Arc<dyn HostClient> {
            self.0.clone()
        }
    }

    let client = Arc::new(FakeHostClient::new(HostMode::User));
    let launcher = Arc::new(FakeHostLauncher::default());
    launcher.script_probe(Ok(Some(FakeHostLauncher::target(HostMode::User))));
    let services = AppServices {
        clients: Arc::new(StaticFactory(client.clone())),
        launcher,
        profiles: Arc::new(FakeProfileStore::default()),
    };
    let (bridge, runtime) = AppRuntime::start(services, BridgeConfig::default()).unwrap();

    let (tray, removed_count, _) = FakeTray::available();
    let quit_called = Arc::new(AtomicBool::new(false));
    let quit_saw_tray_removed = Arc::new(AtomicBool::new(false));
    let quit_flag = quit_called.clone();
    let tray_removed_check = removed_count.clone();
    let saw_removed = quit_saw_tray_removed.clone();
    let (installer2, _) = FakeInstaller::ok();

    let controller = cx.update(|cx| {
        let ctrl = UiController::new_for_window(
            bridge,
            Some(runtime),
            Box::new(tray),
            installer2,
            false,
            std::rc::Rc::new(move |_| {
                saw_removed.store(
                    tray_removed_check.load(Ordering::SeqCst) == 1,
                    Ordering::SeqCst,
                );
                quit_flag.store(true, Ordering::SeqCst);
            }),
            cx,
        );
        ctrl.send_command(UserCommand::Connect(HostMode::User));
        ctrl
    });

    // Wait for background runtime to connect to FakeHostClient.
    for _ in 0..200 {
        if client
            .calls()
            .iter()
            .any(|call| matches!(call, HostCall::Snapshot))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Trigger ExitGate directly via AsyncApp and verify ordering.
    cx.background_executor.allow_parking();
    let mut async_cx = cx.to_async();
    controller.run_exit_gate(&mut async_cx).await;

    assert!(quit_called.load(Ordering::SeqCst), "quit hook must run");
    assert!(
        quit_saw_tray_removed.load(Ordering::SeqCst),
        "tray must be removed before cx.quit()"
    );
    assert!(
        client
            .calls()
            .iter()
            .any(|call| matches!(call, HostCall::ReleaseLease(_))),
        "ExitGate must settle user-host lease before stopping runtime and quitting"
    );
}

#[gpui_kit::test]
fn tray_hide_and_restore_preserves_state_and_exits_from_menu(cx: &mut TestAppContext) {
    cx.update(gpui_kit::init);
    let (cmd_tx, _cmd_rx) = async_channel::unbounded();
    let (_state_tx, state_rx) = async_channel::bounded(1);
    let bridge = AppBridge {
        commands: cmd_tx,
        states: state_rx,
    };

    let (tray, _removed, _updates) = FakeTray::available();
    let (installer, _) = FakeInstaller::ok();
    let quit_called = Arc::new(AtomicBool::new(false));
    let quit_flag = quit_called.clone();

    let controller = cx.update(|cx| {
        UiController::start_with_exit_hook(
            bridge,
            None,
            Box::new(tray),
            None,
            installer,
            false,
            std::rc::Rc::new(move |_| {
                quit_flag.store(true, Ordering::SeqCst);
            }),
            cx,
        )
        .expect("start controller")
    });

    // Window opens at generation 1.
    assert_eq!(controller.window_tray_snapshot().generation(), 1);
    assert_eq!(
        controller.window_tray_snapshot().visibility(),
        etd_app::window_tray::Visibility::Shown
    );

    // Close hides to tray without quitting.
    let close_action =
        cx.update(|cx| controller.handle_window_input(WindowInput::CloseRequested, cx));
    assert_eq!(
        close_action,
        Some(WindowAction::CloseWindow { generation: 1 })
    );
    assert_eq!(
        controller.window_tray_snapshot().visibility(),
        etd_app::window_tray::Visibility::HiddenToTray
    );
    assert!(!quit_called.load(Ordering::SeqCst));

    // Tray activation restores a new window at generation 2.
    let open_action =
        cx.update(|cx| controller.handle_window_input(WindowInput::Tray(TrayEvent::Activated), cx));
    assert_eq!(
        open_action,
        Some(WindowAction::OpenWindow { generation: 2 })
    );
    assert_eq!(
        controller.window_tray_snapshot().visibility(),
        etd_app::window_tray::Visibility::Shown
    );
}

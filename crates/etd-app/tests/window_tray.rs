//! The window/tray state table: single transitions, then convergence under
//! reordered window, tray and host events.
mod common;

use common::*;
use etd_app::reducer::{Reduced, apply_connection, apply_event, apply_snapshot};
use etd_app::window_tray::{
    ExitReason, TrayDriver, TraySummary, Visibility, WindowAction, WindowInput, WindowTray,
    tray_menu, tray_summary,
};
use etd_app::{
    StateStore, SyncState, TrayBackend, TrayError, TrayEvent, TrayIndicator, TrayMenu, menu_id,
};
use etd_client::ConnectionState;
use etd_contract::{Desired, Event, HostMode, HostPhase, InstanceState, Negotiated, Role};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn tray_ready() -> WindowTray {
    let (mut state, first) = WindowTray::new();
    assert_eq!(first, WindowAction::OpenWindow { generation: 1 });
    assert_eq!(state.handle(WindowInput::TrayAvailability(true)), None);
    state
}

fn menu(id: &str) -> WindowInput {
    WindowInput::Tray(TrayEvent::Menu(id.into()))
}

#[test]
fn closing_hides_to_the_tray_and_a_click_restores() {
    let mut state = tray_ready();
    assert_eq!(
        state.handle(WindowInput::CloseRequested),
        Some(WindowAction::CloseWindow { generation: 1 })
    );
    assert_eq!(state.visibility(), Visibility::HiddenToTray);
    assert_eq!(state.handle(WindowInput::CloseRequested), None);
    assert_eq!(
        state.handle(WindowInput::Tray(TrayEvent::Activated)),
        Some(WindowAction::OpenWindow { generation: 2 })
    );
    // The report about the window closed earlier arrives only now.
    assert_eq!(
        state.handle(WindowInput::WindowGone { generation: 1 }),
        None
    );
    assert_eq!(state.visibility(), Visibility::Shown);
    assert_eq!(
        state.handle(menu(menu_id::OPEN)),
        Some(WindowAction::FocusWindow { generation: 2 })
    );
}

#[test]
fn without_a_tray_a_window_stays() {
    let (mut state, _) = WindowTray::new();
    assert_eq!(
        state.handle(WindowInput::CloseRequested),
        Some(WindowAction::KeepWindow)
    );
    assert_eq!(
        state.handle(WindowInput::WindowGone { generation: 1 }),
        Some(WindowAction::OpenWindow { generation: 2 })
    );
}

#[test]
fn losing_the_tray_while_hidden_reopens_the_window() {
    let mut state = tray_ready();
    state.handle(WindowInput::CloseRequested);
    assert_eq!(
        state.handle(WindowInput::TrayAvailability(false)),
        Some(WindowAction::OpenWindow { generation: 2 })
    );
}

#[test]
fn exit_begins_once_from_any_source() {
    for (input, reason) in [
        (menu(menu_id::EXIT), ExitReason::TrayMenu),
        (
            WindowInput::ExitRequested(ExitReason::AppMenu),
            ExitReason::AppMenu,
        ),
        (
            WindowInput::ExitRequested(ExitReason::SessionEnd),
            ExitReason::SessionEnd,
        ),
    ] {
        let mut state = tray_ready();
        state.handle(WindowInput::CloseRequested);
        assert_eq!(state.handle(input), Some(WindowAction::BeginExit(reason)));
        for later in [
            menu(menu_id::EXIT),
            menu(menu_id::OPEN),
            WindowInput::ShowRequested,
            WindowInput::TrayAvailability(false),
        ] {
            assert_eq!(state.handle(later), None);
        }
    }
}

#[test]
fn the_menu_always_offers_open_and_exit() {
    let ids: Vec<_> = tray_menu("Open", "Exit")
        .items
        .into_iter()
        .map(|item| item.id)
        .collect();
    assert_eq!(ids, [menu_id::OPEN, menu_id::EXIT]);
}

// ----------------------------------------------------------- tray driver

#[derive(Default)]
struct FakeTray {
    install_error: Option<TrayError>,
    update_errors: VecDeque<TrayError>,
    shown: Vec<(TrayIndicator, String)>,
    events: VecDeque<TrayEvent>,
    removed: u32,
}

impl TrayBackend for FakeTray {
    fn install(&mut self, _: &str, _: &TrayMenu) -> Result<(), TrayError> {
        self.install_error.take().map_or(Ok(()), Err)
    }
    fn set_indicator(&mut self, indicator: TrayIndicator, tooltip: &str) -> Result<(), TrayError> {
        if let Some(error) = self.update_errors.pop_front() {
            return Err(error);
        }
        self.shown.push((indicator, tooltip.to_owned()));
        Ok(())
    }
    fn set_menu(&mut self, _: &TrayMenu) -> Result<(), TrayError> {
        Ok(())
    }
    fn try_next_event(&mut self) -> Option<TrayEvent> {
        self.events.pop_front()
    }
    fn remove(&mut self) {
        self.removed += 1;
    }
}

#[test]
fn the_driver_reports_availability_and_skips_repeats() {
    let summary = TraySummary {
        indicator: TrayIndicator::Connected,
        tooltip: "1 running".into(),
    };
    let mut driver = TrayDriver::new(FakeTray {
        install_error: Some(TrayError::Unavailable("no host".into())),
        ..FakeTray::default()
    });
    let menu = tray_menu("Open", "Exit");
    assert_eq!(driver.install(&menu), WindowInput::TrayAvailability(false));
    assert_eq!(driver.show(&summary), None);
    assert!(driver.backend().shown.is_empty());

    assert_eq!(driver.install(&menu), WindowInput::TrayAvailability(true));
    driver
        .backend_mut()
        .update_errors
        .push_back(TrayError::Backend("tooltip refused".into()));
    assert_eq!(driver.show(&summary), None, "not fatal");
    assert_eq!(driver.show(&summary), None);
    assert_eq!(driver.show(&summary), None);
    assert_eq!(driver.backend().shown.len(), 1);

    driver.backend_mut().events.push_back(TrayEvent::Activated);
    assert_eq!(driver.poll(), [WindowInput::Tray(TrayEvent::Activated)]);

    driver
        .backend_mut()
        .update_errors
        .push_back(TrayError::Unavailable("explorer is gone".into()));
    let changed = TraySummary {
        indicator: TrayIndicator::Idle,
        ..summary
    };
    assert_eq!(
        driver.show(&changed),
        Some(WindowInput::TrayAvailability(false))
    );
    driver.remove();
    assert_eq!(driver.backend().removed, 1, "removed only once");
}

// ----------------------------------------------------------- indicator

fn connected() -> ConnectionState {
    ConnectionState::Connected(Box::new(Negotiated {
        major: 1,
        minor: 0,
        capabilities: Vec::new(),
        role: Role::Control,
        host_mode: HostMode::Service,
        host_phase: HostPhase::Serving,
        host_build: String::new(),
        stream_id: STREAM.into(),
    }))
}

fn indicator_for(states: &[InstanceState]) -> TrayIndicator {
    let mut store = StateStore::default();
    apply_connection(&mut store, connected());
    let views = states
        .iter()
        .enumerate()
        .map(|(n, state)| view(n as u32, Desired::Running, *state))
        .collect();
    apply_snapshot(&mut store, snapshot(1, 0, views));
    tray_summary(&store).unwrap().indicator
}

#[test]
fn the_indicator_shows_the_worst_instance() {
    use InstanceState::*;
    assert_eq!(indicator_for(&[]), TrayIndicator::Idle);
    assert_eq!(indicator_for(&[Stopped]), TrayIndicator::Idle);
    assert_eq!(indicator_for(&[ReadyBasic]), TrayIndicator::Connected);
    assert_eq!(
        indicator_for(&[ReadyFull, CutUnconfirmed]),
        TrayIndicator::Attention
    );
    assert_eq!(
        indicator_for(&[ReadyFull, Waiting]),
        TrayIndicator::Attention
    );
    assert_eq!(
        indicator_for(&[CutUnconfirmed, Quarantined]),
        TrayIndicator::Error
    );
    assert_eq!(indicator_for(&[GaveUp]), TrayIndicator::Error);
}

#[test]
fn losing_the_host_changes_neither_window_nor_tray() {
    let mut store = StateStore::default();
    apply_connection(&mut store, connected());
    apply_snapshot(
        &mut store,
        snapshot(
            1,
            0,
            vec![view(1, Desired::Running, InstanceState::ReadyFull)],
        ),
    );
    let before = tray_summary(&store).unwrap();
    let mut window = tray_ready();
    window.handle(WindowInput::CloseRequested);
    let window_before = window.clone();
    let mut driver = TrayDriver::new(FakeTray::default());
    driver.install(&tray_menu("Open", "Exit"));
    driver.show(&before);

    for state in [
        ConnectionState::Reconnecting { attempt: 1 },
        ConnectionState::Connecting,
        ConnectionState::Reconnecting { attempt: 7 },
    ] {
        apply_connection(&mut store, state);
        assert!(store.is_reconnecting());
        // No summary: the tray keeps what it shows. The table has no input
        // for the host link at all.
        assert_eq!(tray_summary(&store), None);
    }
    assert_eq!(window, window_before);
    assert_eq!(driver.backend().shown.len(), 1);
}

// ----------------------------------------------------------- convergence

/// What the platform would have on screen, with closing reported late.
#[derive(Default)]
struct Screen {
    open: BTreeSet<u64>,
    unreported: Vec<u64>,
    exits: u32,
}

impl Screen {
    fn perform(&mut self, action: WindowAction) {
        match action {
            WindowAction::OpenWindow { generation } => {
                // A new window replaces one that vanished unreported.
                self.open.insert(generation);
            }
            WindowAction::CloseWindow { generation } => {
                // It may already be gone with its report still on the way.
                if self.open.remove(&generation) {
                    self.unreported.push(generation);
                }
            }
            WindowAction::FocusWindow { .. } | WindowAction::KeepWindow => {}
            WindowAction::BeginExit(_) => self.exits += 1,
        }
    }
}

#[derive(Debug, Clone)]
enum Step {
    Input(WindowInput),
    /// The platform destroys the current window on its own.
    Destroy,
    /// A pending "window gone" report arrives, in any order.
    Report(prop::sample::Index),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        3 => Just(Step::Input(WindowInput::CloseRequested)),
        2 => Just(Step::Input(WindowInput::ShowRequested)),
        2 => Just(Step::Input(WindowInput::Tray(TrayEvent::Activated))),
        1 => Just(Step::Input(menu(menu_id::OPEN))),
        1 => Just(Step::Input(menu("unknown"))),
        3 => any::<bool>().prop_map(|a| Step::Input(WindowInput::TrayAvailability(a))),
        2 => Just(Step::Destroy),
        4 => any::<prop::sample::Index>().prop_map(Step::Report),
    ]
}

const STATES: [InstanceState; 6] = [
    InstanceState::Stopped,
    InstanceState::ReadyFull,
    InstanceState::CutUnconfirmed,
    InstanceState::GaveUp,
    InstanceState::Waiting,
    InstanceState::Starting,
];

proptest! {
    /// In any order: the table and the screen agree, the app is never hidden
    /// without a tray, and once every late report arrived nothing changes.
    #[test]
    fn window_state_converges(steps in prop::collection::vec(step(), 0..60)) {
        let (mut state, first) = WindowTray::new();
        let mut screen = Screen::default();
        screen.perform(first);
        for step in steps {
            let input = match step {
                Step::Input(input) => input,
                Step::Destroy => {
                    if screen.open.remove(&state.generation()) {
                        screen.unreported.push(state.generation());
                    }
                    continue;
                }
                Step::Report(index) => {
                    if screen.unreported.is_empty() {
                        continue;
                    }
                    let at = index.index(screen.unreported.len());
                    WindowInput::WindowGone { generation: screen.unreported.remove(at) }
                }
            };
            if let Some(action) = state.handle(input) {
                screen.perform(action);
            }
            prop_assert!(
                state.visibility() == Visibility::Shown || state.tray_available(),
                "hidden without a tray"
            );
        }
        // Deliver every outstanding report.
        while let Some(generation) = screen.unreported.pop() {
            if let Some(action) = state.handle(WindowInput::WindowGone { generation }) {
                screen.perform(action);
            }
        }
        match state.visibility() {
            Visibility::Shown => {
                prop_assert_eq!(screen.open.iter().copied().collect::<Vec<_>>(), vec![state.generation()]);
            }
            Visibility::HiddenToTray => {
                prop_assert!(screen.open.is_empty());
                prop_assert!(state.tray_available());
            }
        }
        // The user can always get a window back.
        let restore = state.handle(WindowInput::ShowRequested);
        prop_assert!(restore.is_some());
        prop_assert_eq!(state.visibility(), Visibility::Shown);
    }

    /// Exit wins over anything that arrives after it, exactly once.
    #[test]
    fn exit_is_absorbing(
        before in prop::collection::vec(step(), 0..20),
        after in prop::collection::vec(step(), 0..20),
    ) {
        let (mut state, _) = WindowTray::new();
        let mut exits = 0;
        let mut inputs: Vec<WindowInput> = Vec::new();
        let plain = |s: Step| match s { Step::Input(input) => Some(input), _ => None };
        inputs.extend(before.into_iter().filter_map(plain));
        inputs.push(menu(menu_id::EXIT));
        inputs.extend(after.into_iter().filter_map(plain));
        inputs.push(WindowInput::ExitRequested(ExitReason::SessionEnd));
        let mut after_exit = false;
        for input in inputs {
            match state.handle(input) {
                Some(WindowAction::BeginExit(_)) => {
                    exits += 1;
                    after_exit = true;
                }
                action => prop_assert!(!after_exit || action.is_none()),
            }
        }
        prop_assert_eq!(exits, 1);
    }

    /// Host events delivered late, twice, out of order or not at all: with
    /// the snapshots the reducer asks for, store and tray end at the host's
    /// truth.
    #[test]
    fn tray_converges_under_reordered_host_events(
        changes in prop::collection::vec((0u32..4, 0..STATES.len()), 1..30),
        order in prop::collection::vec(any::<prop::sample::Index>(), 0..60),
        reconnect_at in 0usize..60,
    ) {
        // The host's history: truth after each event.
        let mut truth: BTreeMap<u32, InstanceState> =
            (0..4).map(|n| (n, InstanceState::Stopped)).collect();
        let mut history = vec![truth.clone()];
        let mut events: Vec<Event> = Vec::new();
        for (seq, (n, state)) in changes.into_iter().enumerate() {
            truth.insert(n, STATES[state]);
            history.push(truth.clone());
            events.push(state_event(seq as u64 + 1, n, STATES[state]));
        }
        let snapshot_at = |seq: usize| {
            let views = history[seq]
                .iter()
                .map(|(n, state)| view(*n, Desired::Running, *state))
                .collect();
            snapshot(1, seq as u64, views)
        };

        let mut store = StateStore::default();
        apply_connection(&mut store, connected());
        apply_snapshot(&mut store, snapshot_at(0));
        let mut shown = tray_summary(&store).unwrap();
        for (turn, pick) in order.iter().enumerate() {
            if turn == reconnect_at {
                apply_connection(&mut store, ConnectionState::Reconnecting { attempt: 1 });
                prop_assert_eq!(tray_summary(&store), None);
                apply_connection(&mut store, connected());
            }
            let at = pick.index(events.len());
            if let Reduced::Resync(_) = apply_event(&mut store, events[at].clone()) {
                prop_assert_eq!(store.sync, SyncState::Stale);
                prop_assert_eq!(tray_summary(&store), None);
                apply_snapshot(&mut store, snapshot_at(at + 1));
            }
            if let Some(summary) = tray_summary(&store) {
                shown = summary;
            }
            // Whatever is applied is a state the host really had.
            let seq = store.cursor.as_ref().unwrap().seq as usize;
            for (n, state) in &history[seq] {
                let entry = store.instance(&etd_contract::InstanceId(id(*n))).unwrap();
                prop_assert_eq!(entry.condition(), (*state).into());
            }
        }
        // The rest arrives in order.
        for event in events.clone() {
            if let Reduced::Resync(_) = apply_event(&mut store, event) {
                apply_snapshot(&mut store, snapshot_at(events.len()));
            }
        }
        if let Some(summary) = tray_summary(&store) {
            shown = summary;
        }
        let mut expected = StateStore::default();
        apply_connection(&mut expected, connected());
        apply_snapshot(&mut expected, snapshot_at(events.len()));
        prop_assert_eq!(&store.instances, &expected.instances);
        prop_assert_eq!(shown, tray_summary(&expected).unwrap());
    }
}

//! Snapshot + event stream → state store.
mod common;

use common::*;
use etd_app::reducer::{Reduced, ResyncCause, apply_connection, apply_event, apply_snapshot};
use etd_app::{HostLink, InstanceCondition, NOTICE_LIMIT, StateStore, SyncState};
use etd_client::ConnectionState;
use etd_contract::v1::{
    DesiredChanged, HostPhaseChanged, InstanceExited, ManagementAccess, Notice, ResyncRequired,
    event::Payload,
};
use etd_contract::{
    Desired, Event, HostMode, HostPhase, InstanceId, InstanceState, Negotiated, QueryKind,
    ReclaimReport, Role, capability,
};

fn synced(instances: Vec<etd_contract::v1::InstanceView>) -> StateStore {
    let mut store = StateStore::default();
    apply_snapshot(&mut store, snapshot(5, 10, instances));
    store
}

fn condition(store: &StateStore, n: u32) -> InstanceCondition {
    store.instance(&InstanceId(id(n))).unwrap().condition()
}

fn negotiated(stream: &str, capabilities: &[&str]) -> Negotiated {
    Negotiated {
        major: 1,
        minor: 0,
        capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
        role: Role::Control,
        host_mode: HostMode::Service,
        host_phase: HostPhase::Serving,
        host_build: String::new(),
        stream_id: stream.into(),
    }
}

#[test]
fn snapshot_then_events_build_the_store() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::Starting)]);
    assert_eq!((store.revision, store.sync), (5, SyncState::Synced));

    let changes = [
        state_event(11, 1, InstanceState::ReadyBasic),
        state_event(12, 1, InstanceState::ReadyFull),
        event(
            13,
            Payload::DesiredChanged(DesiredChanged {
                revision: 6,
                instance: Some(desired(2, Desired::Stopped)),
                ..DesiredChanged::default()
            }),
        ),
        state_event(14, 2, InstanceState::Stopped),
        event(15, Payload::ReclaimReport(ReclaimReport::default())),
        event(
            16,
            Payload::HostPhase(HostPhaseChanged {
                phase: HostPhase::ShuttingDown as i32,
            }),
        ),
    ];
    for change in changes {
        assert_eq!(apply_event(&mut store, change), Reduced::Changed);
    }
    assert_eq!(condition(&store, 1), InstanceCondition::Running);
    assert_eq!(condition(&store, 2), InstanceCondition::Stopped);
    assert_eq!(store.revision, 6);
    assert_eq!(store.phase, HostPhase::ShuttingDown);
    assert_eq!(store.cursor, Some(cursor(16)));

    assert_eq!(
        apply_event(&mut store, event(17, removed(2, 7))),
        Reduced::Changed
    );
    assert!(store.instance(&InstanceId(id(2))).is_none());
    assert_eq!(store.revision, 7);
}

/// A stop the ledger could not record must never look stopped.
#[test]
fn cut_unconfirmed_is_not_stopped() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::ReadyFull)]);
    apply_event(
        &mut store,
        state_event(11, 1, InstanceState::CutUnconfirmed),
    );
    let entry = store.instance(&InstanceId(id(1))).unwrap();
    assert_eq!(entry.condition(), InstanceCondition::CutUnconfirmed);
    assert_ne!(entry.condition(), InstanceCondition::Stopped);
    assert!(entry.needs_stop_confirm());
    // The stop intent is not durable: the host still wants it running.
    assert_eq!(entry.desired_state(), Desired::Running);

    apply_event(&mut store, state_event(12, 1, InstanceState::Stopped));
    let entry = store.instance(&InstanceId(id(1))).unwrap();
    assert_eq!(entry.condition(), InstanceCondition::Stopped);
    assert!(!entry.needs_stop_confirm());

    // A snapshot reports it just as distinctly.
    let store = synced(vec![view(
        1,
        Desired::Running,
        InstanceState::CutUnconfirmed,
    )]);
    assert_eq!(condition(&store, 1), InstanceCondition::CutUnconfirmed);
}

#[test]
fn deferred_start_shows_waiting_and_its_notice() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::Stopped)]);
    apply_event(
        &mut store,
        event(
            11,
            Payload::Notice(Notice {
                code: "start.deferred".into(),
                message: "waiting for magic_dns, held by another instance".into(),
                instance_id: id(1),
                ..Notice::default()
            }),
        ),
    );
    apply_event(&mut store, state_event(12, 1, InstanceState::Waiting));
    let entry = store.instance(&InstanceId(id(1))).unwrap();
    assert_eq!(entry.condition(), InstanceCondition::Waiting);
    assert_eq!(entry.notice.as_ref().unwrap().code, "start.deferred");
    assert_eq!(store.notices.len(), 1);
}

#[test]
fn every_wire_state_has_its_own_condition() {
    let mut seen = std::collections::BTreeSet::new();
    for raw in 1.. {
        let Ok(state) = InstanceState::try_from(raw) else {
            break;
        };
        let condition = InstanceCondition::from(state);
        assert_ne!(condition, InstanceCondition::Unknown, "{state:?}");
        assert!(seen.insert(condition), "{state:?} shares {condition:?}");
    }
    assert_eq!(seen.len(), 11);
}

#[test]
fn a_state_from_a_newer_host_is_unknown_not_stopped() {
    let mut newer = view(1, Desired::Running, InstanceState::Stopped);
    newer.status.as_mut().unwrap().state = 99;
    let store = synced(vec![newer]);
    assert_eq!(condition(&store, 1), InstanceCondition::Unknown);
}

#[test]
fn duplicates_are_dropped_and_holes_ask_for_a_snapshot() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::Starting)]);
    apply_event(&mut store, state_event(11, 1, InstanceState::ReadyFull));
    assert_eq!(
        apply_event(&mut store, state_event(11, 1, InstanceState::Stopped)),
        Reduced::Ignored
    );
    assert_eq!(
        apply_event(&mut store, state_event(3, 1, InstanceState::Stopped)),
        Reduced::Ignored
    );
    assert_eq!(
        apply_event(&mut store, state_event(13, 1, InstanceState::Stopped)),
        Reduced::Resync(ResyncCause::Gap)
    );
    assert_eq!(condition(&store, 1), InstanceCondition::Running);
    assert_eq!(store.sync, SyncState::Stale);
    // Nothing counts until the new snapshot.
    assert_eq!(
        apply_event(&mut store, state_event(12, 1, InstanceState::Stopped)),
        Reduced::Ignored
    );
    apply_snapshot(
        &mut store,
        snapshot(
            8,
            20,
            vec![view(1, Desired::Stopped, InstanceState::Stopped)],
        ),
    );
    assert_eq!(store.sync, SyncState::Synced);
    assert_eq!(condition(&store, 1), InstanceCondition::Stopped);
}

#[test]
fn resync_requests_and_foreign_streams_are_honoured() {
    let mut store = synced(vec![]);
    let resync = Event {
        cursor: Some(cursor(2)),
        payload: Some(Payload::ResyncRequired(ResyncRequired {
            reason: "not retained".into(),
        })),
        ..Event::default()
    };
    assert_eq!(
        apply_event(&mut store, resync),
        Reduced::Resync(ResyncCause::HostRequested)
    );

    let mut store = synced(vec![]);
    let mut foreign = state_event(11, 1, InstanceState::Stopped);
    foreign.cursor.as_mut().unwrap().stream_id = "other".into();
    assert_eq!(
        apply_event(&mut store, foreign),
        Reduced::Resync(ResyncCause::StreamChanged)
    );

    let mut store = synced(vec![]);
    assert_eq!(
        apply_event(&mut store, Event::default()),
        Reduced::Resync(ResyncCause::Malformed)
    );
}

#[test]
fn an_unknown_payload_still_advances_the_cursor() {
    let mut store = synced(vec![]);
    let newer = Event {
        cursor: Some(cursor(11)),
        ..Event::default()
    };
    assert_eq!(apply_event(&mut store, newer), Reduced::Changed);
    assert_eq!(store.cursor, Some(cursor(11)));
}

#[test]
fn losing_the_host_keeps_the_data() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::ReadyFull)]);
    apply_connection(
        &mut store,
        ConnectionState::Connected(Box::new(negotiated(STREAM, &[]))),
    );
    let instances = store.instances.clone();

    apply_connection(&mut store, ConnectionState::Reconnecting { attempt: 3 });
    assert!(store.is_reconnecting());
    assert_eq!(store.instances, instances);
    assert!(store.negotiated.is_some());
    // The client resumes the stream itself: events keep applying.
    assert_eq!(store.sync, SyncState::Synced);

    apply_connection(&mut store, ConnectionState::Connecting);
    assert!(store.is_reconnecting(), "not a first connection");

    assert_eq!(
        apply_connection(
            &mut store,
            ConnectionState::Connected(Box::new(negotiated("restarted", &[])))
        ),
        Reduced::Resync(ResyncCause::StreamChanged)
    );
    assert_eq!(store.link, HostLink::Connected);
}

#[test]
fn upgrade_required_is_its_own_link() {
    let mut store = StateStore::default();
    apply_connection(
        &mut store,
        ConnectionState::UpgradeRequired {
            host_major: 2,
            host_minor: 1,
        },
    );
    assert_eq!(
        store.link,
        HostLink::UpgradeRequired {
            host_major: 2,
            host_minor: 1
        }
    );
}

#[test]
fn pages_follow_the_capability_list() {
    let mut store = StateStore::default();
    assert!(store.query_pages().is_empty());
    apply_connection(
        &mut store,
        ConnectionState::Connected(Box::new(negotiated(
            STREAM,
            &[capability::QUERY_NODES, capability::QUERY_TRAFFIC],
        ))),
    );
    assert_eq!(store.query_pages(), [QueryKind::Nodes, QueryKind::Traffic]);

    let mut deny_all = view(1, Desired::Running, InstanceState::ReadyBasic);
    deny_all.status.as_mut().unwrap().management = ManagementAccess::DenyAll as i32;
    apply_snapshot(&mut store, snapshot(1, 0, vec![deny_all]));
    let entry = store.instance(&InstanceId(id(1))).unwrap();
    assert!(!entry.management_available());
    assert_eq!(entry.condition(), InstanceCondition::RunningBasic);
}

#[test]
fn a_secret_never_enters_the_store() {
    let mut leaky = view(1, Desired::Running, InstanceState::ReadyFull);
    let spec = leaky.desired.as_mut().unwrap().spec.as_mut().unwrap();
    spec.network_secret = Some("snapshot-secret".into());
    let mut store = synced(vec![leaky]);
    let mut changed = desired(2, Desired::Stopped);
    changed.spec.as_mut().unwrap().network_secret = Some("event-secret".into());
    apply_event(
        &mut store,
        event(
            11,
            Payload::DesiredChanged(DesiredChanged {
                revision: 6,
                instance: Some(changed),
                ..DesiredChanged::default()
            }),
        ),
    );
    let dump = format!("{store:?}");
    assert!(!dump.contains("snapshot-secret"), "{dump}");
    assert!(!dump.contains("event-secret"), "{dump}");
}

#[test]
fn exit_details_stay_with_the_instance_across_snapshots() {
    let mut store = synced(vec![view(1, Desired::Running, InstanceState::ReadyFull)]);
    apply_event(
        &mut store,
        event(
            11,
            Payload::InstanceExited(InstanceExited {
                instance_id: id(1),
                attempt: 5,
                gave_up: true,
                ..InstanceExited::default()
            }),
        ),
    );
    apply_event(&mut store, state_event(12, 1, InstanceState::GaveUp));
    apply_snapshot(
        &mut store,
        snapshot(
            5,
            12,
            vec![view(1, Desired::Running, InstanceState::GaveUp)],
        ),
    );
    let entry = store.instance(&InstanceId(id(1))).unwrap();
    assert!(entry.can_retry_start());
    assert!(entry.last_exit.as_ref().unwrap().gave_up);
}

#[test]
fn notices_are_bounded() {
    let mut store = synced(vec![]);
    for n in 0..(NOTICE_LIMIT as u64 + 10) {
        apply_event(
            &mut store,
            event(
                11 + n,
                Payload::Notice(Notice {
                    code: n.to_string(),
                    ..Notice::default()
                }),
            ),
        );
    }
    assert_eq!(store.notices.len(), NOTICE_LIMIT);
    assert_eq!(store.notices.front().unwrap().notice.code, "10");
}

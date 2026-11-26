//! Backoff reconnect and resumption of the event stream from the last cursor,
//! without gaps or duplicates.
mod common;

use common::*;
use etd_client::{CallError, ConnectionState, HostClient};
use etd_contract::{
    EventCursor, LogLine,
    v1::{StreamLogsRequest, event},
};
use etd_testkit::scripted_server::ScriptedHost;
use proptest::prelude::*;
use std::time::Duration;

fn cursor(stream_id: &str, seq: u64) -> EventCursor {
    EventCursor {
        stream_id: stream_id.into(),
        seq,
    }
}

async fn expect(events: &mut Events, seqs: std::ops::RangeInclusive<u64>) {
    for seq in seqs {
        assert_eq!(next_seq(events).await, seq);
    }
}

#[tokio::test]
async fn dropped_connections_resume_from_the_last_cursor() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));

    host.emit_notice();
    host.emit_notice();
    expect(&mut events, 1..=2).await;

    // Events 3 and 4 happen while the host is unreachable.
    host.set_refusing(true);
    host.disconnect();
    wait_state(&client, |state| {
        matches!(state, ConnectionState::Reconnecting { .. })
    })
    .await;
    assert!(matches!(
        client.snapshot().await,
        Err(CallError::Unavailable(_))
    ));
    host.emit_notice();
    host.emit_notice();
    host.set_refusing(false);
    expect(&mut events, 3..=4).await;

    host.disconnect();
    host.emit_notice();
    expect(&mut events, 5..=5).await;

    assert_eq!(
        host.subscriptions(),
        [0, 2, 4].map(|seq| Some(cursor("stream-1", seq)))
    );
}

#[tokio::test]
async fn subscribing_from_now_loses_nothing_before_the_first_event() {
    let host = ScriptedHost::start();
    host.emit_notice();
    let client = connected(&host).await;
    let mut events = client.subscribe(None);
    // Drive the stream until the host has it, then break it before any event.
    let driver = tokio::spawn(async move {
        let first = next_seq(&mut events).await;
        (first, events)
    });
    until(|| host.subscriptions().len() == 1).await;
    host.set_refusing(true);
    host.disconnect();
    host.emit_notice();
    host.emit_notice();
    host.set_refusing(false);

    let (first, mut events) = driver.await.unwrap();
    assert_eq!(first, 2, "event 1 predates the subscription");
    expect(&mut events, 3..=3).await;
    assert_eq!(host.count("Snapshot"), 1);
    assert!(host.subscriptions().iter().all(Option::is_some));
}

#[tokio::test]
async fn a_subscription_made_before_the_first_connection_waits_for_it() {
    let host = ScriptedHost::start();
    host.set_refusing(true);
    let client = client_with(&host, options());
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    host.emit_notice();
    host.set_refusing(false);
    expect(&mut events, 1..=1).await;
}

#[tokio::test]
async fn events_sent_twice_are_delivered_once() {
    let host = ScriptedHost::start();
    host.replay_overlap(2);
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    for _ in 0..3 {
        host.emit_notice();
    }
    expect(&mut events, 1..=3).await;
    host.disconnect();
    host.emit_notice();
    expect(&mut events, 4..=4).await;
}

#[tokio::test]
async fn a_stream_the_host_ends_cleanly_is_resumed() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    host.emit_notice();
    expect(&mut events, 1..=1).await;
    host.end_streams();
    host.emit_notice();
    expect(&mut events, 2..=2).await;
    assert_eq!(
        host.subscriptions().last(),
        Some(&Some(cursor("stream-1", 1)))
    );
}

async fn assert_resync(events: &mut Events) {
    let last = next(events).await.unwrap().unwrap();
    assert!(
        matches!(last.payload, Some(event::Payload::ResyncRequired(_))),
        "{last:?}"
    );
    assert!(next(events).await.is_none(), "resync ends the stream");
}

#[tokio::test]
async fn a_restarted_host_requires_a_resync() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    host.emit_notice();
    expect(&mut events, 1..=1).await;
    host.restart("stream-2");
    // The new journal numbers below the old cursor: its events must not be
    // mistaken for duplicates.
    assert_resync(&mut events).await;
}

#[tokio::test]
async fn a_cursor_the_host_forgot_requires_a_resync() {
    let host = ScriptedHost::start();
    for _ in 0..5 {
        host.emit_notice();
    }
    host.retain_from(3);
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 1)));
    assert_resync(&mut events).await;
}

#[tokio::test]
async fn a_rejected_subscription_ends_with_the_error() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.fail_next("Subscribe", tonic::Status::unimplemented("no events"));
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    assert!(matches!(
        next(&mut events).await,
        Some(Err(CallError::Transport(_)))
    ));
    assert!(next(&mut events).await.is_none());
}

#[tokio::test(start_paused = true)]
async fn reconnect_delays_grow_up_to_the_ceiling() {
    let host = ScriptedHost::start();
    host.set_refusing(true);
    let mut options = options();
    options.backoff_min = Duration::from_millis(100);
    options.backoff_max = Duration::from_millis(800);
    let client = client_with(&host, options);
    wait_state(
        &client,
        |state| matches!(state, ConnectionState::Reconnecting { attempt } if *attempt >= 7),
    )
    .await;
    let dials = host.dials();
    let delays: Vec<Duration> = dials.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let floors = [100, 200, 400, 800, 800, 800].map(Duration::from_millis);
    for (delay, floor) in delays.iter().zip(floors) {
        // Jitter adds up to the delay itself; timers round up to 1 ms.
        assert!(
            *delay >= floor && *delay <= floor * 2 + Duration::from_millis(2),
            "delays {delays:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn only_a_stable_connection_resets_the_backoff() {
    let host = ScriptedHost::start();
    let mut options = options();
    options.stable_after = Duration::from_secs(5);
    let client = client_with(&host, options);
    let attempt_after_drop = |client_attempt: u32| {
        move |state: &ConnectionState| {
            *state
                == ConnectionState::Reconnecting {
                    attempt: client_attempt,
                }
        }
    };
    for attempt in 1..=3 {
        wait_connected(&client).await;
        host.disconnect();
        wait_state(&client, attempt_after_drop(attempt)).await;
    }
    wait_connected(&client).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    host.disconnect();
    wait_state(&client, attempt_after_drop(1)).await;
}

#[tokio::test(start_paused = true)]
async fn a_handshake_that_hangs_is_abandoned_and_retried() {
    let host = ScriptedHost::start();
    host.hang_next("Handshake");
    let client = client_with(&host, options());
    wait_connected(&client).await;
    assert_eq!(host.count("Handshake"), 2);
}

#[tokio::test]
async fn closing_the_client_ends_streams_and_calls() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    host.emit_notice();
    expect(&mut events, 1..=1).await;
    let waiting = tokio::spawn(async move {
        let item = next(&mut events).await;
        (item, next(&mut events).await)
    });
    host.set_logs(vec![LogLine::default()]);
    let mut lines = client.logs(StreamLogsRequest {
        follow: true,
        ..Default::default()
    });
    assert!(matches!(next(&mut lines).await, Some(Ok(_))));
    host.hang_next("GetReclaimReport");
    let mut state = client.connection();

    let (pending, ()) = tokio::join!(client.reclaim_report(), async {
        until(|| host.count("GetReclaimReport") == 1).await;
        client.close();
    });
    assert!(matches!(pending, Err(CallError::Cancelled)));
    let (item, end) = waiting.await.unwrap();
    assert!(matches!(item, Some(Err(CallError::Cancelled))));
    assert!(end.is_none());
    assert!(matches!(
        next(&mut lines).await,
        Some(Err(CallError::Cancelled))
    ));
    assert!(next(&mut lines).await.is_none());
    assert!(matches!(client.snapshot().await, Err(CallError::Cancelled)));
    assert_eq!(*state.borrow_and_update(), ConnectionState::Closed);
}

#[tokio::test]
async fn dropping_the_client_ends_its_streams() {
    let host = ScriptedHost::start();
    host.set_refusing(true);
    let client = client_with(&host, options());
    let mut events = client.subscribe(None);
    let state = client.connection();
    drop(client);
    assert!(matches!(
        next(&mut events).await,
        Some(Err(CallError::Cancelled))
    ));
    assert_eq!(*state.borrow(), ConnectionState::Closed);
}

#[tokio::test]
async fn a_broken_log_stream_reports_the_break_instead_of_resuming() {
    let host = ScriptedHost::start();
    let client = connected(&host).await;
    host.set_logs(vec![LogLine {
        text: "line".into(),
        ..Default::default()
    }]);

    let mut finite = client.logs(StreamLogsRequest::default());
    assert_eq!(next(&mut finite).await.unwrap().unwrap().text, "line");
    assert!(next(&mut finite).await.is_none());

    let mut followed = client.logs(StreamLogsRequest {
        follow: true,
        ..Default::default()
    });
    assert!(next(&mut followed).await.unwrap().is_ok());
    host.disconnect();
    assert!(matches!(
        next(&mut followed).await,
        Some(Err(CallError::Unavailable(_)))
    ));
    assert!(next(&mut followed).await.is_none());
    assert_eq!(host.count("StreamLogs"), 2);
}

/// One thing happening on the host side while the consumer reads.
#[derive(Debug, Clone)]
enum Action {
    Emit(u8),
    Read(u8),
    Disconnect,
    Outage,
    EndStreams,
}

fn actions() -> impl Strategy<Value = Vec<Action>> {
    let action = prop_oneof![
        4 => (1u8..6).prop_map(Action::Emit),
        4 => (1u8..6).prop_map(Action::Read),
        2 => Just(Action::Disconnect),
        1 => Just(Action::Outage),
        1 => Just(Action::EndStreams),
    ];
    prop::collection::vec(action, 1..30)
}

async fn run(actions: Vec<Action>, overlap: u64) {
    let host = ScriptedHost::start();
    host.replay_overlap(overlap);
    let client = connected(&host).await;
    let mut events = client.subscribe(Some(cursor("stream-1", 0)));
    let (mut emitted, mut read) = (0, 0);
    for action in actions {
        match action {
            Action::Emit(count) => {
                for _ in 0..count {
                    emitted = host.emit_notice();
                }
            }
            Action::Read(count) => {
                for _ in 0..count {
                    if read < emitted {
                        read += 1;
                        assert_eq!(next_seq(&mut events).await, read);
                    }
                }
            }
            Action::Disconnect => host.disconnect(),
            // Unreachable for a while without losing the journal.
            Action::Outage => {
                host.set_refusing(true);
                host.disconnect();
                tokio::time::sleep(Duration::from_millis(15)).await;
                host.set_refusing(false);
            }
            Action::EndStreams => host.end_streams(),
        }
    }
    emitted = emitted.max(host.emit_notice());
    while read < emitted {
        read += 1;
        assert_eq!(next_seq(&mut events).await, read);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn every_event_arrives_exactly_once_in_order(actions in actions(), overlap in 0u64..3) {
        // Paused time: backoff delays cost nothing.
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(run(actions, overlap));
    }
}

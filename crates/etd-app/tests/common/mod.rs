//! Builders shared by the etd-app tests.
#![allow(dead_code)] // each test binary uses a part

use etd_contract::v1::{InstanceRemoved, InstanceView, event::Payload};
use etd_contract::{
    Desired, DesiredInstance, Event, EventCursor, HostPhase, HostSnapshot, InstanceState,
    InstanceStatus, NetworkSpec,
};

pub const STREAM: &str = "fake-stream-1";

pub fn id(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

pub fn status(n: u32, state: InstanceState) -> InstanceStatus {
    InstanceStatus {
        instance_id: id(n),
        state: state as i32,
        ..InstanceStatus::default()
    }
}

pub fn desired(n: u32, desired: Desired) -> DesiredInstance {
    DesiredInstance {
        instance_id: id(n),
        spec: Some(NetworkSpec {
            network_name: format!("net-{n}"),
            network_secret_set: true,
            ..NetworkSpec::default()
        }),
        desired: desired as i32,
    }
}

pub fn view(n: u32, wanted: Desired, state: InstanceState) -> InstanceView {
    InstanceView {
        desired: Some(desired(n, wanted)),
        status: Some(status(n, state)),
    }
}

pub fn snapshot(revision: u64, seq: u64, instances: Vec<InstanceView>) -> HostSnapshot {
    HostSnapshot {
        revision,
        instances,
        cursor: Some(cursor(seq)),
        phase: HostPhase::Serving as i32,
        ..HostSnapshot::default()
    }
}

pub fn cursor(seq: u64) -> EventCursor {
    EventCursor {
        stream_id: STREAM.into(),
        seq,
    }
}

pub fn event(seq: u64, payload: Payload) -> Event {
    Event {
        cursor: Some(cursor(seq)),
        at_unix_ms: seq as i64,
        payload: Some(payload),
    }
}

pub fn state_event(seq: u64, n: u32, state: InstanceState) -> Event {
    event(seq, Payload::InstanceStatus(status(n, state)))
}

pub fn removed(n: u32, revision: u64) -> Payload {
    Payload::InstanceRemoved(InstanceRemoved {
        instance_id: id(n),
        revision,
    })
}

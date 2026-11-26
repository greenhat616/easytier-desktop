//! Snapshot + event reduction into the state store ("cut, unconfirmed" vs
//! "stopped" kept distinct). Owned by A1.
//!
//! Pure functions: no I/O, no clock. Events are applied strictly in cursor
//! order. Duplicates are dropped; anything that would leave a hole (a gap,
//! another host run, an explicit resync request) marks the store stale and
//! asks for a new snapshot instead of guessing.
use crate::{HostLink, InstanceEntry, NOTICE_LIMIT, NoticeEntry, StateStore, SyncState};
use etd_client::ConnectionState;
use etd_contract::v1::event::Payload;
use etd_contract::{DesiredInstance, Event, HostSnapshot, InstanceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncCause {
    /// The host cannot honour the cursor.
    HostRequested,
    /// Events from another host run.
    StreamChanged,
    /// At least one event is missing.
    Gap,
    /// An event without a cursor cannot be ordered.
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reduced {
    Changed,
    Ignored,
    /// The caller must take a new snapshot and resubscribe from its cursor.
    Resync(ResyncCause),
}

fn sanitized(mut instance: DesiredInstance) -> DesiredInstance {
    // The host redacts already; the store must not depend on that.
    if let Some(spec) = instance.spec.as_mut()
        && let Some(secret) = spec.network_secret.take()
    {
        spec.network_secret_set |= !secret.is_empty();
    }
    instance
}

fn entry<'a>(store: &'a mut StateStore, id: &str) -> &'a mut InstanceEntry {
    store
        .instances
        .entry(InstanceId(id.to_owned()))
        .or_insert_with_key(|id| InstanceEntry::new(id.clone()))
}

/// Replaces the host-derived data with a snapshot. Operations, notices and
/// profiles are kept.
pub fn apply_snapshot(store: &mut StateStore, snapshot: HostSnapshot) {
    let mut previous = std::mem::take(&mut store.instances);
    store.revision = snapshot.revision;
    store.phase = snapshot.phase();
    store.cursor = snapshot.cursor;
    store.reclaim = snapshot.reclaim.unwrap_or_default();
    store.default_core_version = snapshot.default_core_version;
    for view in snapshot.instances {
        let id = view
            .desired
            .as_ref()
            .map(|desired| desired.instance_id.clone())
            .or_else(|| view.status.as_ref().map(|s| s.instance_id.clone()))
            .filter(|id| !id.is_empty());
        let Some(id) = id.map(InstanceId) else {
            continue;
        };
        let mut instance = previous
            .remove(&id)
            .unwrap_or_else(|| InstanceEntry::new(id.clone()));
        instance.desired = view.desired.map(sanitized);
        instance.status = view.status;
        store.instances.insert(id, instance);
    }
    if store
        .watched
        .as_ref()
        .is_some_and(|w| !store.instances.contains_key(&w.id))
    {
        store.watched = None;
    }
    store.sync = SyncState::Synced;
}

fn resync(store: &mut StateStore, cause: ResyncCause) -> Reduced {
    store.sync = SyncState::Stale;
    Reduced::Resync(cause)
}

/// Applies one event of the subscription that started at the snapshot cursor.
pub fn apply_event(store: &mut StateStore, event: Event) -> Reduced {
    if store.sync != SyncState::Synced {
        return Reduced::Ignored;
    }
    // Its cursor says where the journal is, not what comes next.
    if matches!(event.payload, Some(Payload::ResyncRequired(_))) {
        return resync(store, ResyncCause::HostRequested);
    }
    let Some(cursor) = event.cursor else {
        return resync(store, ResyncCause::Malformed);
    };
    if let Some(current) = &store.cursor {
        if cursor.stream_id != current.stream_id {
            return resync(store, ResyncCause::StreamChanged);
        }
        if cursor.seq <= current.seq {
            return Reduced::Ignored;
        }
        if cursor.seq - current.seq > 1 {
            return resync(store, ResyncCause::Gap);
        }
    }
    store.cursor = Some(cursor);
    // A payload from a newer minor version decodes as `None`: the cursor
    // still advances.
    if let Some(payload) = event.payload {
        apply_payload(store, event.at_unix_ms, payload);
    }
    Reduced::Changed
}

fn apply_payload(store: &mut StateStore, at_unix_ms: i64, payload: Payload) {
    match payload {
        Payload::InstanceStatus(status) => {
            let id = status.instance_id.clone();
            entry(store, &id).status = Some(status);
        }
        Payload::InstanceRemoved(removed) => {
            store.revision = store.revision.max(removed.revision);
            let id = InstanceId(removed.instance_id);
            store.instances.remove(&id);
            if store.watched.as_ref().is_some_and(|w| w.id == id) {
                store.watched = None;
            }
        }
        Payload::DesiredChanged(change) => {
            store.revision = store.revision.max(change.revision);
            if let Some(instance) = change.instance {
                let id = instance.instance_id.clone();
                entry(store, &id).desired = Some(sanitized(instance));
            }
        }
        Payload::ReclaimReport(report) => store.reclaim = report,
        Payload::HostPhase(change) => store.phase = change.phase(),
        Payload::InstanceExited(exited) => {
            if let Some(instance) = store
                .instances
                .get_mut(&InstanceId(exited.instance_id.clone()))
            {
                instance.last_exit = Some(exited);
            }
        }
        Payload::Notice(notice) => {
            if let Some(instance) = store
                .instances
                .get_mut(&InstanceId(notice.instance_id.clone()))
            {
                instance.notice = Some(notice.clone());
            }
            if store.notices.len() == NOTICE_LIMIT {
                store.notices.pop_front();
            }
            store.notices.push_back(NoticeEntry { at_unix_ms, notice });
        }
        // `ResyncRequired` is handled by the caller; later variants are
        // ignored.
        _ => {}
    }
}

/// Tracks the connection. Losing the host changes only the link: instance
/// data stays as last known (the client resumes the stream by itself).
pub fn apply_connection(store: &mut StateStore, state: ConnectionState) -> Reduced {
    let before = store.link.clone();
    let negotiated_before = store.negotiated.clone();
    match state {
        ConnectionState::Connecting => {
            store.link = if store.negotiated.is_some() {
                HostLink::Reconnecting { attempt: 0 }
            } else {
                HostLink::Connecting
            };
        }
        ConnectionState::Connected(negotiated) => {
            store.link = HostLink::Connected;
            store.relaunch_failure = None;
            store.unverified_host = None;
            let other_run = store.sync == SyncState::Synced
                && !negotiated.stream_id.is_empty()
                && store
                    .cursor
                    .as_ref()
                    .is_some_and(|c| c.stream_id != negotiated.stream_id);
            store.negotiated = Some(*negotiated);
            if other_run {
                return resync(store, ResyncCause::StreamChanged);
            }
        }
        ConnectionState::Reconnecting { attempt } => {
            store.link = HostLink::Reconnecting { attempt };
        }
        ConnectionState::UpgradeRequired {
            host_major,
            host_minor,
        } => {
            store.link = HostLink::UpgradeRequired {
                host_major,
                host_minor,
            };
        }
        ConnectionState::Closed => store.link = HostLink::Closed,
        // A state from a newer client build: keep what is shown.
        _ => {}
    }
    if store.link == before && store.negotiated == negotiated_before {
        Reduced::Ignored
    } else {
        Reduced::Changed
    }
}

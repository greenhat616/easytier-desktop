//! A bounded event journal. A cursor outside the retained contiguous suffix
//! explicitly requires resync instead of silently dropping events.
use crate::api::OrchestratorHandle;
use etd_contract::{
    Event, EventCursor,
    v1::{ResyncRequired, event},
};
use futures_util::{stream, stream::BoxStream};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

struct State {
    seq: u64,
    events: VecDeque<Event>,
    closed: bool,
}
pub struct EventJournal {
    id: String,
    state: Arc<Mutex<State>>,
    updates: watch::Receiver<u64>,
    cancel: CancellationToken,
}
impl Drop for EventJournal {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl EventJournal {
    pub fn new(handle: &OrchestratorHandle, capacity: usize) -> Self {
        assert!(capacity > 0);
        let mut receiver = handle.subscribe();
        let seq = handle.view().seq;
        let id = uuid::Uuid::new_v4().to_string();
        let state = Arc::new(Mutex::new(State {
            seq,
            events: VecDeque::new(),
            closed: false,
        }));
        let (tx, updates) = watch::channel(0u64);
        let cancel = CancellationToken::new();
        let (shared, stream_id, stop) = (state.clone(), id.clone(), cancel.clone());
        tokio::spawn(async move {
            loop {
                let result = tokio::select! { _ = stop.cancelled() => break, value = receiver.recv() => value };
                let mut state = shared.lock().unwrap();
                match result {
                    Ok(e) if e.seq > state.seq => {
                        if e.seq != state.seq + 1 {
                            state.events.clear();
                        }
                        state.seq = e.seq;
                        if state.events.len() == capacity {
                            state.events.pop_front();
                        }
                        state.events.push_back(Event {
                            cursor: Some(EventCursor {
                                stream_id: stream_id.clone(),
                                seq: e.seq,
                            }),
                            at_unix_ms: e.at_unix_ms,
                            payload: Some(e.payload),
                        });
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.events.clear();
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        state.closed = true;
                        tx.send_modify(|v| *v = v.wrapping_add(1));
                        break;
                    }
                }
                tx.send_modify(|v| *v = v.wrapping_add(1));
            }
        });
        Self {
            id,
            state,
            updates,
            cancel,
        }
    }
    pub fn stream_id(&self) -> &str {
        &self.id
    }
    pub fn cursor(&self, seq: u64) -> EventCursor {
        EventCursor {
            stream_id: self.id.clone(),
            seq,
        }
    }
    pub fn subscribe(
        &self,
        after: Option<EventCursor>,
        current_view_seq: u64,
    ) -> BoxStream<'static, Event> {
        let current = self.state.lock().unwrap().seq.max(current_view_seq);
        let cursor = after.unwrap_or_else(|| self.cursor(current));
        let invalid = cursor.stream_id != self.id || cursor.seq > current;
        let id = self.id.clone();
        let next = Some(cursor.seq);
        let shared = self.state.clone();
        let updates = self.updates.clone();
        Box::pin(stream::unfold(
            (updates, shared, id, next, invalid),
            |(mut updates, shared, id, next, invalid)| async move {
                let seq = next?;
                loop {
                    updates.borrow_and_update();
                    let (event, closed) = {
                        let state = shared.lock().unwrap();
                        let event = if invalid
                            || (seq < state.seq
                                && state
                                    .events
                                    .front()
                                    .and_then(|e| e.cursor.as_ref())
                                    .is_none_or(|c| c.seq > seq + 1))
                        {
                            Some(Event {
                                cursor: Some(EventCursor {
                                    stream_id: id.clone(),
                                    seq: state.seq,
                                }),
                                payload: Some(event::Payload::ResyncRequired(ResyncRequired {
                                    reason: "Event cursor is not retained; take a new snapshot"
                                        .into(),
                                })),
                                ..Default::default()
                            })
                        } else {
                            state
                                .events
                                .iter()
                                .find(|e| e.cursor.as_ref().is_some_and(|c| c.seq > seq))
                                .cloned()
                        };
                        (event, state.closed)
                    };
                    if let Some(event) = event {
                        let next =
                            if matches!(event.payload, Some(event::Payload::ResyncRequired(_))) {
                                None
                            } else {
                                event.cursor.as_ref().map(|c| c.seq)
                            };
                        return Some((event, (updates, shared, id, next, false)));
                    }
                    if closed || updates.changed().await.is_err() {
                        return None;
                    }
                }
            },
        ))
    }
}

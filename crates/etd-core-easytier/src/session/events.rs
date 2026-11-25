//! The upstream management journal is a newest-first rolling list of 20
//! JSON strings, not a cursor API. Preserve multiplicity and reconcile its
//! overlap with the previous snapshot; never turn raw config events into logs.
use etd_core_api::{CoreError, CoreEvent, CoreEventCursor, CoreEventKind};
use serde_json::Value;
use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const HISTORY_LIMIT: usize = 1024;

#[derive(Default)]
pub(super) struct Journal {
    previous: Vec<String>,
    history: VecDeque<CoreEvent>,
    cursor: u64,
}

impl Journal {
    pub(super) fn ingest(&mut self, mut newest_first: Vec<String>) {
        newest_first.reverse();
        let overlap = (0..=self.previous.len().min(newest_first.len()))
            .rev()
            .find(|&len| self.previous[self.previous.len() - len..] == newest_first[..len])
            .unwrap_or(0);
        if overlap == 0 && !self.previous.is_empty() && !newest_first.is_empty() {
            self.push(
                SystemTime::now(),
                CoreEventKind::Other {
                    name: "EventHistoryGap".into(),
                    detail: "upstream journal rolled over between polls".into(),
                },
            );
        }
        for raw in &newest_first[overlap..] {
            let (at, kind) = decode(raw);
            self.push(at, kind);
        }
        self.previous = newest_first;
    }

    fn push(&mut self, at: SystemTime, kind: CoreEventKind) {
        self.cursor += 1;
        self.history.push_back(CoreEvent {
            cursor: CoreEventCursor(self.cursor),
            at,
            kind,
        });
        if self.history.len() > HISTORY_LIMIT {
            self.history.pop_front();
        }
    }

    pub(super) fn after(
        &self,
        since: Option<CoreEventCursor>,
    ) -> Result<Vec<CoreEvent>, CoreError> {
        let since = since.unwrap_or(CoreEventCursor(0));
        if since.0 > self.cursor
            || self
                .history
                .front()
                .is_some_and(|first| since.0 < first.cursor.0 - 1)
        {
            return Err(CoreError::Rpc(
                "kernel event cursor is outside retained history".into(),
            ));
        }
        Ok(self
            .history
            .iter()
            .filter(|event| event.cursor > since)
            .cloned()
            .collect())
    }
}

fn other(name: &str) -> CoreEventKind {
    CoreEventKind::Other {
        name: name.to_owned(),
        detail: String::new(),
    }
}

fn peer_id(v: &Value) -> Option<u32> {
    u32::try_from(v.as_u64()?).ok()
}

pub(super) fn latest_interface(events: &[String]) -> Option<String> {
    for raw in events {
        let Ok(v) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        let event = &v["event"];
        if let Some(name) = event["TunDeviceReady"].as_str() {
            return Some(name.to_owned());
        }
        if event.get("TunDeviceError").is_some() {
            return None;
        }
    }
    None
}

fn decode(raw: &str) -> (SystemTime, CoreEventKind) {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return (SystemTime::now(), other("UnrecognizedEvent"));
    };
    let at = value
        .get("time")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<jiff::Timestamp>().ok())
        .and_then(|timestamp| {
            let ms = timestamp.as_millisecond();
            let duration = Duration::from_millis(ms.unsigned_abs());
            if ms < 0 {
                UNIX_EPOCH.checked_sub(duration)
            } else {
                UNIX_EPOCH.checked_add(duration)
            }
        })
        .unwrap_or_else(SystemTime::now);
    let event = &value["event"];
    let kind = if let Some(name) = event.as_str() {
        other(if name == "CredentialChanged" {
            "CredentialChanged"
        } else {
            "UnrecognizedEvent"
        })
    } else if let Some((name, data)) = event.as_object().and_then(|object| object.iter().next()) {
        match name.as_str() {
            "PeerAdded" => peer_id(data).map(|peer_id| CoreEventKind::PeerAdded { peer_id }),
            "PeerRemoved" => peer_id(data).map(|peer_id| CoreEventKind::PeerRemoved { peer_id }),
            "PeerConnAdded" | "PeerConnRemoved" => peer_id(&data["peer_id"]).map(|peer_id| {
                let tunnel = data["tunnel"]["tunnel_type"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if name == "PeerConnAdded" {
                    CoreEventKind::ConnectionAdded { peer_id, tunnel }
                } else {
                    CoreEventKind::ConnectionRemoved { peer_id, tunnel }
                }
            }),
            "TunDeviceReady" => data.as_str().map(|name| CoreEventKind::InterfaceReady {
                name: name.to_owned(),
            }),
            "DhcpIpv4Changed" => data.as_array().and_then(|pair| pair.get(1)).map(|new| {
                CoreEventKind::AddressChanged {
                    ipv4_cidr: new.as_str().map(str::to_owned),
                }
            }),
            "ListenerAddFailed" | "ListenerAcceptFailed" => data
                .as_array()
                .and_then(|pair| pair.first())
                .and_then(Value::as_str)
                .map(|url| {
                    let url = url::Url::parse(url)
                        .ok()
                        .map(|mut u| {
                            let _ = u.set_username("");
                            let _ = u.set_password(None);
                            u.set_query(None);
                            u.set_fragment(None);
                            u.to_string()
                        })
                        .unwrap_or_default();
                    CoreEventKind::ListenerFailed {
                        url,
                        message: "kernel listener failed".into(),
                    }
                }),
            "ConfigPatched" | "CredentialChanged" => Some(other(name)),
            _ => Some(other("UnmappedEvent")),
        }
        .unwrap_or_else(|| other("UnrecognizedEvent"))
    } else {
        other("UnrecognizedEvent")
    };
    (at, kind)
}

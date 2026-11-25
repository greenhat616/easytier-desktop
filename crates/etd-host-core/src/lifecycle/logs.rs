//! Bounded log buffers (kernel stdout / stderr per instance, host notices)
//! with live following for `StreamLogs`.
use crate::api::LogStream;
use etd_contract::LogLine;
use futures_util::StreamExt;
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

pub(crate) struct LogBook {
    capacity: usize,
    lines: Mutex<VecDeque<LogLine>>,
    live: broadcast::Sender<LogLine>,
}

impl LogBook {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            lines: Mutex::new(VecDeque::new()),
            live: broadcast::channel(capacity.clamp(16, 4096)).0,
        }
    }

    pub(crate) fn push(&self, line: LogLine) {
        let mut lines = self.lines.lock().unwrap_or_else(|p| p.into_inner());
        if lines.len() == self.capacity {
            lines.pop_front();
        }
        lines.push_back(line.clone());
        // Sent under the lock so `stream` can split tail and live exactly.
        let _ = self.live.send(line);
    }

    /// The last `tail` lines, then (with `follow`) every new line, with no
    /// gap or duplicate between the two (subscribed under the buffer lock).
    pub(crate) fn stream(&self, tail: usize, follow: bool) -> LogStream {
        let lines = self.lines.lock().unwrap_or_else(|p| p.into_inner());
        let rx = follow.then(|| self.live.subscribe());
        let skip = lines.len().saturating_sub(tail);
        let past: Vec<LogLine> = lines.iter().skip(skip).cloned().collect();
        drop(lines);
        let head = futures_util::stream::iter(past);
        match rx {
            None => head.boxed(),
            Some(rx) => {
                let live = BroadcastStream::new(rx).filter_map(|r| async move { r.ok() });
                head.chain(live).boxed()
            }
        }
    }

    pub(crate) fn split_lines(bytes: &[u8]) -> impl Iterator<Item = String> + '_ {
        bytes
            .split(|b| *b == b'\n')
            .map(|l| {
                String::from_utf8_lossy(l)
                    .trim_end_matches('\r')
                    .to_string()
            })
            .filter(|l| !l.is_empty())
    }
}

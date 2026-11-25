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
}

/// Longest partial line kept while waiting for its end.
const MAX_PARTIAL: usize = 64 * 1024;

/// Splits kernel output into lines across chunk boundaries, so a secret
/// that arrives in two chunks is still seen (and redacted) as a whole.
#[derive(Default)]
pub(crate) struct LineBuffer {
    partial: Vec<u8>,
}

impl LineBuffer {
    /// Complete lines of `bytes` together with what came before.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.partial.extend_from_slice(bytes);
        let mut lines = Vec::new();
        while let Some(end) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=end).collect();
            lines.extend(text(&line[..end]));
        }
        // An endless line is emitted in pieces (a secret straddling such a
        // cut is the one case not caught).
        if self.partial.len() > MAX_PARTIAL {
            lines.extend(text(&std::mem::take(&mut self.partial)));
        }
        lines
    }

    /// What is left once the stream ended.
    pub(crate) fn finish(&mut self) -> Option<String> {
        text(&std::mem::take(&mut self.partial))
    }
}

fn text(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes);
    let s = s.trim_end_matches('\r');
    (!s.is_empty()).then(|| s.to_string())
}

/// Every exact occurrence of a secret replaced.
pub(crate) fn redact(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        if out.contains(s.as_str()) {
            out = out.replace(s.as_str(), "<redacted>");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_span_chunks_and_secrets_are_redacted() {
        let mut b = LineBuffer::default();
        assert!(b.push(b"peer key=s3c").is_empty());
        let lines = b.push(b"ret ok\r\nnext");
        assert_eq!(lines, vec!["peer key=s3cret ok".to_string()]);
        assert_eq!(b.finish(), Some("next".into()));
        let secrets = vec!["s3cret".to_string()];
        assert_eq!(redact(&lines[0], &secrets), "peer key=<redacted> ok");
        assert_eq!(redact("nothing", &[String::new()]), "nothing");
    }
}

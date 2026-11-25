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
///
/// A line longer than [`MAX_PARTIAL`] without a newline is emitted in
/// pieces. Before a piece is cut the whole pending text is redacted, and
/// the last `longest secret - 1` bytes stay behind: any secret not yet
/// replaced is incomplete, so it starts inside that tail and is matched
/// once the rest arrives. No secret survives a cut.
#[derive(Default)]
pub(crate) struct LineBuffer {
    partial: Vec<u8>,
}

impl LineBuffer {
    /// Complete lines of `bytes` together with what came before, redacted.
    pub(crate) fn push(&mut self, bytes: &[u8], secrets: &[String]) -> Vec<String> {
        self.partial.extend_from_slice(bytes);
        let mut lines = Vec::new();
        while let Some(end) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=end).collect();
            lines.extend(text(&line[..end], secrets));
        }
        if self.partial.len() > MAX_PARTIAL {
            self.partial = redact_bytes(&self.partial, secrets);
            let keep = secrets
                .iter()
                .map(|s| s.len())
                .max()
                .unwrap_or(0)
                .saturating_sub(1);
            let mut cut = self.partial.len().saturating_sub(keep);
            // Never split a UTF-8 character.
            while cut > 0 && cut < self.partial.len() && self.partial[cut] & 0xC0 == 0x80 {
                cut -= 1;
            }
            let piece: Vec<u8> = self.partial.drain(..cut).collect();
            lines.extend(text(&piece, secrets));
        }
        lines
    }

    /// What is left once the stream ended, redacted.
    pub(crate) fn finish(&mut self, secrets: &[String]) -> Option<String> {
        text(&std::mem::take(&mut self.partial), secrets)
    }
}

fn text(bytes: &[u8], secrets: &[String]) -> Option<String> {
    let s = String::from_utf8_lossy(&redact_bytes(bytes, secrets)).into_owned();
    let s = s.trim_end_matches('\r');
    (!s.is_empty()).then(|| s.to_string())
}

const REDACTED: &str = "<redacted>";

/// Every exact occurrence of a secret replaced.
fn redact_bytes(bytes: &[u8], secrets: &[String]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for s in secrets
        .iter()
        .map(String::as_bytes)
        .filter(|s| !s.is_empty())
    {
        if !out.windows(s.len()).any(|w| w == s) {
            continue;
        }
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            if out[i..].starts_with(s) {
                next.extend_from_slice(REDACTED.as_bytes());
                i += s.len();
            } else {
                next.push(out[i]);
                i += 1;
            }
        }
        out = next;
    }
    out
}

/// Every exact occurrence of a secret replaced.
pub(crate) fn redact(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        if out.contains(s.as_str()) {
            out = out.replace(s.as_str(), REDACTED);
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_span_chunks_and_secrets_are_redacted() {
        let secrets = vec!["s3cret".to_string()];
        let mut b = LineBuffer::default();
        assert!(b.push(b"peer key=s3c", &secrets).is_empty());
        let lines = b.push(b"ret ok\r\nnext s3cr", &secrets);
        assert_eq!(lines, vec!["peer key=<redacted> ok".to_string()]);
        assert_eq!(b.finish(&secrets), Some("next s3cr".into()));
        assert_eq!(redact("a s3cret b", &secrets), "a <redacted> b");
        assert_eq!(redact("nothing", &[String::new()]), "nothing");
    }

    /// An endless line, cut at the buffer limit at every possible offset
    /// of the secret: the secret never appears in any emitted piece.
    #[test]
    fn a_secret_straddling_the_buffer_limit_is_redacted() {
        let secrets = vec!["a-much-longer-secret".to_string(), "s3cret".to_string()];
        for offset in 0..secrets[0].len() + 2 {
            for secret in &secrets {
                let mut b = LineBuffer::default();
                let filler = vec![b'x'; MAX_PARTIAL - offset];
                let mut out = b.push(&filler, &secrets);
                for chunk in secret.as_bytes().chunks(3) {
                    out.extend(b.push(chunk, &secrets));
                }
                out.extend(b.push(&vec![b'y'; MAX_PARTIAL + 7], &secrets));
                out.extend(b.push(b" tail\nsecond line ", &secrets));
                out.extend(b.push(secret.as_bytes(), &secrets));
                out.extend(b.finish(&secrets));
                let all: String = out.concat();
                assert!(
                    secrets.iter().all(|s| !all.contains(s.as_str())),
                    "offset {offset}: leaked"
                );
                assert_eq!(all.matches(REDACTED).count(), 2, "offset {offset}");
                assert!(out.iter().any(|l| l == "second line <redacted>"));
            }
        }
    }

    #[test]
    fn utf8_is_never_split_at_a_cut() {
        let mut b = LineBuffer::default();
        let secrets = vec!["kéy-secret".to_string()];
        let mut out = b.push(&"é".repeat(MAX_PARTIAL / 2 + 3).into_bytes(), &secrets);
        out.extend(b.finish(&secrets));
        assert!(out.iter().all(|l| !l.contains('\u{FFFD}')));
    }
}

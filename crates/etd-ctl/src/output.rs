//! Rendering. Every field is picked by name, so that nothing secret can ride
//! along: a configuration is shown only as `network_secret_set`.
//!
//! Text from the host or a kernel is stripped of control characters before it
//! reaches a terminal; JSON escapes them by itself.
use crate::error::{CtlError, error_code_name};
use etd_client::CallError;
use etd_contract::{
    HostSnapshot, LogLine, Negotiated, Receipt, ReclaimReport,
    v1::{InstanceView, LogSource, Notice},
};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    io::{self, Write},
};

/// `("HOST_MODE_USER", "HOST_MODE_")` as `user`.
pub fn enum_name(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix).unwrap_or(name).to_lowercase()
}

macro_rules! name {
    ($value:expr, $prefix:literal) => {
        enum_name($value.as_str_name(), $prefix)
    };
}

fn clean(text: &str) -> Cow<'_, str> {
    if text.contains(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

fn time(unix_ms: i64) -> String {
    jiff::Timestamp::from_millisecond(unix_ms)
        .map_or_else(|_| unix_ms.to_string(), |at| at.to_string())
}

/// Replaces whatever follows a mention of the network secret. Kernels echo
/// their configuration into the log, secret included.
fn redact(text: &str) -> Cow<'_, str> {
    // ASCII lowering keeps every byte offset.
    let lower = text.to_ascii_lowercase();
    for key in ["network_secret", "network-secret"] {
        for (start, _) in lower.match_indices(key) {
            let end = start + key.len();
            let rest = &lower[end..];
            // `network_secret_set` and `network_secret_digest` are other keys.
            if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            if !rest.trim().is_empty() {
                return Cow::Owned(format!("{} <redacted>", &text[..end]));
            }
        }
    }
    Cow::Borrowed(text)
}

/// Writes one chunk of standard output. `false`: the reader went away.
fn emit(text: &str) -> Result<bool, CtlError> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(CtlError::internal(format!("cannot write output: {error}"))),
    }
}

fn print(text: &str) -> Result<(), CtlError> {
    emit(text).map(|_| ())
}

fn print_json(value: &Value) -> Result<(), CtlError> {
    print(&format!("{value}\n"))
}

pub fn warning(message: &str) {
    // Nothing to do if standard error is gone.
    let _ = writeln!(io::stderr(), "warning: {message}");
}

pub fn print_error(error: &CtlError, json: bool) {
    let mut err = io::stderr().lock();
    if !json {
        let _ = writeln!(err, "error: {}", clean(&error.message()));
        if let Some(hint) = error.hint() {
            let _ = writeln!(err, "hint: {hint}");
        }
        return;
    }
    let mut body = json!({
        "kind": error.kind(),
        "message": error.message(),
        "exit_code": error.exit_code(),
    });
    match error {
        CtlError::Call(CallError::Conflict { current }) => {
            body["current_revision"] = json!(current);
        }
        CtlError::Call(CallError::Rejected(detail)) => {
            body["error_code"] = json!(error_code_name(detail.code()));
            body["features"] = json!(detail.features);
            body["instance_id"] = json!(detail.instance_id);
        }
        CtlError::Unknown(_, unsettled) => {
            body["request_id"] = json!(unsettled.request_id);
            body["expected_revision"] = json!(unsettled.expected_revision);
            body["instance_id"] = json!(unsettled.instance_id);
        }
        _ => {}
    }
    let _ = writeln!(err, "{}", json!({ "error": body }));
}

pub fn receipt(receipt: &Receipt, instance_id: &str, json: bool) -> Result<(), CtlError> {
    if json {
        return print_json(&json!({
            "instance_id": instance_id,
            "request_id": receipt.request_id,
            "revision": receipt.revision,
            "ticket": receipt.ticket,
            "accepted_unix_ms": receipt.accepted_unix_ms,
        }));
    }
    print(&format!(
        "accepted: instance {}\nrevision {}, ticket {}, request {}\n",
        clean(instance_id),
        receipt.revision,
        clean(&receipt.ticket),
        clean(&receipt.request_id),
    ))
}

pub fn instance_id(view: &InstanceView) -> &str {
    let desired = view.desired.as_ref().map(|d| d.instance_id.as_str());
    let status = view.status.as_ref().map(|s| s.instance_id.as_str());
    desired.or(status).unwrap_or_default()
}

fn instance_json(view: &InstanceView) -> Value {
    let desired = view.desired.as_ref();
    let spec = desired.and_then(|d| d.spec.as_ref());
    let status = view.status.as_ref().map(|s| {
        json!({
            "state": name!(s.state(), "INSTANCE_STATE_"),
            "state_since_unix_ms": s.state_since_unix_ms,
            "epoch": s.epoch,
            "management": name!(s.management(), "MANAGEMENT_ACCESS_"),
            "message": redact(&s.message),
            "interface_name": s.interface_name,
            "addresses": s.addresses,
            "core_version": s.core_version,
            "restart_attempt": s.restart_attempt,
            "next_restart_unix_ms": s.next_restart_unix_ms,
            "last_exit": s.last_exit.as_ref().map(|exit| json!({
                "code": exit.code,
                "signal": exit.signal,
                "abnormal": exit.abnormal,
                "at_unix_ms": exit.at_unix_ms,
            })),
            "open_residues": s.open_residues,
        })
    });
    json!({
        "instance_id": instance_id(view),
        "desired": desired.map(|d| name!(d.desired(), "DESIRED_")),
        "display_name": spec.map(|s| &s.display_name),
        "network_name": spec.map(|s| &s.network_name),
        "network_secret_set": spec.map(|s| s.network_secret_set),
        "status": status,
    })
}

fn instance_text(out: &mut String, view: &InstanceView) {
    let desired = view.desired.as_ref();
    let spec = desired.and_then(|d| d.spec.as_ref());
    out.push_str(&format!("\ninstance {}\n", clean(instance_id(view))));
    let mut field = |label: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(&format!("  {label:<10} {}\n", clean(value)));
        }
    };
    if let Some(spec) = spec {
        field("name", &spec.display_name);
        field("network", &spec.network_name);
        let secret = if spec.network_secret_set {
            "set"
        } else {
            "not set"
        };
        field("secret", secret);
    }
    if let Some(desired) = desired {
        field("desired", &name!(desired.desired(), "DESIRED_"));
    }
    let Some(status) = &view.status else {
        return;
    };
    field("state", &name!(status.state(), "INSTANCE_STATE_"));
    field("detail", &redact(&status.message));
    field("epoch", &status.epoch.to_string());
    field(
        "management",
        &name!(status.management(), "MANAGEMENT_ACCESS_"),
    );
    field("interface", &status.interface_name);
    field("addresses", &status.addresses.join(", "));
    field("core", &status.core_version);
    if status.restart_attempt > 0 {
        field("restarts", &status.restart_attempt.to_string());
    }
    if status.next_restart_unix_ms > 0 {
        field("next start", &time(status.next_restart_unix_ms));
    }
    if let Some(exit) = &status.last_exit {
        let how = match (exit.code, exit.signal) {
            (Some(code), _) => format!("code {code}"),
            (None, Some(signal)) => format!("signal {signal}"),
            (None, None) => "unknown status".to_owned(),
        };
        let abnormal = if exit.abnormal { ", abnormal" } else { "" };
        field(
            "last exit",
            &format!("{how}{abnormal}, {}", time(exit.at_unix_ms)),
        );
    }
    if status.open_residues > 0 {
        field("residues", &status.open_residues.to_string());
    }
}

pub fn status(host: &Negotiated, snapshot: &HostSnapshot, json: bool) -> Result<(), CtlError> {
    let phase = name!(snapshot.phase(), "HOST_PHASE_");
    let mode = name!(host.host_mode, "HOST_MODE_");
    let role = name!(host.role, "ROLE_");
    let reclaim = snapshot.reclaim.as_ref();
    let candidates = reclaim.map_or(0, |r| r.candidates.len());
    let conflicts = reclaim.map_or(0, |r| r.conflicts.len());
    if json {
        let instances: Vec<Value> = snapshot.instances.iter().map(instance_json).collect();
        return print_json(&json!({
            "host": {
                "mode": mode,
                "phase": phase,
                "role": role,
                "build": host.host_build,
                "contract": format!("{}.{}", host.major, host.minor),
                "capabilities": host.capabilities,
            },
            "revision": snapshot.revision,
            "default_core_version": snapshot.default_core_version,
            "reclaim": { "candidates": candidates, "conflicts": conflicts },
            "instances": instances,
        }));
    }
    let mut out = format!(
        "host: {mode}, {phase} (build {}, contract {}.{}, your role: {role})\nrevision: {}\n",
        clean(&host.host_build),
        host.major,
        host.minor,
        snapshot.revision,
    );
    if !snapshot.default_core_version.is_empty() {
        out.push_str(&format!(
            "default core: {}\n",
            clean(&snapshot.default_core_version)
        ));
    }
    if candidates + conflicts > 0 {
        out.push_str(&format!(
            "awaiting an administrator: {candidates} candidate(s), {conflicts} conflict(s); \
             see `etd-ctl reclaim-report`\n"
        ));
    }
    if snapshot.instances.is_empty() {
        out.push_str("no instances\n");
    }
    for view in &snapshot.instances {
        instance_text(&mut out, view);
    }
    print(&out)
}

/// Prints one line. `false`: stop, the reader went away.
pub fn log_line(line: &LogLine, json: bool) -> Result<bool, CtlError> {
    let source = name!(line.source(), "LOG_SOURCE_");
    let text = redact(&line.text);
    if json {
        let value = json!({
            "at_unix_ms": line.at_unix_ms,
            "source": source,
            "instance_id": line.instance_id,
            "epoch": line.epoch,
            "text": text,
        });
        return emit(&format!("{value}\n"));
    }
    let source = match line.source() {
        LogSource::CoreStdout => "stdout",
        LogSource::CoreStderr => "stderr",
        _ => &source,
    };
    emit(&format!(
        "{} {source}: {}\n",
        time(line.at_unix_ms),
        clean(text.trim_end_matches(['\r', '\n']))
    ))
}

fn notice_json(notice: &Notice) -> Value {
    json!({
        "level": name!(notice.level(), "NOTICE_LEVEL_"),
        "code": notice.code,
        "message": redact(&notice.message),
        "instance_id": notice.instance_id,
    })
}

fn reclaim_json(report: &ReclaimReport) -> Value {
    json!({
        "generated_unix_ms": report.generated_unix_ms,
        "instances": report.instances.iter().map(|i| json!({
            "instance_id": i.instance_id,
            "epoch": i.epoch,
            "status": name!(i.status(), "RECLAIM_STATUS_"),
            "reason": redact(&i.reason),
            "residues": i.residues.iter().map(|r| json!({
                "effect_id": r.effect_id,
                "kind": r.kind,
                "identity": r.identity,
                "failures": r.failures,
                "last_error": redact(&r.last_error),
                "state": name!(r.state(), "RESIDUE_STATE_"),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "candidates": report.candidates.iter().map(|c| json!({
            "candidate_id": c.candidate_id,
            "kind": c.kind,
            "identity": c.identity,
            "origin": name!(c.origin(), "CANDIDATE_ORIGIN_"),
            "instance_id": c.instance_id,
            "epoch": c.epoch,
            "detail": redact(&c.detail),
        })).collect::<Vec<_>>(),
        "conflicts": report.conflicts.iter().map(|c| json!({
            "conflict_id": c.conflict_id,
            "effect_id": c.effect_id,
            "kind": c.kind,
            "identity": c.identity,
            "expected": c.expected,
            "found": c.found,
        })).collect::<Vec<_>>(),
        "notes": report.notes.iter().map(notice_json).collect::<Vec<_>>(),
    })
}

pub fn reclaim_report(report: &ReclaimReport, json: bool) -> Result<(), CtlError> {
    if json {
        return print_json(&reclaim_json(report));
    }
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&clean(&text));
        out.push('\n');
    };
    for instance in &report.instances {
        let mut head = format!(
            "instance {} epoch {}: {}",
            instance.instance_id,
            instance.epoch,
            name!(instance.status(), "RECLAIM_STATUS_")
        );
        if !instance.reason.is_empty() {
            head.push_str(&format!(" ({})", redact(&instance.reason)));
        }
        line(head);
        for residue in &instance.residues {
            let mut text = format!(
                "  residue {} {} [{}], {} failure(s)",
                residue.kind,
                residue.identity,
                name!(residue.state(), "RESIDUE_STATE_"),
                residue.failures
            );
            if !residue.last_error.is_empty() {
                text.push_str(&format!(": {}", redact(&residue.last_error)));
            }
            line(text);
        }
    }
    for candidate in &report.candidates {
        line(format!(
            "candidate {}: {} {} [{}] {}",
            candidate.candidate_id,
            candidate.kind,
            candidate.identity,
            name!(candidate.origin(), "CANDIDATE_ORIGIN_"),
            redact(&candidate.detail)
        ));
    }
    for conflict in &report.conflicts {
        line(format!(
            "conflict {}: {} {} expected {}, found {}",
            conflict.conflict_id,
            conflict.kind,
            conflict.identity,
            conflict.expected,
            conflict.found
        ));
    }
    for note in &report.notes {
        line(format!(
            "note [{}] {}: {}",
            name!(note.level(), "NOTICE_LEVEL_"),
            note.code,
            redact(&note.message)
        ));
    }
    if out.is_empty() {
        out.push_str("nothing to reclaim\n");
    }
    print(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_cut_from_log_text() {
        for text in [
            r#"network_secret = "hunter2""#,
            r#"{"network_identity":{"Network_Secret":"hunter2"}}"#,
            "easytier-core --network-secret hunter2 --no-tun",
            "network_secret_set=true network_secret=hunter2",
            "配置 network_secret: hunter2",
        ] {
            let shown = redact(text);
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.ends_with("<redacted>"), "{shown}");
        }
        for text in [
            "network_secret_set: true",
            "no network_secret",
            "peer connected",
        ] {
            assert_eq!(redact(text), text);
        }
    }

    #[test]
    fn terminal_controls_are_removed() {
        assert_eq!(clean("a\x1b[2J\r\nb\u{9b}c"), "a [2J  b c");
    }
}

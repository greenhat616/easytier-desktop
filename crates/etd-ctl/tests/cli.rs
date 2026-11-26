//! Every subcommand against a scripted host: output and exit code.
mod common;
use common::*;
use etd_contract::{
    ErrorCode, ErrorDetail, HostSnapshot, LogLine, ReclaimReport,
    v1::{
        Candidate, CandidateOrigin, Conflict, Desired, DesiredInstance, ExitInfo, InstanceReclaim,
        InstanceState, InstanceStatus, InstanceView, LogSource, NetworkSpec, Notice, NoticeLevel,
        ReclaimStatus, Residue, ResidueState,
    },
};
use etd_testkit::scripted_server::rejection;
use serde_json::json;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};
use tonic::{Code, Status};

/// A host which, against the contract, also returns the secret.
fn snapshot(state: InstanceState) -> HostSnapshot {
    HostSnapshot {
        phase: etd_contract::HostPhase::Serving as i32,
        default_core_version: "2.7.1".into(),
        instances: vec![InstanceView {
            desired: Some(DesiredInstance {
                instance_id: "inst-1".into(),
                desired: Desired::Running as i32,
                spec: Some(NetworkSpec {
                    display_name: "Home\x1b[2J".into(),
                    network_name: "home-net".into(),
                    network_secret: Some(SECRET.into()),
                    network_secret_set: true,
                    ..Default::default()
                }),
            }),
            status: Some(InstanceStatus {
                instance_id: "inst-1".into(),
                state: state as i32,
                epoch: 3,
                interface_name: "etd-3f9a1c2e".into(),
                addresses: vec!["10.0.0.1/24".into()],
                last_exit: Some(ExitInfo {
                    code: Some(7),
                    abnormal: true,
                    ..Default::default()
                }),
                message: format!("started with network_secret={SECRET}"),
                ..Default::default()
            }),
        }],
        ..Default::default()
    }
}

fn rejected(code: Code, error: ErrorCode, message: &str) -> Status {
    rejection(
        code,
        ErrorDetail {
            code: error as i32,
            message: message.into(),
            ..Default::default()
        },
    )
}

host_test!(status_shows_the_host_and_its_instances, |host| {
    let run = host.run(&["status"]).expect(0);
    assert!(
        run.stdout.contains("host: service, serving"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("no instances"));

    host.script.set_snapshot(snapshot(InstanceState::ReadyFull));
    let run = host.run(&["status"]).expect(0);
    for part in [
        "instance inst-1",
        "network    home-net",
        "secret     set",
        "desired    running",
        "state      ready_full",
        "interface  etd-3f9a1c2e",
        "addresses  10.0.0.1/24",
        "last exit  code 7, abnormal",
        "<redacted>",
    ] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    assert!(!run.stdout.contains('\x1b'));
    assert_eq!(run.stderr, "");

    let body = host.run(&["--json", "status"]).expect(0).json();
    assert_eq!(body["host"]["role"], "admin");
    assert_eq!(body["host"]["contract"], "1.0");
    assert_eq!(body["revision"], 0);
    let instance = &body["instances"][0];
    assert_eq!(instance["instance_id"], "inst-1");
    assert_eq!(instance["desired"], "running");
    assert_eq!(instance["network_secret_set"], true);
    assert_eq!(instance["status"]["state"], "ready_full");
    assert_eq!(instance["status"]["last_exit"]["code"], 7);

    host.run(&["status", "inst-1"]).expect(0);
    let run = host.run(&["status", "nope", "--json"]).expect(8);
    assert_eq!(run.error()["kind"], "unknown_instance");
    assert_eq!(run.stdout, "");
});

host_test!(apply_creates_and_replaces_instances, |host| {
    let spec = json!({"network_name": "home-net", "network_secret": SECRET}).to_string();
    let file = host.file("net.json", &format!("\u{feff}{spec}"));
    let body = host.run(&["--json", "apply", "-f", &file]).expect(0).json();
    assert_eq!(body["revision"], 1);
    assert_eq!(body["ticket"], "ticket-1");
    let id = body["instance_id"].as_str().unwrap().to_owned();
    let request = body["request_id"].as_str().unwrap().to_owned();
    assert!(!id.is_empty() && id != request);

    // The same id, revision and content replay the receipt.
    let replay = [
        "--json",
        "apply",
        "-f",
        "-",
        "--instance",
        &id,
        "--request-id",
        &request,
        "--expected-revision",
        "0",
    ];
    let again = host.run_with(&replay, &spec).expect(0).json();
    assert_eq!(again, body);
    assert_eq!(host.script.executed(), std::slice::from_ref(&request));

    // Anything else under that id is refused.
    let changed = json!({"network_name": "other", "network_secret": SECRET}).to_string();
    let run = host.run_with(&replay, &changed).expect(7);
    assert_eq!(run.error()["kind"], "request_id_reused");
    let mut started = replay.to_vec();
    started.push("--start");
    host.run_with(&started, &spec).expect(7);

    let run = host
        .run(&["apply", "-f", &file, "--instance", &id, "--start"])
        .expect(0);
    assert!(
        run.stdout
            .starts_with(&format!("accepted: instance {id}\n"))
    );
    assert!(run.stdout.contains("revision 2, ticket ticket-2"));
    assert_eq!(host.script.revision(), 2);
});

host_test!(start_and_stop_change_the_desired_state, |host| {
    let run = host.run(&["start", "inst-1"]).expect(0);
    assert!(run.stdout.contains("accepted: instance inst-1"));
    assert_eq!(run.stderr, "");
    let body = host.run(&["stop", "inst-1", "--json"]).expect(0).json();
    assert_eq!(body["revision"], 2);
    assert_eq!(body["instance_id"], "inst-1");
    assert_eq!(host.script.count("SetDesired"), 2);

    // A stale revision is a conflict.
    let run = host
        .run(&["stop", "inst-1", "--expected-revision", "1", "--json"])
        .expect(7);
    assert_eq!(run.error()["kind"], "revision_conflict");
    assert_eq!(run.error()["current_revision"], 2);
    let run = host
        .run(&["stop", "inst-1", "--expected-revision", "1"])
        .expect(7);
    assert!(run.stderr.contains("hint: "), "{}", run.stderr);

    // `start` does not restart an instance the host gave up on, and says so.
    host.script.set_snapshot(snapshot(InstanceState::GaveUp));
    let run = host.run(&["start", "inst-1"]).expect(0);
    assert!(
        run.stderr.contains("start --retry inst-1"),
        "{}",
        run.stderr
    );
    host.run(&["start", "--retry", "inst-1"]).expect(0);
    assert_eq!(host.script.count("RetryStart"), 1);
});

host_test!(an_unanswered_change_is_sent_again_unchanged, |host| {
    host.script
        .fail_next("SetDesired", Status::unavailable("gone"));
    let body = host.run(&["--json", "start", "inst-1"]).expect(0).json();
    assert_eq!(host.script.count("SetDesired"), 2);
    assert_eq!(
        host.script.executed(),
        [body["request_id"].as_str().unwrap()]
    );

    host.script
        .fail_next("SetDesired", Status::internal("broken"));
    host.run(&["stop", "inst-1"]).expect(0);
    assert_eq!(host.script.count("SetDesired"), 4);
    assert_eq!(host.script.executed().len(), 2);
});

host_test!(an_unknown_outcome_can_be_replayed_by_hand, |host| {
    for _ in 0..3 {
        host.script.fail_next("Apply", Status::unavailable("gone"));
    }
    let spec = json!({"network_name": "n", "network_secret": SECRET}).to_string();
    let run = host
        .run_with(&["--json", "apply", "-f", "-"], &spec)
        .expect(3);
    assert_eq!(host.script.count("Apply"), 3);
    let error = run.error();
    assert_eq!(error["kind"], "unavailable");
    assert_eq!(error["expected_revision"], 0);
    let request = error["request_id"].as_str().unwrap();
    let id = error["instance_id"].as_str().unwrap();
    let replay = [
        "apply",
        "-f",
        "-",
        "--instance",
        id,
        "--request-id",
        request,
        "--expected-revision",
        "0",
    ];
    host.run_with(&replay, &spec).expect(0);
    assert_eq!(host.script.executed(), [request]);

    for _ in 0..3 {
        host.script
            .fail_next("SetDesired", Status::unavailable("gone"));
    }
    let run = host.run(&["stop", id]).expect(3);
    assert!(run.stderr.contains("may or may not"), "{}", run.stderr);
    assert!(run.stderr.contains("--request-id "), "{}", run.stderr);
});

host_test!(refusals_have_their_own_exit_codes, |host| {
    for (code, error, exit, kind) in [
        (
            Code::PermissionDenied,
            ErrorCode::PermissionDenied,
            6,
            "permission_denied",
        ),
        (
            Code::PermissionDenied,
            ErrorCode::ElevationRequired,
            6,
            "elevation_required",
        ),
        (
            Code::FailedPrecondition,
            ErrorCode::InstanceBusy,
            8,
            "rejected",
        ),
    ] {
        host.script
            .fail_next("SetDesired", rejected(code, error, "no"));
        let run = host.run(&["--json", "stop", "inst-1"]).expect(exit);
        assert_eq!(run.error()["kind"], kind);
        assert_eq!(run.error()["exit_code"], exit);
    }
    // A refusal is final: it is not sent again.
    assert_eq!(host.script.count("SetDesired"), 3);

    // A host that quotes the request back does not get the secret printed.
    let spec = json!({"network_name": "n", "network_secret": SECRET}).to_string();
    for json in [&["--json"][..], &[]] {
        host.script.fail_next(
            "Apply",
            rejected(
                Code::InvalidArgument,
                ErrorCode::InvalidSpec,
                &format!("bad secret {SECRET}"),
            ),
        );
        let mut args = json.to_vec();
        args.extend(["apply", "-f", "-"]);
        let run = host.run_with(&args, &spec).expect(8);
        assert!(run.stderr.contains("invalid_spec"), "{}", run.stderr);
        assert!(run.stderr.contains("bad secret <redacted>"));
    }
});

host_test!(logs_are_printed_without_secrets_or_control_codes, |host| {
    let line = |source: LogSource, text: String| LogLine {
        at_unix_ms: 1_700_000_000_000,
        source: source as i32,
        text,
        instance_id: "inst-1".into(),
        epoch: 3,
    };
    host.script.set_logs(vec![
        line(LogSource::CoreStdout, "peer \x1b[31mconnected\n".into()),
        line(
            LogSource::CoreStderr,
            format!("network_secret = \"{SECRET}\""),
        ),
    ]);
    let run = host.run(&["logs", "inst-1", "--tail", "5"]).expect(0);
    assert_eq!(
        run.stdout,
        "2023-11-14T22:13:20Z stdout: peer  [31mconnected\n\
         2023-11-14T22:13:20Z stderr: network_secret <redacted>\n"
    );

    let run = host.run(&["--json", "logs"]).expect(0);
    let lines: Vec<serde_json::Value> = run
        .stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["source"], "core_stdout");
    assert_eq!(lines[0]["epoch"], 3);
    assert_eq!(lines[1]["text"], "network_secret <redacted>");

    // `--follow` prints lines while the stream stays open.
    let mut child = Command::new(CTL)
        .args(host.flags())
        .args(["logs", "-f"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(output.next().unwrap().unwrap().contains("connected"));
    assert!(output.next().unwrap().unwrap().contains("<redacted>"));
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();

    host.script.fail_next(
        "StreamLogs",
        rejected(Code::NotFound, ErrorCode::UnknownInstance, "no such"),
    );
    host.run(&["logs", "nope"]).expect(8);
    host.script.set_capabilities(&["instances"]);
    let run = host.run(&["--json", "logs"]).expect(9);
    assert_eq!(run.error()["kind"], "unsupported");
});

host_test!(reclaim_report_lists_what_is_left, |host| {
    let run = host.run(&["reclaim-report"]).expect(0);
    assert_eq!(run.stdout, "nothing to reclaim\n");

    host.script.set_snapshot(HostSnapshot {
        reclaim: Some(ReclaimReport {
            generated_unix_ms: 5,
            instances: vec![InstanceReclaim {
                instance_id: "inst-1".into(),
                epoch: 2,
                status: ReclaimStatus::Quarantined as i32,
                reason: "five failures".into(),
                residues: vec![Residue {
                    effect_id: "e1".into(),
                    kind: "win.firewall_rule".into(),
                    identity: "rule-a".into(),
                    failures: 5,
                    last_error: "denied".into(),
                    state: ResidueState::Failing as i32,
                }],
            }],
            candidates: vec![Candidate {
                candidate_id: "c1".into(),
                kind: "iface".into(),
                identity: "etd-x".into(),
                origin: CandidateOrigin::LedgerLost as i32,
                ..Default::default()
            }],
            conflicts: vec![Conflict {
                conflict_id: "k1".into(),
                kind: "route".into(),
                identity: "r".into(),
                expected: "a".into(),
                found: "b".into(),
                ..Default::default()
            }],
            notes: vec![Notice {
                level: NoticeLevel::Warning as i32,
                code: "dns_kept".into(),
                message: "another process".into(),
                ..Default::default()
            }],
        }),
        ..Default::default()
    });
    let run = host.run(&["reclaim-report"]).expect(0);
    assert_eq!(
        run.stdout,
        "instance inst-1 epoch 2: quarantined (five failures)\n\
         \x20 residue win.firewall_rule rule-a [failing], 5 failure(s): denied\n\
         candidate c1: iface etd-x [ledger_lost] \n\
         conflict k1: route r expected a, found b\n\
         note [warning] dns_kept: another process\n"
    );
    let body = host.run(&["--json", "reclaim-report"]).expect(0).json();
    assert_eq!(body["instances"][0]["status"], "quarantined");
    assert_eq!(body["instances"][0]["residues"][0]["failures"], 5);
    assert_eq!(body["candidates"][0]["origin"], "ledger_lost");
    assert_eq!(body["conflicts"][0]["conflict_id"], "k1");
    assert_eq!(body["notes"][0]["level"], "warning");

    let run = host.run(&["status"]).expect(0);
    assert!(run.stdout.contains("1 candidate(s), 1 conflict(s)"));
});

host_test!(another_major_version_asks_for_an_upgrade, |host| {
    host.script.edit_welcome(|welcome| welcome.major = 2);
    for command in [&["status"][..], &["stop", "inst-1"], &["reclaim-report"]] {
        let run = host.run(command).expect(5);
        assert!(run.stderr.contains("upgrade the service"), "{}", run.stderr);
    }
    assert_eq!(host.script.count("SetDesired"), 0);
});

host_test!(a_silent_host_times_out, |host| {
    host.script.hang_next("GetReclaimReport");
    let run = host.run(&["--timeout", "2", "reclaim-report"]).expect(3);
    assert!(run.stderr.contains("timed out"), "{}", run.stderr);
});

host_test!(an_unexpected_host_executable_is_not_trusted, |host| {
    // Linux before 6.5 can only check the socket and the peer's uid.
    if cfg!(target_os = "linux") && !kernel_reports_peer_process() {
        return;
    }
    let elsewhere = tempfile::tempdir().unwrap();
    let run = ctl(
        &[
            "--json",
            "--host",
            "user",
            "--endpoint",
            &host.endpoint,
            "--host-dir",
            elsewhere.path().to_str().unwrap(),
            "status",
        ],
        "",
    )
    .expect(4);
    assert_eq!(run.error()["kind"], "host_not_verified");
    assert!(host.script.calls().is_empty(), "nothing may be sent");
});

#[cfg(target_os = "linux")]
fn kernel_reports_peer_process() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut parts = release.split(['.', '-']).map(|part| part.parse::<u32>());
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= (6, 5),
        _ => false,
    }
}
#[cfg(not(target_os = "linux"))]
fn kernel_reports_peer_process() -> bool {
    true
}

#[test]
fn a_missing_host_is_unavailable() {
    // On Linux a user socket must lie in the runtime directory set up here.
    if !run_as_host("a_missing_host_is_unavailable") {
        return;
    }
    let (_dir, endpoint) = free_endpoint();
    let endpoint = endpoint_arg(&endpoint);
    let flags = ["--host", "user", "--endpoint", &endpoint, "--timeout", "1"];
    for command in [&["status"][..], &["start", "inst-1"], &["logs"]] {
        let mut args = flags.to_vec();
        args.extend_from_slice(command);
        let run = ctl(&args, "");
        let run = run.expect(3);
        assert_eq!(run.stdout, "");
        assert!(
            run.stderr.starts_with("error: host unavailable"),
            "{}",
            run.stderr
        );
    }
}

#[test]
fn bad_input_fails_before_any_connection() {
    for args in [
        &["frobnicate"][..],
        &["start"],
        &["stop", "a", "--request-id", "r"],
        &["apply", "-f", "-", "--start", "--stop"],
        &["--timeout", "0", "status"],
    ] {
        ctl(args, "").expect(2);
    }
    let spec = json!({"network_secret": SECRET, "netwrok_name": "x"}).to_string();
    let run = ctl(&["--json", "apply", "-f", "-"], &spec).expect(2);
    assert_eq!(run.error()["kind"], "invalid_input");
    ctl(
        &["apply", "-f", "-"],
        &format!("{{\"network_secret\":\"{SECRET}\""),
    )
    .expect(2);
    ctl(&["apply", "-f", "no/such/file.json"], "").expect(2);
    let run = ctl(
        &[
            "apply",
            "-f",
            "-",
            "--request-id",
            "r",
            "--expected-revision",
            "1",
        ],
        "{}",
    )
    .expect(2);
    assert!(run.stderr.contains("--instance"), "{}", run.stderr);
}

#[test]
fn help_names_every_subcommand_and_exit_code() {
    let run = ctl(&["--help"], "").expect(0);
    for part in [
        "status",
        "apply",
        "start",
        "stop",
        "logs",
        "reclaim-report",
        "--json",
        "Exit codes:",
    ] {
        assert!(run.stdout.contains(part), "{part}: {}", run.stdout);
    }
    ctl(&["--version"], "").expect(0);
}

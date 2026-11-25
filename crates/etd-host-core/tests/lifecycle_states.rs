//! Instance states: give-up after the fifth abnormal exit within five
//! minutes (desired state stays RUNNING), basic readiness without the
//! management RPC, a stop that cannot be recorded still cuts the kernel
//! (CUT_UNCONFIRMED), single-writer waiting, process-cleanup uncertainty,
//! and a foreign object on the derived interface name.
mod lifecycle_common;

use etd_contract::v1::{ManagementAccess, event::Payload};
use etd_contract::{Desired, DesiredInstance, ErrorCode, InstanceState as S};
use etd_core_api::CoreError;
use etd_proc::{Exit, ExitCause, Liveness, ProcessEngine, ProcessEvent};
use etd_sysfx::{EffectKind, EffectState};
use etd_testkit::fakes::core::MAGIC_DNS_CLAIM;
use lifecycle_common::*;
use std::sync::atomic::Ordering;

fn crash() -> Exit {
    Exit {
        code: Some(9),
        signal: None,
        cause: ExitCause::Exited,
    }
}

#[tokio::test]
async fn fifth_abnormal_exit_gives_up_with_desired_running() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    for n in 1..=5u64 {
        h.until("ready", |h| {
            h.status("a")
                .is_some_and(|s| s.epoch == n && s.state() == S::ReadyFull)
        })
        .await;
        world.engine.exit(&world.last_kernel(), crash());
        if n < 5 {
            h.until_still("backoff", |h| h.state("a") == S::Backoff)
                .await;
        }
    }
    h.wait_state("a", S::GaveUp).await;
    // 1 + 2 + 4 + 8 s of backoff: well inside five minutes.
    let status = h.status("a").unwrap();
    assert_eq!(status.restart_attempt, 5);
    let desired = h.snapshot().instances[0].desired.clone().unwrap();
    assert_eq!(desired.desired(), Desired::Running);
    let gave_up = h
        .log
        .iter()
        .any(|e| matches!(&e.payload, Payload::InstanceExited(x) if x.epoch == 5 && x.gave_up));
    assert!(gave_up);
    assert!(
        world.open_records("a").await.is_empty(),
        "reclaimed before giving up"
    );
    // Stays down on its own ...
    h.idle(
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(600),
    )
    .await;
    assert_eq!(world.spawned().len(), 5);
    assert_eq!(h.state("a"), S::GaveUp);
    // ... until a manual retry.
    h.retry_start("a").await;
    h.until("epoch 6", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 6 && s.state() == S::ReadyFull)
    })
    .await;
    assert_eq!(h.status("a").unwrap().restart_attempt, 0);
}

#[tokio::test]
async fn basic_readiness_does_not_need_the_rpc() {
    let world = World::new();
    world
        .driver
        .set_attach_error(Some(CoreError::Connect("refused".into())));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyBasic).await;
    let status = h.status("a").unwrap();
    assert_eq!(status.addresses, vec!["10.144.0.1/24".to_string()]);
    assert_eq!(status.management(), ManagementAccess::Available);
    // Time passes: still basic, never killed for the missing RPC.
    for _ in 0..50 {
        world.clock.advance(std::time::Duration::from_millis(500));
        h.settle().await;
    }
    assert_eq!(h.state("a"), S::ReadyBasic);
    assert_eq!(world.spawned().len(), 1);
    let err = h.query("a").await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ManagementUnavailable);
    // The RPC comes back: full readiness.
    world.driver.set_attach_error(None);
    h.wait_state("a", S::ReadyFull).await;
    assert!(h.query("a").await.is_ok());
}

#[tokio::test]
async fn unrecordable_stop_still_cuts_the_kernel() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();

    world.ledger.writes_fail.store(true, Ordering::SeqCst);
    assert!(h.set_desired("a", Desired::Stopped).await.is_err());
    // H2 cannot commit the stop: it cuts.
    h.cut("a").await.unwrap();
    h.wait_state("a", S::CutUnconfirmed).await;
    assert_eq!(world.kernel.liveness(&kernel).await, Liveness::Gone);
    // Nothing is reclaimed while the stop is unconfirmed (records stay).
    assert!(!world.open_records("a").await.is_empty());
    h.idle(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(30),
    )
    .await;
    assert_eq!(h.state("a"), S::CutUnconfirmed);
    assert_eq!(world.spawned().len(), 1);

    // The retried stop commits: reclaim, then stopped.
    world.ledger.writes_fail.store(false, Ordering::SeqCst);
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    assert!(world.open_records("a").await.is_empty());
}

#[tokio::test]
async fn single_writer_claims_are_exclusive_and_deferred() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    let dns = || etd_contract::NetworkSpec {
        magic_dns: true,
        ..spec("net")
    };
    h.apply("a", dns(), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    // Both running with the same claim: refused.
    let err = h.plan("b", Some(dns()), true).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SingleWriterTaken);
    assert_eq!(err.features, vec![MAGIC_DNS_CLAIM.to_string()]);

    // b saved stopped, a stopped; b started while a's generation still
    // holds the claim: b waits, then starts once a is reclaimed.
    h.apply("b", dns(), Desired::Stopped).await;
    world.sys.inject(
        etd_testkit::fakes::system::Fault::on(etd_testkit::fakes::system::Step::Reclaim)
            .kind(EffectKind::WinNrptRule)
            .times(2)
            .fail(etd_sysfx::ReclaimError::Busy("busy".into())),
    );
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.until_still("a reclaiming", |h| h.state("a") == S::Reclaiming)
        .await;
    let planned = h.plan("b", None, true).await.unwrap();
    assert!(planned.generation.is_none());
    h.set_desired("b", Desired::Running).await.unwrap();
    h.until("b ready", |h| h.state("b") == S::ReadyFull).await;
    assert_eq!(h.state("a"), S::Stopped);
    let history = h.history("b");
    assert!(history.contains(&S::Waiting), "{history:?}");
}

#[tokio::test]
async fn cleanup_uncertain_quarantines_without_restart() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let kernel = world.last_kernel();
    world.engine.emit(
        &kernel,
        ProcessEvent::CleanupUncertain("job not empty".into()),
    );
    h.wait_state("a", S::Quarantined).await;
    let open = world.open_records("a").await;
    let process = open.iter().find(|e| e.kind == EffectKind::Process).unwrap();
    assert_eq!(process.state, EffectState::Quarantined);
    h.idle(
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(120),
    )
    .await;
    assert_eq!(world.spawned().len(), 1);
    assert_eq!(h.state("a"), S::Quarantined);
}

#[tokio::test]
async fn foreign_interface_name_refuses_the_start() {
    let world = World::new();
    world
        .sys
        .create_foreign(EffectKind::LinuxTun, world.interface_key("a"));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::Quarantined).await;
    assert!(world.spawned().is_empty());
    assert!(world.sys.foreign_deleted().is_empty());
}

#[tokio::test]
async fn a_stop_committed_before_the_launch_wins() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    // The stop lands between the ticket and the kernel's start.
    *world.ledger.on_generation_read.lock().unwrap() = Some((
        "a".into(),
        etd_sysfx::Change::SetDesired {
            instance: "a".into(),
            desired: Desired::Stopped,
        },
    ));
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::Stopped).await;
    assert!(world.spawned().is_empty(), "a receipted stop never revives");
    assert!(world.open_records("a").await.is_empty());
    assert!(world.sys.ours().is_empty(), "no fence, no directory left");
}

#[tokio::test]
async fn a_new_configuration_committed_before_the_launch_wins() {
    let world = World::new();
    let mut h = world.start();
    h.wait_serving().await;
    let mut newer = DesiredInstance {
        instance_id: "a".into(),
        spec: Some(spec("newer")),
        ..Default::default()
    };
    newer.set_desired(Desired::Running);
    *world.ledger.on_generation_read.lock().unwrap() = Some((
        "a".into(),
        etd_sysfx::Change::PutInstance {
            instance: Box::new(newer),
            claims: Vec::new(),
        },
    ));
    h.apply("a", spec("older"), Desired::Running).await;
    h.until("newer config running", |h| {
        h.status("a")
            .is_some_and(|s| s.epoch == 2 && s.state() == S::ReadyFull)
    })
    .await;
    let spawned = world.kernel.spawned.lock().unwrap().clone();
    assert_eq!(spawned.len(), 1, "the older generation never started");
    let plan = world
        .driver
        .plan_for(spawned[0].1.cwd.as_deref().unwrap())
        .unwrap();
    let config = String::from_utf8(plan.files[0].contents.clone()).unwrap();
    assert!(config.contains("newer"), "{config}");
}

#[tokio::test]
async fn kernel_output_never_carries_the_secret() {
    use futures_util::StreamExt;
    let world = World::new();
    world
        .engine
        .push_spawn(Ok(etd_testkit::fakes::process::SpawnScript {
            events: vec![
                ProcessEvent::Stdout(b"joined with key=s3".to_vec()),
                ProcessEvent::Stdout(b"cret now\nsecond s3cr".to_vec()),
                ProcessEvent::Stderr(b"err s3cret\n".to_vec()),
            ],
            ..Default::default()
        }));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    world
        .driver
        .push_event(etd_core_api::CoreEventKind::ListenerFailed {
            url: "tcp://0.0.0.0:11010?k=s3cret".into(),
            message: "bad s3cret".into(),
        });
    h.clients(1).await;
    h.idle(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(3),
    )
    .await;
    // The kernel ends with half a secret pending; its tail is flushed too.
    world
        .engine
        .emit(&world.last_kernel(), ProcessEvent::Stdout(b"et\n".to_vec()));
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;

    let lines: Vec<String> = h.logs("a").await.unwrap().map(|l| l.text).collect().await;
    assert!(lines.iter().all(|l| !l.contains("s3cret")), "{lines:?}");
    assert!(
        lines.iter().any(|l| l == "joined with key=<redacted> now"),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l == "err <redacted>"), "{lines:?}");
    assert!(lines.iter().any(|l| l == "second <redacted>"), "{lines:?}");
    h.settle_sync();
    for e in &h.log {
        let text = format!("{:?}", e.payload);
        assert!(!text.contains("s3cret"), "{text}");
    }
}

#[tokio::test]
async fn applied_only_with_a_creation_credential() {
    let world = World::new();
    world.behave(KernelBehaviour {
        no_credentials: true,
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.idle(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(3),
    )
    .await;
    let open = world.open_records("a").await;
    let iface = open
        .iter()
        .find(|e| e.kind == EffectKind::LinuxTun)
        .unwrap();
    assert_eq!(
        iface.state,
        EffectState::Planned,
        "no credential, not applied"
    );
}

#[tokio::test]
async fn a_preexisting_object_is_flagged_not_claimed() {
    let world = World::new();
    let rule = etd_sysfx::ObjectKey::Rule {
        name: "etd-dns-a".into(),
        group: None,
    };
    world
        .sys
        .create_foreign(EffectKind::WinNrptRule, rule.clone());
    let mut h = world.start();
    h.wait_serving().await;
    let dns = etd_contract::NetworkSpec {
        magic_dns: true,
        ..spec("net")
    };
    h.apply("a", dns, Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    let open = world.open_records("a").await;
    let record = open
        .iter()
        .find(|e| e.kind == EffectKind::WinNrptRule)
        .unwrap();
    assert_eq!(record.state, EffectState::Conflict);
    h.settle_sync();
    assert!(h.log.iter().any(|e| matches!(&e.payload,
        Payload::Notice(n) if n.code == "start.preexisting")));
    // Stopping never deletes it.
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.idle(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(5),
    )
    .await;
    assert!(world.sys.find(EffectKind::WinNrptRule, &rule).is_some());
    assert!(world.sys.foreign_deleted().is_empty());
}

#[tokio::test]
async fn user_host_attaches_only_to_its_own_kernel() {
    let world = World::with_mode(etd_contract::HostMode::User, false);
    world.behave(KernelBehaviour {
        squatter: Some(4242),
        ..KernelBehaviour::default()
    });
    let mut h = world.start();
    h.wait_serving().await;
    h.leases(1).await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyBasic).await;
    h.idle(
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(5),
    )
    .await;
    assert_eq!(world.driver.attach_calls(), 0);
    assert_eq!(h.state("a"), S::ReadyBasic);
    h.settle_sync();
    assert!(h.log.iter().any(|e| matches!(&e.payload,
        Payload::Notice(n) if n.code == "management.foreign_listener")));
}

#[tokio::test]
async fn endless_output_lines_never_leak_the_secret() {
    use futures_util::StreamExt;
    let world = World::new();
    let mut events = Vec::new();
    for (i, stream) in [
        ProcessEvent::Stdout as fn(Vec<u8>) -> ProcessEvent,
        ProcessEvent::Stderr,
    ]
    .into_iter()
    .enumerate()
    {
        // No newline for longer than the line buffer, the secret cut in
        // three around the limit, then several lines in one chunk.
        events.push(stream(vec![b'x'; 65_536 - 3 - i]));
        events.push(stream(b"s3".to_vec()));
        events.push(stream(b"cr".to_vec()));
        events.push(stream(b"et".to_vec()));
        events.push(stream(vec![b'y'; 70_000]));
        events.push(stream(b"\none s3cret\ntwo s3cret three\n".to_vec()));
    }
    world
        .engine
        .push_spawn(Ok(etd_testkit::fakes::process::SpawnScript {
            events,
            ..Default::default()
        }));
    let mut h = world.start();
    h.wait_serving().await;
    h.apply("a", spec("net"), Desired::Running).await;
    h.wait_state("a", S::ReadyFull).await;
    h.set_desired("a", Desired::Stopped).await.unwrap();
    h.wait_state("a", S::Stopped).await;
    let lines: Vec<String> = h.logs("a").await.unwrap().map(|l| l.text).collect().await;
    let all = lines.concat();
    assert!(!all.contains("s3cret"), "leaked");
    assert_eq!(all.matches("<redacted>").count(), 6);
    assert_eq!(lines.iter().filter(|l| *l == "one <redacted>").count(), 2);
}

#[tokio::test]
async fn an_unknown_baseline_never_starts_the_generation() {
    use etd_testkit::fakes::system::{Fault, Step};
    let world = World::new();
    world.sys.inject(
        Fault::on(Step::Observe)
            .kind(EffectKind::WinNrptRule)
            .times(1)
            .fail(etd_sysfx::ReclaimError::Busy("cannot look".into())),
    );
    let mut h = world.start();
    h.wait_serving().await;
    let dns = etd_contract::NetworkSpec {
        magic_dns: true,
        ..spec("net")
    };
    h.apply("a", dns, Desired::Running).await;
    h.until("backoff", |h| h.state("a") == S::Backoff).await;
    assert!(
        world.spawned().is_empty(),
        "nothing spawned on an unknown baseline"
    );
    assert_eq!(
        h.status("a").unwrap().restart_attempt,
        1,
        "counts toward backoff"
    );
    h.until("ready", |h| h.state("a") == S::ReadyFull).await;
    assert_eq!(world.spawned().len(), 1);
    let open = world.open_records("a").await;
    assert!(open.iter().all(|e| e.state != EffectState::Conflict));
}

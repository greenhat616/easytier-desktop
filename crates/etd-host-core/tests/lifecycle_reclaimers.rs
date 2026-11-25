//! The host's own reclaimers: the process recovery convention (liveness
//! first; a gone root closes the record only when its containment
//! guarantees the tree is dead or a fresh marker sweep finds no survivor)
//! and the runtime directory as an exclusive container.
mod lifecycle_common;

use etd_contract::InstanceId;
use etd_host_core::reclaimers::{ProcessReclaimer, RuntimeDirReclaimer, process_detail};
use etd_proc::{Command, Containment, Exit, ExitCause, Liveness, ProcessEngine, ProcessIdentity};
use etd_sysfx::*;
use etd_testkit::fakes::clock::FakeClock;
use etd_testkit::fakes::process::{Call, FakeProcessEngine, SpawnScript};
use lifecycle_common::Scratch;
use std::path::Path;
use std::sync::Arc;

fn record(exe: &Path, dir: &Path, id: Option<(&ProcessIdentity, Containment)>) -> Effect {
    Effect {
        id: EffectId("p".into()),
        scope: EffectScope::Instance {
            instance: InstanceId::from("a"),
            epoch: Epoch(1),
        },
        kind: EffectKind::Process,
        key: ObjectKey::Process {
            exe: exe.into(),
            cmdline_marker: dir.into(),
        },
        undo: Undo::EnsureAbsent,
        persistence: Persistence::WithProcess,
        state: EffectState::Applied,
        boot: BootId("b".into()),
        observation: id.map(|(id, c)| Observation {
            credential: Some(Credential::Process {
                pid: id.pid,
                start_token: id.start_token.clone(),
            }),
            key: None,
            observed_at: jiff::Timestamp::UNIX_EPOCH,
            detail: Some(process_detail(id.pid, c)),
        }),
        failures: 0,
        last_error: None,
        recorded_at: jiff::Timestamp::UNIX_EPOCH,
    }
}

async fn spawn(
    engine: &FakeProcessEngine,
    dir: &Path,
    containment: Containment,
) -> ProcessIdentity {
    engine.push_spawn(Ok(SpawnScript {
        containment,
        ..SpawnScript::default()
    }));
    engine
        .spawn(Command {
            executable: "store/kernel".into(),
            args: vec![dir.join("config.toml").into()],
            env: Vec::new(),
            cwd: Some(dir.into()),
        })
        .await
        .unwrap()
        .identity()
        .clone()
}

fn crash() -> Exit {
    Exit {
        code: Some(1),
        signal: None,
        cause: ExitCause::Exited,
    }
}

fn setup() -> (FakeProcessEngine, ProcessReclaimer) {
    let clock = FakeClock::default();
    let engine = FakeProcessEngine::new(clock.clone());
    let r = ProcessReclaimer::new(Arc::new(engine.clone()), Arc::new(clock));
    (engine, r)
}

#[tokio::test]
async fn live_kernel_is_present_and_killed_by_identity() {
    let (engine, r) = setup();
    let dir = Path::new("run/a/1");
    let id = spawn(&engine, dir, Containment::JobObject).await;
    let e = record(
        Path::new("store/kernel"),
        dir,
        Some((&id, Containment::JobObject)),
    );
    match r.probe(&e).await {
        Probe::Present(o) => assert_eq!(o.credential, e.observation.as_ref().unwrap().credential),
        other => panic!("{other:?}"),
    }
    assert_eq!(r.reclaim(&e).await.unwrap(), Reclaimed::Removed);
    assert!(engine.calls().contains(&Call::KillVerified(id.clone())));
    assert_eq!(engine.liveness(&id).await, Liveness::Gone);
}

#[tokio::test]
async fn job_object_root_gone_closes_without_a_sweep() {
    let (engine, r) = setup();
    let dir = Path::new("run/a/1");
    let id = spawn(&engine, dir, Containment::JobObject).await;
    engine.exit(&id, crash());
    let e = record(
        Path::new("store/kernel"),
        dir,
        Some((&id, Containment::JobObject)),
    );
    assert_eq!(r.probe(&e).await, Probe::Absent);
    assert!(
        !engine
            .calls()
            .iter()
            .any(|c| matches!(c, Call::FindMarked(_)))
    );
}

#[tokio::test]
async fn process_group_root_gone_needs_an_empty_sweep() {
    let (engine, r) = setup();
    let dir = Path::new("run/a/1");
    let root = spawn(&engine, dir, Containment::ProcessGroup).await;
    // A survivor of the same generation (same image, same marker).
    let child = spawn(&engine, dir, Containment::ProcessGroup).await;
    engine.exit(&root, crash());
    let e = record(
        Path::new("store/kernel"),
        dir,
        Some((&root, Containment::ProcessGroup)),
    );
    assert!(matches!(r.probe(&e).await, Probe::Indeterminate(_)));
    engine.exit(&child, crash());
    assert_eq!(r.probe(&e).await, Probe::Absent);

    // Without a recorded containment the sweep is required as well.
    let mut bare = e.clone();
    bare.observation.as_mut().unwrap().detail = None;
    assert_eq!(r.probe(&bare).await, Probe::Absent);
    assert!(
        engine
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::FindMarked(_)))
            .count()
            >= 3
    );
}

#[tokio::test]
async fn uncertain_liveness_is_never_absent() {
    let (engine, r) = setup();
    let dir = Path::new("run/a/1");
    let id = spawn(&engine, dir, Containment::JobObject).await;
    engine.set_liveness(&id, Some(Liveness::Uncertain));
    let e = record(
        Path::new("store/kernel"),
        dir,
        Some((&id, Containment::JobObject)),
    );
    assert!(matches!(r.probe(&e).await, Probe::Indeterminate(_)));
    engine.exit(&id, crash());
    assert!(matches!(r.probe(&e).await, Probe::Indeterminate(_)));
}

#[tokio::test]
async fn planned_record_uses_the_marker() {
    let (engine, r) = setup();
    let dir = Path::new("run/a/1");
    let e = record(Path::new("store/kernel"), dir, None);
    assert_eq!(r.probe(&e).await, Probe::Absent);
    let id = spawn(&engine, dir, Containment::ProcessGroup).await;
    match r.probe(&e).await {
        Probe::Present(o) => assert_eq!(
            o.credential,
            Some(Credential::Process {
                pid: id.pid,
                start_token: id.start_token.clone()
            })
        ),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn runtime_dir_is_removed_only_inside_the_run_directory() {
    let scratch = Scratch::new();
    let run = scratch.0.join("run");
    let epoch = run.join("a").join("1");
    std::fs::create_dir_all(&epoch).unwrap();
    let config = epoch.join("config.toml");
    std::fs::write(&config, b"x").unwrap();
    let mut perms = std::fs::metadata(&config).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&config, perms).unwrap();

    let r = RuntimeDirReclaimer::new(run.clone(), Arc::new(FakeClock::default()));
    let mut e = record(Path::new("x"), Path::new("y"), None);
    e.kind = EffectKind::RuntimeDir;
    e.persistence = Persistence::Persistent;
    e.key = ObjectKey::Path {
        path: epoch.clone(),
    };
    match r.probe(&e).await {
        Probe::Present(o) => assert!(matches!(
            o.credential,
            Some(Credential::ExclusiveContainer { .. })
        )),
        other => panic!("{other:?}"),
    }
    assert_eq!(r.reclaim(&e).await.unwrap(), Reclaimed::Removed);
    assert!(!epoch.exists());
    assert!(
        !run.join("a").exists(),
        "the empty instance directory goes too"
    );
    assert!(run.exists());
    assert_eq!(r.reclaim(&e).await.unwrap(), Reclaimed::AlreadyAbsent);

    let outside = scratch.0.join("state");
    std::fs::create_dir_all(&outside).unwrap();
    e.key = ObjectKey::Path {
        path: outside.clone(),
    };
    assert!(matches!(
        r.reclaim(&e).await,
        Err(ReclaimError::PermissionDenied(_))
    ));
    assert!(outside.exists());
}

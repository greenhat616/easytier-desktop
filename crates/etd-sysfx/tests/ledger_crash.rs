//! Kill an actual child while its SQLite worker is paused at each transaction
//! boundary. Reopening must see the entire mutation or none of it.
use etd_contract::Desired;
use etd_sysfx::{
    sqlite::{CommitStage, OpenOptions, SqliteLedger},
    *,
};
use etd_testkit::conformance::ledger::{changes, plan, put, request};
use proptest::prelude::*;
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

const STAGES: [CommitStage; 6] = [
    CommitStage::Begin,
    CommitStage::Requests,
    CommitStage::Desired,
    CommitStage::Generations,
    CommitStage::Effects,
    CommitStage::Committed,
];
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("ETD_LEDGER_CRASH_DB") else {
        return;
    };
    let marker = std::env::var_os("ETD_LEDGER_CRASH_MARKER").unwrap();
    let stage = STAGES[std::env::var("ETD_LEDGER_CRASH_STAGE")
        .unwrap()
        .parse::<usize>()
        .unwrap()];
    let count = std::env::var("ETD_LEDGER_CRASH_COUNT")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    runtime().block_on(async {
        let ledger = SqliteLedger::open_with_options(
            Path::new(&path),
            BootId("boot".into()),
            OpenOptions {
                commit_observer: Some(Arc::new(move |at| {
                    if at == stage {
                        std::fs::write(&marker, b"ready").unwrap();
                        loop {
                            std::thread::park();
                        }
                    }
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut desired = Vec::new();
        let mut generations = Vec::new();
        for n in 0..count {
            let id = format!("instance-{n}");
            desired.push(put(&id, Desired::Running, &[]));
            generations.push(plan(&id, 1, &[]));
        }
        ledger
            .commit(0, changes("request", 1, desired, generations))
            .await
            .unwrap();
        panic!("expected child to be killed");
    });
}

fn kill_and_reopen(stage: usize, count: usize) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let marker = dir.path().join("ready");
    runtime().block_on(async {
        SqliteLedger::open(&path, BootId("boot".into()))
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
    });
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture"])
        .env("ETD_LEDGER_CRASH_DB", &path)
        .env("ETD_LEDGER_CRASH_MARKER", &marker)
        .env("ETD_LEDGER_CRASH_STAGE", stage.to_string())
        .env("ETD_LEDGER_CRASH_COUNT", count.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited at {stage}: {status}");
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("child never reached stage {stage}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    runtime().block_on(async {
        let ledger = SqliteLedger::open(&path, BootId("boot".into()))
            .await
            .unwrap();
        let committed = STAGES[stage] == CommitStage::Committed;
        assert_eq!(ledger.desired().await.unwrap().0, u64::from(committed));
        assert_eq!(
            ledger.desired().await.unwrap().1.len(),
            if committed { count } else { 0 }
        );
        assert_eq!(
            ledger.pending_tickets().await.unwrap().len(),
            usize::from(committed)
        );
        assert_eq!(
            ledger
                .open_effects(&ScopeFilter::all())
                .await
                .unwrap()
                .len(),
            if committed { count } else { 0 }
        );
        let status = ledger.request_status(&request("request", 1)).await.unwrap();
        assert_eq!(matches!(status, RequestStatus::Done(_)), committed);
        for n in 0..count {
            let id = format!("instance-{n}").into();
            assert_eq!(
                ledger.next_epoch(&id).await.unwrap(),
                Epoch(if committed { 2 } else { 1 })
            );
            assert_eq!(
                ledger.generation(&id, Epoch(1)).await.unwrap().is_some(),
                committed
            );
        }
        ledger.close().await.unwrap();
    });
}

#[test]
fn every_commit_stage() {
    for stage in 0..STAGES.len() {
        kill_and_reopen(stage, 2);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn arbitrary_transaction_size_and_crash_stage(stage in 0..STAGES.len(), count in 1usize..6) {
        kill_and_reopen(stage, count);
    }
}

//! Tier 2: real subprocess host composition + fake-core + native IPC.
mod host_process;
#[path = "../../../etd-host/src/serving.rs"]
mod serving;

use etd_proc::{Liveness, ProcessEngine, ProcessIdentity, processkit_engine::ProcessKitEngine};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::{sleep, timeout};

fn executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake-core"))
}
fn engine() -> ProcessKitEngine {
    ProcessKitEngine::with_console_helper(executable())
}
async fn file(path: &Path) -> String {
    timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(text) = std::fs::read_to_string(path)
                && !text.is_empty()
            {
                return text;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("fixture did not become ready")
}
async fn gone(engine: &ProcessKitEngine, id: &ProcessIdentity) {
    timeout(Duration::from_secs(20), async {
        loop {
            if matches!(engine.liveness(id).await, Liveness::Gone | Liveness::Reused) {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("recorded process still exists or cannot be verified")
}

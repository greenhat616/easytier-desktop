use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use gpui_kit::AsyncApp;

use crate::{grpc_backend::TokioBridge, tray::TrayAdapter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitPhase {
    StopSubscription,
    StopTokio,
    QuitGpui,
}

impl ExitPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StopSubscription => "stop_subscription",
            Self::StopTokio => "stop_tokio",
            Self::QuitGpui => "quit_gpui",
        }
    }
}

#[derive(Debug, Default)]
pub struct ExitTrace {
    pub started_at: Option<Instant>,
    pub phases: Vec<(ExitPhase, Duration)>,
    pub last_subscription_seq: Option<u64>,
    pub errors: Vec<String>,
}

/// Coordinates the strict shutdown order required by S3 / A1:
/// `stop-subscription -> stop tokio -> quit gpui`.
///
/// Running this sequence *before* calling `cx.quit()` avoids GPUI's 200ms `SHUTDOWN_TIMEOUT`
/// inside `App::shutdown()`, keeps the Win32 message loop alive while joining Tokio on GPUI's
/// `background_executor`, and removes the tray icon before posting `WM_QUIT`.
#[derive(Clone)]
pub struct ExitGate {
    triggered: Arc<AtomicBool>,
    trace: Arc<Mutex<ExitTrace>>,
}

impl ExitGate {
    pub fn new() -> Self {
        Self {
            triggered: Arc::new(AtomicBool::new(false)),
            trace: Arc::new(Mutex::new(ExitTrace::default())),
        }
    }

    pub fn trace(&self) -> Arc<Mutex<ExitTrace>> {
        self.trace.clone()
    }

    /// Executes the three-stage teardown exactly once. Subsequent calls are no-ops.
    pub async fn run(
        &self,
        bridge: Option<TokioBridge>,
        tray: Option<TrayAdapter>,
        cx: &mut AsyncApp,
    ) {
        if self.triggered.swap(true, Ordering::SeqCst) {
            return;
        }

        let started_at = Instant::now();
        {
            let mut trace = self.trace.lock().expect("exit trace lock");
            trace.started_at = Some(started_at);
        }

        // Phase 1: stop-subscription
        if let Some(ref bridge) = bridge {
            match bridge.stop_subscription().await {
                Ok(last_seq) => {
                    let elapsed = started_at.elapsed();
                    eprintln!(
                        "[exit 1/3] stop_subscription complete (last_seq={last_seq}, +{elapsed:?})"
                    );
                    let mut trace = self.trace.lock().expect("exit trace lock");
                    trace.last_subscription_seq = Some(last_seq);
                    trace.phases.push((ExitPhase::StopSubscription, elapsed));
                }
                Err(err) => {
                    let elapsed = started_at.elapsed();
                    eprintln!("[exit 1/3] stop_subscription error: {err:#} (+{elapsed:?})");
                    let mut trace = self.trace.lock().expect("exit trace lock");
                    trace.errors.push(format!("stop_subscription: {err:#}"));
                    trace.phases.push((ExitPhase::StopSubscription, elapsed));
                }
            }
        } else {
            let mut trace = self.trace.lock().expect("exit trace lock");
            trace
                .phases
                .push((ExitPhase::StopSubscription, started_at.elapsed()));
        }

        // Phase 2: stop tokio (join background OS thread off the GPUI UI thread)
        if let Some(bridge) = bridge {
            let stop_result = cx
                .background_executor()
                .spawn(async move { bridge.stop_tokio() })
                .await;
            let elapsed = started_at.elapsed();
            match stop_result {
                Ok(()) => {
                    eprintln!("[exit 2/3] stop_tokio complete (+{elapsed:?})");
                }
                Err(err) => {
                    eprintln!("[exit 2/3] stop_tokio error: {err:#} (+{elapsed:?})");
                    let mut trace = self.trace.lock().expect("exit trace lock");
                    trace.errors.push(format!("stop_tokio: {err:#}"));
                }
            }
            let mut trace = self.trace.lock().expect("exit trace lock");
            trace.phases.push((ExitPhase::StopTokio, elapsed));
        } else {
            let mut trace = self.trace.lock().expect("exit trace lock");
            trace
                .phases
                .push((ExitPhase::StopTokio, started_at.elapsed()));
        }

        // Phase 3: drop tray cleanly while Win32 loop is still live, then quit gpui.
        if let Some(tray) = tray {
            tray.shutdown();
        }
        let elapsed = started_at.elapsed();
        eprintln!("[exit 3/3] quit_gpui requested (+{elapsed:?})");
        {
            let mut trace = self.trace.lock().expect("exit trace lock");
            trace.phases.push((ExitPhase::QuitGpui, elapsed));
        }
        cx.update(|cx| cx.quit());
    }
}

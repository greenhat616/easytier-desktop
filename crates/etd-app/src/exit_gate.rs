//! Exit gate: every exit path funnels here, fixed order: settle instances
//! (disconnect or release lease) -> stop subscriptions -> stop tokio -> quit
//! gpui. Owned by A1.
//!
//! The gate runs on the UI executor, before the UI toolkit is told to quit
//! (its own shutdown hook is too short for this). Nothing in it needs a tokio
//! context. Each step has a deadline, and a failed or late step never stops
//! the following ones: the user asked to exit.
use async_channel::bounded;
use etd_contract::v1::LeaseRelease;
use futures_util::future::{Either, select};
use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitPhase {
    SettleInstances,
    StopSubscriptions,
    StopRuntime,
    QuitUi,
}

/// The background side of an exit, implemented by [`crate::AppRuntime`].
/// The gate calls the methods in declaration order.
pub trait ExitSteps {
    /// Session-form hosts get the lease back; a service host needs nothing.
    fn settle_instances(
        &mut self,
        release: LeaseRelease,
    ) -> impl Future<Output = Result<(), String>>;
    fn stop_subscriptions(&mut self) -> impl Future<Output = Result<(), String>>;
    /// Must not block the calling thread.
    fn stop_runtime(&mut self) -> impl Future<Output = Result<(), String>>;
}

/// Per-step limits. The defaults keep a whole exit under five seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitDeadlines {
    pub settle: Duration,
    pub subscriptions: Duration,
    pub runtime: Duration,
}

impl Default for ExitDeadlines {
    fn default() -> Self {
        Self {
            settle: Duration::from_millis(2500),
            subscriptions: Duration::from_millis(500),
            runtime: Duration::from_millis(1500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStep {
    pub phase: ExitPhase,
    pub result: Result<(), String>,
    /// Time since the exit began, at the end of the step.
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitReport {
    pub steps: Vec<ExitStep>,
}

impl ExitReport {
    pub fn phases(&self) -> Vec<ExitPhase> {
        self.steps.iter().map(|step| step.phase).collect()
    }

    pub fn errors(&self) -> impl Iterator<Item = (ExitPhase, &str)> {
        self.steps.iter().filter_map(|step| {
            step.result
                .as_ref()
                .err()
                .map(|error| (step.phase, error.as_str()))
        })
    }
}

/// Clones share the "already exiting" flag.
#[derive(Debug, Clone, Default)]
pub struct ExitGate {
    triggered: Arc<AtomicBool>,
    deadlines: ExitDeadlines,
}

impl ExitGate {
    pub fn new(deadlines: ExitDeadlines) -> Self {
        Self {
            triggered: Arc::default(),
            deadlines,
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }

    /// Runs the exit once; later calls return `None` and do nothing.
    /// `quit_ui` removes the tray icon and quits the UI toolkit.
    pub async fn run<S: ExitSteps>(
        &self,
        steps: &mut S,
        release: LeaseRelease,
        quit_ui: impl FnOnce(),
    ) -> Option<ExitReport> {
        if self.triggered.swap(true, Ordering::SeqCst) {
            return None;
        }
        let started = Instant::now();
        let mut report = ExitReport::default();
        let mut record = |phase, result: Result<(), String>| {
            if let Err(error) = &result {
                tracing::warn!(?phase, %error, "exit step failed");
            }
            report.steps.push(ExitStep {
                phase,
                result,
                elapsed: started.elapsed(),
            });
        };

        let limits = self.deadlines;
        let result = within(limits.settle, steps.settle_instances(release)).await;
        record(ExitPhase::SettleInstances, result);
        let result = within(limits.subscriptions, steps.stop_subscriptions()).await;
        record(ExitPhase::StopSubscriptions, result);
        let result = within(limits.runtime, steps.stop_runtime()).await;
        record(ExitPhase::StopRuntime, result);
        quit_ui();
        record(ExitPhase::QuitUi, Ok(()));
        Some(report)
    }
}

/// A deadline that works on any executor: a timer thread closes the race.
async fn within(
    limit: Duration,
    step: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    let (sender, timer) = bounded::<()>(1);
    thread::Builder::new()
        .name("etd-exit-timer".into())
        .spawn(move || {
            thread::sleep(limit);
            let _ = sender.try_send(());
        })
        .map_err(|error| format!("cannot start the exit timer: {error}"))?;
    match select(pin!(step), pin!(timer.recv())).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(format!("not finished within {limit:?}")),
    }
}

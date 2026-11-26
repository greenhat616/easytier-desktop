//! The exit order is fixed: settle instances -> stop subscriptions -> stop
//! tokio -> quit the UI.
use etd_app::{ExitDeadlines, ExitGate, ExitPhase, ExitSteps};
use etd_contract::v1::LeaseRelease;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Behaviour {
    Works,
    Fails,
    Hangs,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn push(&self, entry: impl Into<String>) {
        self.0.lock().unwrap().push(entry.into());
    }
    fn entries(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct Steps {
    record: Recorder,
    behaviour: [Behaviour; 3],
}

impl Steps {
    fn new(record: &Recorder, behaviour: [Behaviour; 3]) -> Self {
        Self {
            record: record.clone(),
            behaviour,
        }
    }

    async fn step(&self, index: usize, name: String) -> Result<(), String> {
        self.record.push(name);
        match self.behaviour[index] {
            Behaviour::Works => Ok(()),
            Behaviour::Fails => Err("boom".into()),
            Behaviour::Hangs => std::future::pending().await,
        }
    }
}

impl ExitSteps for Steps {
    async fn settle_instances(&mut self, release: LeaseRelease) -> Result<(), String> {
        self.step(0, format!("settle {release:?}")).await
    }
    async fn stop_subscriptions(&mut self) -> Result<(), String> {
        self.step(1, "stop subscriptions".into()).await
    }
    async fn stop_runtime(&mut self) -> Result<(), String> {
        self.step(2, "stop tokio".into()).await
    }
}

const ORDER: [ExitPhase; 4] = [
    ExitPhase::SettleInstances,
    ExitPhase::StopSubscriptions,
    ExitPhase::StopRuntime,
    ExitPhase::QuitUi,
];

fn short() -> ExitDeadlines {
    ExitDeadlines {
        settle: Duration::from_millis(40),
        subscriptions: Duration::from_millis(40),
        runtime: Duration::from_millis(40),
    }
}

// No tokio runtime on purpose: the gate runs on the UI toolkit's executor.
fn run(gate: &ExitGate, steps: &mut Steps) -> Option<etd_app::ExitReport> {
    let record = steps.record.clone();
    futures_executor_block_on(gate.run(steps, LeaseRelease::StopInstances, move || {
        record.push("quit ui")
    }))
}

fn futures_executor_block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[test]
fn the_order_is_fixed() {
    let record = Recorder::default();
    let mut steps = Steps::new(&record, [Behaviour::Works; 3]);
    let report = run(&ExitGate::default(), &mut steps).unwrap();
    assert_eq!(
        record.entries(),
        [
            "settle StopInstances",
            "stop subscriptions",
            "stop tokio",
            "quit ui"
        ]
    );
    assert_eq!(report.phases(), ORDER);
    assert_eq!(report.errors().count(), 0);
}

#[test]
fn it_runs_only_once() {
    let record = Recorder::default();
    let gate = ExitGate::default();
    let second_path = gate.clone();
    assert!(!gate.is_triggered());
    let mut steps = Steps::new(&record, [Behaviour::Works; 3]);
    assert!(run(&gate, &mut steps).is_some());
    assert!(second_path.is_triggered());
    assert!(run(&second_path, &mut steps).is_none());
    assert_eq!(record.entries().len(), 4);
}

#[test]
fn failing_or_hanging_steps_never_block_or_reorder_the_exit() {
    use Behaviour::*;
    for behaviour in [
        [Fails, Works, Works],
        [Hangs, Works, Works],
        [Works, Hangs, Fails],
        [Hangs, Hangs, Hangs],
    ] {
        let record = Recorder::default();
        let mut steps = Steps::new(&record, behaviour);
        let started = Instant::now();
        let report = run(&ExitGate::new(short()), &mut steps).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "{behaviour:?}");
        assert_eq!(report.phases(), ORDER, "{behaviour:?}");
        assert_eq!(record.entries().len(), 4);
        assert_eq!(record.entries()[3], "quit ui");
        assert_eq!(
            report.errors().count(),
            behaviour.iter().filter(|b| **b != Works).count(),
            "{behaviour:?}"
        );
    }
}

#[test]
fn the_default_deadlines_keep_an_exit_under_five_seconds() {
    let limits = ExitDeadlines::default();
    assert!(limits.settle + limits.subscriptions + limits.runtime < Duration::from_secs(5));
}

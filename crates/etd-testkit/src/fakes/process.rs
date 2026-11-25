//! Scripted `etd_proc::ProcessEngine`. Owned by P1.
use super::clock::FakeClock;
use async_trait::async_trait;
use etd_proc::*;
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, watch};

/// Instructions for the next successfully spawned process. No real process
/// is launched. With `graceful_exit = None`, stop waits for an injected exit
/// or the fake clock's grace deadline, then kills the process.
pub struct SpawnScript {
    pub containment: Containment,
    pub pid: Option<u32>,
    pub start_token: Option<String>,
    pub events: Vec<ProcessEvent>,
    pub graceful_exit: Option<Exit>,
}

impl Default for SpawnScript {
    fn default() -> Self {
        Self {
            containment: Containment::ProcessGroup,
            pid: None,
            start_token: None,
            events: Vec::new(),
            graceful_exit: Some(Exit {
                code: Some(0),
                signal: None,
                cause: ExitCause::Stopped,
            }),
        }
    }
}

/// Ordered record of calls, for assertions on orchestration sequencing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Spawn(Command),
    Liveness(ProcessIdentity),
    KillVerified(ProcessIdentity),
    FindMarked(ProcessMarker),
    Stop(ProcessIdentity, Duration),
    Kill(ProcessIdentity),
    Wait(ProcessIdentity),
}

#[derive(Clone, Default)]
pub struct FakeProcessEngine {
    state: Arc<Mutex<State>>,
    clock: FakeClock,
}

#[derive(Default)]
struct State {
    serial: u32,
    scripts: VecDeque<Result<SpawnScript, ProcessError>>,
    processes: HashMap<u32, Arc<Process>>,
    uncertain: HashMap<ProcessIdentity, Liveness>,
    enumeration_errors: VecDeque<ProcessError>,
    calls: Vec<Call>,
}

struct Process {
    identity: ProcessIdentity,
    command: Command,
    containment: Containment,
    graceful_exit: Option<Exit>,
    exit: watch::Sender<Option<Exit>>,
    events: Mutex<Option<mpsc::UnboundedSender<ProcessEvent>>>,
}

impl Process {
    fn event(&self, event: ProcessEvent) -> bool {
        match event {
            ProcessEvent::Exited(exit) => self.finish(exit),
            other => self
                .events
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|tx| tx.send(other).is_ok()),
        }
    }

    fn finish(&self, exit: Exit) -> bool {
        // One terminal event and result, even when stop/kill and an injected
        // exit race. No lock is held across await.
        let mut events = self.events.lock().unwrap();
        if let Some(tx) = events.take() {
            let _ = tx.send(ProcessEvent::Exited(exit.clone()));
            self.exit.send_replace(Some(exit));
            true
        } else {
            false
        }
    }

    async fn wait(&self) -> Exit {
        let mut rx = self.exit.subscribe();
        let result = rx
            .wait_for(Option::is_some)
            .await
            .expect("process owns exit sender");
        result.clone().unwrap()
    }

    fn killed(&self) {
        self.finish(Exit {
            code: None,
            signal: None,
            cause: ExitCause::Killed,
        });
    }
}

impl FakeProcessEngine {
    pub fn new(clock: FakeClock) -> Self {
        Self {
            clock,
            ..Self::default()
        }
    }

    pub fn clock(&self) -> FakeClock {
        self.clock.clone()
    }

    /// Queue a spawn result. An empty queue uses the default spawn script.
    pub fn push_spawn(&self, script: Result<SpawnScript, ProcessError>) {
        self.state.lock().unwrap().scripts.push_back(script);
    }

    pub fn fail_next_enumeration(&self, error: ProcessError) {
        self.state
            .lock()
            .unwrap()
            .enumeration_errors
            .push_back(error);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    /// Override a liveness inspection (e.g. permission denied). `None`
    /// restores the verdict derived from the current simulated processes.
    pub fn set_liveness(&self, id: &ProcessIdentity, verdict: Option<Liveness>) {
        let mut state = self.state.lock().unwrap();
        if let Some(verdict) = verdict {
            state.uncertain.insert(id.clone(), verdict);
        } else {
            state.uncertain.remove(id);
        }
    }

    /// Inject output or an unsolicited exit. Returns false for a missing,
    /// replaced, or already exited process.
    pub fn emit(&self, id: &ProcessIdentity, event: ProcessEvent) -> bool {
        let state = self.state.lock().unwrap();
        state
            .processes
            .get(&id.pid)
            .is_some_and(|p| p.identity == *id && p.event(event))
    }

    pub fn exit(&self, id: &ProcessIdentity, exit: Exit) -> bool {
        self.emit(id, ProcessEvent::Exited(exit))
    }

    fn record(&self, call: Call) {
        self.state.lock().unwrap().calls.push(call);
    }
}

impl State {
    fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        if let Some(verdict) = self.uncertain.get(id) {
            return *verdict;
        }
        match self.processes.get(&id.pid) {
            Some(p) if p.identity != *id => Liveness::Reused,
            Some(p) if p.exit.borrow().is_none() => Liveness::Same,
            _ => Liveness::Gone,
        }
    }
}

#[async_trait]
impl ProcessEngine for FakeProcessEngine {
    async fn spawn(&self, cmd: Command) -> Result<Box<dyn ProcessHandle>, ProcessError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Spawn(cmd.clone()));
        let script = state
            .scripts
            .pop_front()
            .unwrap_or_else(|| Ok(SpawnScript::default()))?;
        state.serial += 1;
        let identity = ProcessIdentity {
            pid: script.pid.unwrap_or(10_000 + state.serial),
            start_token: script
                .start_token
                .unwrap_or_else(|| format!("fake-{}", state.serial)),
            exe: cmd.executable.clone(),
        };
        if state
            .processes
            .get(&identity.pid)
            .is_some_and(|p| p.exit.borrow().is_none())
        {
            return Err(ProcessError::Spawn {
                executable: cmd.executable,
                message: "fake PID is already in use".into(),
            });
        }
        let (tx, mut pending) = mpsc::unbounded_channel();
        let (event_tx, events) = mpsc::channel(32);
        // Exit and wait must not block behind a slow event consumer.
        tokio::spawn(async move {
            while let Some(event) = pending.recv().await {
                if event_tx.send(event).await.is_err() {
                    break;
                }
            }
        });
        let process = Arc::new(Process {
            identity: identity.clone(),
            command: cmd,
            containment: script.containment,
            graceful_exit: script.graceful_exit,
            exit: watch::channel(None).0,
            events: Mutex::new(Some(tx)),
        });
        for event in script.events {
            process.event(event);
        }
        state.processes.insert(identity.pid, process.clone());
        Ok(Box::new(FakeHandle {
            engine: self.clone(),
            process,
            events: Some(events),
        }))
    }

    async fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Liveness(id.clone()));
        state.liveness(id)
    }

    async fn kill_verified(&self, id: &ProcessIdentity) -> Result<KillOutcome, ProcessError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::KillVerified(id.clone()));
        Ok(match state.liveness(id) {
            Liveness::Same => match state.processes.get(&id.pid) {
                Some(p) if p.identity == *id => {
                    p.killed();
                    KillOutcome::Killed
                }
                _ => KillOutcome::Uncertain,
            },
            Liveness::Gone => KillOutcome::Gone,
            Liveness::Reused => KillOutcome::Reused,
            Liveness::Uncertain => KillOutcome::Uncertain,
        })
    }

    async fn find_marked(
        &self,
        marker: &ProcessMarker,
    ) -> Result<Vec<ProcessIdentity>, ProcessError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::FindMarked(marker.clone()));
        if let Some(error) = state.enumeration_errors.pop_front() {
            return Err(error);
        }
        let mut found: Vec<_> = state
            .processes
            .values()
            .filter(|p| {
                p.exit.borrow().is_none()
                    && p.identity.exe.starts_with(&marker.exe_root)
                    && p.command
                        .args
                        .iter()
                        .any(|arg| Path::new(arg).starts_with(&marker.cmdline_root))
            })
            .map(|p| p.identity.clone())
            .collect();
        found.sort_by_key(|id| id.pid);
        Ok(found)
    }
}

struct FakeHandle {
    engine: FakeProcessEngine,
    process: Arc<Process>,
    events: Option<mpsc::Receiver<ProcessEvent>>,
}

#[async_trait]
impl ProcessHandle for FakeHandle {
    fn identity(&self) -> &ProcessIdentity {
        &self.process.identity
    }
    fn containment(&self) -> Containment {
        self.process.containment
    }
    fn take_events(&mut self) -> Option<mpsc::Receiver<ProcessEvent>> {
        self.events.take()
    }

    async fn stop(&self, grace: Duration) -> Result<Exit, ProcessError> {
        self.engine
            .record(Call::Stop(self.identity().clone(), grace));
        if let Some(exit) = self.process.graceful_exit.clone() {
            self.process.finish(exit);
        }
        tokio::select! {
            biased;
            exit = self.process.wait() => Ok(exit),
            () = self.engine.clock.sleep(grace) => {
                self.process.killed();
                Ok(self.process.wait().await)
            }
        }
    }

    async fn kill(&self) -> Result<Exit, ProcessError> {
        self.engine.record(Call::Kill(self.identity().clone()));
        self.process.killed();
        Ok(self.process.wait().await)
    }

    async fn wait(&self) -> Exit {
        self.engine.record(Call::Wait(self.identity().clone()));
        self.process.wait().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    fn command() -> Command {
        Command {
            executable: "store/core".into(),
            args: vec!["runtime/epoch/config.toml".into()],
            env: vec![],
            cwd: None,
        }
    }

    #[tokio::test]
    async fn scripted_timeout_and_exit_event() {
        let engine = FakeProcessEngine::default();
        engine.push_spawn(Ok(SpawnScript {
            graceful_exit: None,
            events: vec![ProcessEvent::Stdout(b"ready".to_vec())],
            ..Default::default()
        }));
        let mut handle = engine.spawn(command()).await.unwrap();
        let mut events = handle.take_events().unwrap();
        assert!(handle.take_events().is_none());
        assert_eq!(
            events.recv().await,
            Some(ProcessEvent::Stdout(b"ready".to_vec()))
        );
        let mut stop = handle.stop(Duration::from_secs(3));
        assert!((&mut stop).now_or_never().is_none());
        engine.clock().advance(Duration::from_secs(3));
        let exit = stop.await.unwrap();
        assert_eq!(exit.cause, ExitCause::Killed);
        assert_eq!(handle.wait().await, exit);
        assert_eq!(events.recv().await, Some(ProcessEvent::Exited(exit)));
        assert_eq!(events.recv().await, None);
        assert_eq!(engine.liveness(handle.identity()).await, Liveness::Gone);
    }

    #[tokio::test]
    async fn reuse_and_uncertainty_never_kill_another_process() {
        let engine = FakeProcessEngine::default();
        let original = engine.spawn(command()).await.unwrap();
        let id = original.identity().clone();
        let marker = ProcessMarker {
            exe_root: "store".into(),
            cmdline_root: "runtime/epoch".into(),
        };
        assert_eq!(engine.find_marked(&marker).await.unwrap(), vec![id.clone()]);
        engine.set_liveness(&id, Some(Liveness::Uncertain));
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Uncertain
        );
        engine.set_liveness(&id, None);
        original.kill().await.unwrap();
        engine.push_spawn(Ok(SpawnScript {
            pid: Some(id.pid),
            ..Default::default()
        }));
        let replacement = engine.spawn(command()).await.unwrap();
        assert_eq!(
            engine.kill_verified(&id).await.unwrap(),
            KillOutcome::Reused
        );
        assert_eq!(
            engine.liveness(replacement.identity()).await,
            Liveness::Same
        );
    }

    #[tokio::test]
    async fn exit_wins_stop_race_without_duplicate_events() {
        let engine = FakeProcessEngine::default();
        engine.push_spawn(Ok(SpawnScript {
            graceful_exit: None,
            ..Default::default()
        }));
        let mut handle = engine.spawn(command()).await.unwrap();
        let mut events = handle.take_events().unwrap();
        let mut stop = handle.stop(Duration::from_secs(3));
        assert!((&mut stop).now_or_never().is_none());
        let exit = Exit {
            code: Some(17),
            signal: None,
            cause: ExitCause::Exited,
        };
        assert!(engine.exit(handle.identity(), exit.clone()));
        assert_eq!(stop.await.unwrap(), exit);
        assert_eq!(handle.kill().await.unwrap(), exit);
        assert_eq!(events.recv().await, Some(ProcessEvent::Exited(exit)));
        assert_eq!(events.recv().await, None);
    }
}

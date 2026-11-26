//! Fake `etd_app::HostLauncher`. Owned by A1.
use async_trait::async_trait;
use etd_app::{HostLauncher, HostTarget, LaunchError};
use etd_contract::HostMode;
use etd_ipc::{Endpoint, ServerExpectation, ServerRequirement};
use std::{collections::VecDeque, sync::Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherCall {
    Probe,
    Ensure(HostMode),
}

#[derive(Default)]
struct Inner {
    probes: VecDeque<Result<Option<HostTarget>, LaunchError>>,
    ensures: VecDeque<Result<HostTarget, LaunchError>>,
    calls: Vec<LauncherCall>,
}

/// Scripted results, used once each in order. Unscripted: a probe finds
/// nothing and `ensure` succeeds with [`FakeHostLauncher::target`].
#[derive(Default)]
pub struct FakeHostLauncher(Mutex<Inner>);

impl FakeHostLauncher {
    /// A made-up target of this form.
    pub fn target(mode: HostMode) -> HostTarget {
        HostTarget {
            mode,
            endpoint: Endpoint::NamedPipe(format!(r"\\.\pipe\fake-{mode:?}")),
            expectation: ServerExpectation {
                exe_dir: "fake".into(),
                requirement: match mode {
                    HostMode::Service => ServerRequirement::Service,
                    HostMode::ElevatedSession => ServerRequirement::CurrentUserElevated,
                    _ => ServerRequirement::CurrentUser,
                },
            },
        }
    }

    pub fn script_probe(&self, result: Result<Option<HostTarget>, LaunchError>) {
        self.0
            .lock()
            .expect("fake launcher lock")
            .probes
            .push_back(result);
    }

    pub fn script_ensure(&self, result: Result<HostTarget, LaunchError>) {
        self.0
            .lock()
            .expect("fake launcher lock")
            .ensures
            .push_back(result);
    }

    pub fn calls(&self) -> Vec<LauncherCall> {
        self.0.lock().expect("fake launcher lock").calls.clone()
    }
}

#[async_trait]
impl HostLauncher for FakeHostLauncher {
    async fn probe(&self) -> Result<Option<HostTarget>, LaunchError> {
        let mut inner = self.0.lock().expect("fake launcher lock");
        inner.calls.push(LauncherCall::Probe);
        inner.probes.pop_front().unwrap_or(Ok(None))
    }

    async fn ensure(&self, want: HostMode) -> Result<HostTarget, LaunchError> {
        let mut inner = self.0.lock().expect("fake launcher lock");
        inner.calls.push(LauncherCall::Ensure(want));
        inner
            .ensures
            .pop_front()
            .unwrap_or_else(|| Ok(Self::target(want)))
    }
}

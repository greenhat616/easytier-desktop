//! Fake `etd_core_api::CoreDriver` / `CoreSession`. Owned by H1.
//!
//! The driver plans like a real adapter: it checks the requested
//! management guard against its adapter profile (deny-all only when the
//! profile marks it verified), predicts one interface for TUN instances
//! (readiness: that interface carries an address) or the management
//! listener for no-TUN instances, and a Magic DNS rule plus its
//! single-writer claim. Every plan is remembered by runtime directory so a
//! simulated kernel can create exactly the predicted objects.
//!
//! Sessions answer `wait_ready`, `query` and `poll_events` from shared
//! state; attach / readiness failures and poll counts are scriptable.
use async_trait::async_trait;
use etd_contract::{QueryKind, QueryResponse};
use etd_core_api::{
    AdapterProfile, CoreDescriptor, CoreDriver, CoreEndpoint, CoreError, CoreEvent,
    CoreEventCursor, CoreRuntimeInfo, CoreSession, LaunchContext, LaunchPlan, ManagementGuard,
    PlannedFile, Readiness, ReadinessCondition,
};
use etd_proc::Command;
use etd_sysfx::{EffectIntent, EffectKind, EffectScope, ObjectKey, Persistence, Undo};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Name of the generated configuration inside the epoch directory.
pub const CONFIG_FILE: &str = "config.toml";
/// Single-writer claim of a Magic DNS instance.
pub const MAGIC_DNS_CLAIM: &str = "magic-dns";

struct State {
    descriptor: CoreDescriptor,
    profile: Option<AdapterProfile>,
    interface_kind: EffectKind,
    minimum_uptime: Duration,
    plan_error: Option<CoreError>,
    attach_error: Option<CoreError>,
    ready_error: Option<CoreError>,
    poll_error: Option<CoreError>,
    attach_calls: u32,
    polls: u32,
    queries: u32,
    events: VecDeque<CoreEvent>,
    next_cursor: u64,
    plans: HashMap<PathBuf, LaunchPlan>,
}

/// Scriptable fake driver; clones share state.
#[derive(Clone)]
pub struct FakeCoreDriver {
    inner: Arc<Mutex<State>>,
}

impl Default for FakeCoreDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeCoreDriver {
    /// Kernel "9.9.9" with a profile whose deny-all is verified.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                descriptor: CoreDescriptor {
                    version: "9.9.9".into(),
                    proto_revision: "fake".into(),
                },
                profile: Some(AdapterProfile {
                    id: "9.9.9-fake".into(),
                    deny_all_verified: true,
                }),
                interface_kind: EffectKind::LinuxTun,
                minimum_uptime: Duration::ZERO,
                plan_error: None,
                attach_error: None,
                ready_error: None,
                poll_error: None,
                attach_calls: 0,
                polls: 0,
                queries: 0,
                events: VecDeque::new(),
                next_cursor: 1,
                plans: HashMap::new(),
            })),
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn descriptor(&self) -> CoreDescriptor {
        self.st().descriptor.clone()
    }

    /// `None`: lifecycle-only kernel.
    pub fn set_profile(&self, profile: Option<AdapterProfile>) {
        self.st().profile = profile;
    }

    pub fn profile_of(&self) -> Option<AdapterProfile> {
        self.st().profile.clone()
    }

    pub fn set_deny_all_verified(&self, verified: bool) {
        if let Some(p) = self.st().profile.as_mut() {
            p.deny_all_verified = verified;
        }
    }

    pub fn set_interface_kind(&self, kind: EffectKind) {
        self.st().interface_kind = kind;
    }

    pub fn set_minimum_uptime(&self, uptime: Duration) {
        self.st().minimum_uptime = uptime;
    }

    /// Every following `plan_launch` fails with this error (`None` clears).
    pub fn set_plan_error(&self, error: Option<CoreError>) {
        self.st().plan_error = error;
    }

    /// Every following `attach` fails with this error (`None` clears).
    pub fn set_attach_error(&self, error: Option<CoreError>) {
        self.st().attach_error = error;
    }

    /// Every following `wait_ready` fails with this error (`None` clears).
    pub fn set_ready_error(&self, error: Option<CoreError>) {
        self.st().ready_error = error;
    }

    /// Every following `poll_events` fails with this error (`None` clears).
    pub fn set_poll_error(&self, error: Option<CoreError>) {
        self.st().poll_error = error;
    }

    pub fn attach_calls(&self) -> u32 {
        self.st().attach_calls
    }

    /// `poll_events` calls so far, over every session.
    pub fn polls(&self) -> u32 {
        self.st().polls
    }

    pub fn queries(&self) -> u32 {
        self.st().queries
    }

    /// Queue a kernel event for the next poll.
    pub fn push_event(&self, kind: etd_core_api::CoreEventKind) {
        let mut st = self.st();
        let cursor = CoreEventCursor(st.next_cursor);
        st.next_cursor += 1;
        st.events.push_back(CoreEvent {
            cursor,
            at: std::time::SystemTime::UNIX_EPOCH,
            kind,
        });
    }

    /// The last plan made for a runtime directory (what the simulated
    /// kernel launched from it creates).
    pub fn plan_for(&self, runtime_dir: &Path) -> Option<LaunchPlan> {
        self.st().plans.get(runtime_dir).cloned()
    }

    /// Runtime directory a kernel command line points into.
    pub fn runtime_dir_of(command: &Command) -> Option<PathBuf> {
        command.cwd.clone()
    }
}

fn guard_ok(guard: ManagementGuard, profile: Option<&AdapterProfile>) -> bool {
    match guard {
        ManagementGuard::LifecycleOnly => true,
        ManagementGuard::DenyAll => profile.is_some_and(|p| p.deny_all_verified),
        _ => profile.is_some(),
    }
}

#[async_trait]
impl CoreDriver for FakeCoreDriver {
    async fn identify(&self, _binary: &Path) -> Result<CoreDescriptor, CoreError> {
        Ok(self.descriptor())
    }

    fn profile(&self, core: &CoreDescriptor) -> Option<AdapterProfile> {
        let st = self.st();
        (core.version == st.descriptor.version)
            .then(|| st.profile.clone())
            .flatten()
    }

    fn plan_launch(&self, ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
        let mut st = self.st();
        if let Some(e) = &st.plan_error {
            return Err(e.clone());
        }
        let inputs = &ctx.inputs;
        if !guard_ok(inputs.guard, st.profile.as_ref()) {
            return Err(CoreError::GuardUnavailable(inputs.guard));
        }
        let scope = EffectScope::Instance {
            instance: ctx.instance.clone(),
            epoch: ctx.epoch,
        };
        let mut effects = Vec::new();
        let mut exclusive = Vec::new();
        let condition = if inputs.spec.no_tun {
            ReadinessCondition::Listener(inputs.management)
        } else {
            let key = ObjectKey::Interface {
                name: Some(inputs.interface_name.clone()),
                guid: None,
            };
            effects.push(EffectIntent {
                scope: scope.clone(),
                kind: st.interface_kind,
                key: key.clone(),
                undo: Undo::EnsureAbsent,
                persistence: Persistence::Persistent,
            });
            ReadinessCondition::InterfaceAddress(key)
        };
        if inputs.spec.magic_dns {
            exclusive.push(MAGIC_DNS_CLAIM.to_string());
            effects.push(EffectIntent {
                scope,
                kind: EffectKind::WinNrptRule,
                key: ObjectKey::Rule {
                    name: format!("etd-dns-{}", ctx.instance),
                    group: None,
                },
                undo: Undo::EnsureAbsent,
                persistence: Persistence::Persistent,
            });
        }
        let dir = inputs.runtime_dir.clone();
        let config = dir.join(CONFIG_FILE);
        let plan = LaunchPlan {
            command: Command {
                executable: inputs.core.binary.clone(),
                args: vec!["--config-file".into(), config.clone().into_os_string()],
                env: Vec::new(),
                cwd: Some(dir.clone()),
            },
            files: vec![PlannedFile {
                path: config,
                contents: format!("network_name = {:?}\n", inputs.spec.network_name).into_bytes(),
            }],
            readiness: Readiness {
                minimum_uptime: st.minimum_uptime,
                condition,
            },
            effects,
            management: inputs.guard,
            endpoint: CoreEndpoint(inputs.management),
            exclusive,
            features: Vec::new(),
        };
        st.plans.insert(dir, plan.clone());
        Ok(plan)
    }

    async fn attach(
        &self,
        _ep: &CoreEndpoint,
        _core: &CoreDescriptor,
    ) -> Result<Box<dyn CoreSession>, CoreError> {
        let mut st = self.st();
        st.attach_calls += 1;
        if let Some(e) = &st.attach_error {
            return Err(e.clone());
        }
        Ok(Box::new(FakeCoreSession {
            driver: self.clone(),
        }))
    }
}

/// Session handed out by [`FakeCoreDriver::attach`].
pub struct FakeCoreSession {
    driver: FakeCoreDriver,
}

#[async_trait]
impl CoreSession for FakeCoreSession {
    async fn wait_ready(&self, _deadline: Instant) -> Result<CoreRuntimeInfo, CoreError> {
        let st = self.driver.st();
        if let Some(e) = &st.ready_error {
            return Err(e.clone());
        }
        Ok(CoreRuntimeInfo {
            version: Some(st.descriptor.version.clone()),
            ..CoreRuntimeInfo::default()
        })
    }

    async fn query(&self, _kind: QueryKind) -> Result<QueryResponse, CoreError> {
        self.driver.st().queries += 1;
        Ok(QueryResponse::default())
    }

    async fn poll_events(
        &self,
        since: Option<CoreEventCursor>,
    ) -> Result<Vec<CoreEvent>, CoreError> {
        let mut st = self.driver.st();
        st.polls += 1;
        if let Some(e) = &st.poll_error {
            return Err(e.clone());
        }
        let events: Vec<CoreEvent> = st
            .events
            .iter()
            .filter(|e| since.is_none_or(|c| e.cursor > c))
            .cloned()
            .collect();
        Ok(events)
    }
}

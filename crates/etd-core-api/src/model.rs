use etd_proc::Command;
use etd_sysfx::Effect;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
#[derive(Debug, Clone)]
pub struct CoreDescriptor {
    pub version: String,
    pub proto_revision: String,
}
#[derive(Debug, Clone)]
pub struct RuntimeDirs {
    pub generation: PathBuf,
}
#[derive(Debug, Clone)]
pub struct CoreEndpoint(pub SocketAddr);
#[derive(Debug, Clone)]
pub struct PlannedFile {
    pub path: PathBuf,
    pub contents: Vec<u8>,
}
#[derive(Debug, Clone)]
pub enum ReadinessCondition {
    InterfaceAddress(String),
    Listener(SocketAddr),
}
#[derive(Debug, Clone)]
pub struct Readiness {
    pub minimum_uptime: Duration,
    pub condition: ReadinessCondition,
}
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub command: Command,
    pub files: Vec<PlannedFile>,
    pub readiness: Readiness,
    pub effects: Vec<Effect>,
}
#[derive(Debug, Clone)]
pub struct CoreRuntimeInfo;
#[derive(Debug, Clone)]
pub struct CoreEvent;
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("unmodelled side effects")]
    UnmodelledEffects,
    #[error("core adapter not implemented")]
    NotImplemented,
}

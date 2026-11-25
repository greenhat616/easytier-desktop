use std::{ffi::OsString, path::PathBuf};

#[derive(Debug, Clone)]
pub struct Command {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_token: String,
    pub exe: PathBuf,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Same,
    Reused,
    Gone,
    Uncertain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    JobObject,
    CgroupV2,
    ProcessGroup,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    Killed,
    Gone,
    Reused,
    Uncertain,
}
#[derive(Debug, Clone)]
pub struct Exit {
    pub code: Option<i32>,
}
#[derive(Debug, Clone)]
pub enum ProcessEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited(Exit),
}
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("process operation not implemented")]
    NotImplemented,
}

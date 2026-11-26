//! Failures and their exit codes.
use etd_client::CallError;
use etd_contract::{ErrorCode, Role};

/// What the user needs to repeat a state change whose outcome is unknown.
#[derive(Debug, Clone)]
pub struct Unsettled {
    pub request_id: String,
    pub expected_revision: u64,
    pub instance_id: String,
    /// Extra flag a replay needs when the command generated the instance id.
    pub instance_flag: Option<String>,
}

#[derive(Debug)]
pub enum CtlError {
    /// Invalid input found after argument parsing.
    Input(String),
    Internal(String),
    Call(CallError),
    /// The instance named on the command line is not in the snapshot.
    UnknownInstance(String),
    /// A state change ran out of retries without an answer.
    Unknown(CallError, Box<Unsettled>),
}

impl From<CallError> for CtlError {
    fn from(error: CallError) -> Self {
        Self::Call(error)
    }
}

/// True when the call may be repeated unchanged: the reply is missing.
pub fn is_ambiguous(error: &CallError) -> bool {
    matches!(error, CallError::Unavailable(_) | CallError::Transport(_))
}

/// True when the host itself refused the request. Because it answers a
/// repeated, already accepted request with its receipt, a refusal means the
/// change was not made.
pub fn is_host_decision(error: &CallError) -> bool {
    matches!(
        error,
        CallError::Conflict { .. }
            | CallError::RequestIdReused
            | CallError::PermissionDenied { .. }
            | CallError::ElevationRequired
            | CallError::Rejected(_)
    )
}

fn call_exit_code(error: &CallError) -> u8 {
    match error {
        CallError::Unavailable(_) | CallError::Transport(_) => 3,
        CallError::HostNotVerified(_) => 4,
        CallError::VersionMismatch { .. } => 5,
        CallError::PermissionDenied { .. } | CallError::ElevationRequired => 6,
        CallError::Conflict { .. } | CallError::RequestIdReused => 7,
        CallError::Rejected(_) => 8,
        CallError::Unsupported(_) => 9,
        _ => 1,
    }
}

fn call_kind(error: &CallError) -> &'static str {
    match error {
        CallError::Unavailable(_) => "unavailable",
        CallError::Transport(_) => "transport",
        CallError::HostNotVerified(_) => "host_not_verified",
        CallError::VersionMismatch { .. } => "upgrade_required",
        CallError::PermissionDenied { .. } => "permission_denied",
        CallError::ElevationRequired => "elevation_required",
        CallError::Conflict { .. } => "revision_conflict",
        CallError::RequestIdReused => "request_id_reused",
        CallError::Rejected(_) => "rejected",
        CallError::Unsupported(_) => "unsupported",
        CallError::Cancelled => "cancelled",
        _ => "internal",
    }
}

/// `ERROR_CODE_INSTANCE_BUSY` as `instance_busy`.
pub fn error_code_name(code: ErrorCode) -> String {
    crate::output::enum_name(code.as_str_name(), "ERROR_CODE_")
}

fn role_name(role: Role) -> String {
    crate::output::enum_name(role.as_str_name(), "ROLE_")
}

impl CtlError {
    pub fn internal(message: String) -> Self {
        Self::Internal(message)
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Input(_) => 2,
            Self::Internal(_) => 1,
            Self::Call(error) | Self::Unknown(error, _) => call_exit_code(error),
            Self::UnknownInstance(_) => 8,
        }
    }

    /// Stable machine-readable name.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Input(_) => "invalid_input",
            Self::Internal(_) => "internal",
            Self::Call(error) | Self::Unknown(error, _) => call_kind(error),
            Self::UnknownInstance(_) => "unknown_instance",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Input(message) | Self::Internal(message) => message.clone(),
            Self::UnknownInstance(id) => format!("the host has no instance {id}"),
            Self::Call(error) | Self::Unknown(error, _) => match error {
                CallError::VersionMismatch {
                    host_major,
                    host_minor,
                } => format!(
                    "the host speaks contract {host_major}.{host_minor} and this etd-ctl \
                     speaks {}.{}; upgrade the service (or etd-ctl, if it is the older one)",
                    etd_contract::VERSION_MAJOR,
                    etd_contract::VERSION_MINOR
                ),
                CallError::PermissionDenied { required } => format!(
                    "permission denied: this needs the {} role",
                    role_name(*required)
                ),
                CallError::Rejected(detail) => format!(
                    "rejected by host ({}): {}",
                    error_code_name(detail.code()),
                    detail.message
                ),
                other => other.to_string(),
            },
        }
    }

    /// Removes `secret` from every text taken over from elsewhere, in case a
    /// host quotes the request back.
    pub fn scrubbed(mut self, secret: &str) -> Self {
        if secret.is_empty() {
            return self;
        }
        let scrub = |text: &mut String| *text = text.replace(secret, "<redacted>");
        if let Self::Call(error) | Self::Unknown(error, _) = &mut self {
            match error {
                CallError::Unavailable(text)
                | CallError::Transport(text)
                | CallError::HostNotVerified(text) => scrub(text),
                CallError::Rejected(detail) => {
                    scrub(&mut detail.message);
                    detail.features.iter_mut().for_each(scrub);
                }
                _ => {}
            }
        }
        self
    }

    /// Extra advice for a human reader.
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Unknown(_, unsettled) => {
                let mut flags = format!(
                    "--request-id {} --expected-revision {}",
                    unsettled.request_id, unsettled.expected_revision
                );
                if let Some(instance) = &unsettled.instance_flag {
                    flags = format!("{instance} {flags}");
                }
                Some(format!(
                    "the host may or may not have accepted the change. Repeat the same \
                     command and configuration with: {flags}"
                ))
            }
            Self::Call(CallError::Conflict { current }) => Some(format!(
                "the configuration changed meanwhile (current revision {current}); \
                 check it with `etd-ctl status` and run the command again"
            )),
            _ => None,
        }
    }
}

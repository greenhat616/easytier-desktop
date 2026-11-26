//! The requests the bridge sends and how a lost reply is settled.
use super::{ApplyDraft, BridgeConfig};
use crate::{OperationKind, SecretInput};
use etd_client::{CallError, HostClient};
use etd_contract::v1::{
    ApplyRequest, MutationHeader, RemoveInstanceRequest, ResolveCandidatesRequest,
    RetryReclaimRequest, RetryStartRequest, SetDesiredRequest,
};
use etd_contract::{CandidateDecision, Desired, InstanceId, Receipt, RequestId, Revision};
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// What the user asked for, before it gets a request id's header.
pub(super) enum Intent {
    Apply(Box<ApplyDraft>),
    SetDesired(InstanceId, Desired),
    Remove(InstanceId),
    RetryStart(InstanceId),
    RetryReclaim(InstanceId),
    Resolve(Vec<CandidateDecision>),
}

impl Intent {
    pub(super) fn describe(&self) -> (OperationKind, Option<InstanceId>) {
        match self {
            Self::Apply(draft) => (OperationKind::Apply, Some(draft.instance_id.clone())),
            Self::SetDesired(id, Desired::Stopped) => (OperationKind::Stop, Some(id.clone())),
            Self::SetDesired(id, _) => (OperationKind::Start, Some(id.clone())),
            Self::Remove(id) => (OperationKind::Remove, Some(id.clone())),
            Self::RetryStart(id) => (OperationKind::RetryStart, Some(id.clone())),
            Self::RetryReclaim(id) => (OperationKind::RetryReclaim, Some(id.clone())),
            Self::Resolve(_) => (OperationKind::ResolveCandidates, None),
        }
    }

    pub(super) fn into_request(
        self,
        request_id: &RequestId,
        expected_revision: Revision,
    ) -> Request {
        let header = Some(MutationHeader {
            request_id: request_id.0.clone(),
            expected_revision,
        });
        match self {
            Self::Apply(draft) => {
                let mut spec = draft.spec.get().clone();
                spec.network_secret = match &draft.secret {
                    SecretInput::Keep => None,
                    SecretInput::Clear => Some(String::new()),
                    SecretInput::Set(secret) => Some(secret.expose().to_owned()),
                };
                Request::Apply(Box::new(ApplyRequest {
                    header,
                    instance_id: draft.instance_id.0,
                    spec: Some(spec),
                    desired: draft.desired as i32,
                }))
            }
            Self::SetDesired(id, desired) => Request::SetDesired(SetDesiredRequest {
                header,
                instance_id: id.0,
                desired: desired as i32,
            }),
            Self::Remove(id) => Request::Remove(RemoveInstanceRequest {
                header,
                instance_id: id.0,
            }),
            Self::RetryStart(id) => Request::RetryStart(RetryStartRequest {
                header,
                instance_id: id.0,
            }),
            Self::RetryReclaim(id) => Request::RetryReclaim(RetryReclaimRequest {
                header,
                instance_id: id.0,
            }),
            Self::Resolve(decisions) => {
                Request::Resolve(ResolveCandidatesRequest { header, decisions })
            }
        }
    }
}

/// A request as sent. An Apply holds the secret, so this type has no
/// `Debug` and lives only as long as the request may be resent.
#[derive(Clone)]
pub(super) enum Request {
    Apply(Box<ApplyRequest>),
    SetDesired(SetDesiredRequest),
    Remove(RemoveInstanceRequest),
    RetryStart(RetryStartRequest),
    RetryReclaim(RetryReclaimRequest),
    Resolve(ResolveCandidatesRequest),
}

impl Request {
    async fn send(&self, client: &dyn HostClient) -> Result<Receipt, CallError> {
        match self.clone() {
            Self::Apply(request) => client.apply(*request).await,
            Self::SetDesired(request) => client.set_desired(request).await,
            Self::Remove(request) => client.remove_instance(request).await,
            Self::RetryStart(request) => client.retry_start(request).await,
            Self::RetryReclaim(request) => client.retry_reclaim(request).await,
            Self::Resolve(request) => client.resolve_candidates(request).await,
        }
    }
}

pub(super) enum Body {
    New(Intent),
    /// An earlier request, unchanged.
    Resend(Request),
}

pub(super) struct Job {
    pub(super) id: RequestId,
    pub(super) body: Body,
}

pub(super) enum Outcome {
    Accepted(Receipt),
    Rejected(CallError),
    /// The reply is missing and the lookups did not settle it.
    Unconfirmed(CallError),
}

fn outcome_unknown(error: &CallError) -> bool {
    matches!(
        error,
        CallError::Unavailable(_) | CallError::Transport(_) | CallError::Cancelled
    )
}

pub(super) fn unavailable(reason: &str) -> CallError {
    CallError::Unavailable(reason.into())
}

pub(super) async fn limited<T>(
    limit: Duration,
    call: impl Future<Output = Result<T, CallError>>,
) -> Result<T, CallError> {
    timeout(limit, call)
        .await
        .unwrap_or_else(|_| Err(unavailable("the host did not answer in time")))
}

pub(super) fn doubled(delay: Duration, config: &BridgeConfig) -> Duration {
    (delay * 2).min(config.retry_max)
}

/// Sends once. When the reply is lost: look the receipt up, and resend the
/// identical request only after the host said it has no record of it.
pub(super) async fn execute(
    client: &dyn HostClient,
    request: &Request,
    id: &RequestId,
    config: BridgeConfig,
) -> Outcome {
    let mut last = match limited(config.call_timeout, request.send(client)).await {
        Ok(receipt) => return Outcome::Accepted(receipt),
        Err(error) if outcome_unknown(&error) => error,
        Err(error) => return Outcome::Rejected(error),
    };
    let mut delay = config.retry_min;
    for _ in 0..config.recovery_attempts {
        sleep(delay).await;
        delay = doubled(delay, &config);
        match limited(config.call_timeout, client.receipt(id.clone())).await {
            Ok(Some(receipt)) => return Outcome::Accepted(receipt),
            Ok(None) => match limited(config.call_timeout, request.send(client)).await {
                Ok(receipt) => return Outcome::Accepted(receipt),
                Err(error) if outcome_unknown(&error) => last = error,
                // The first send may still commit between the lookup and this
                // answer; a conflict is then about our own change.
                Err(error) => {
                    return match limited(config.call_timeout, client.receipt(id.clone())).await {
                        Ok(Some(receipt)) => Outcome::Accepted(receipt),
                        _ => Outcome::Rejected(error),
                    };
                }
            },
            Err(error) => last = error,
        }
    }
    Outcome::Unconfirmed(last)
}

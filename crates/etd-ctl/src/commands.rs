//! One function per subcommand, over a connected [`HostClient`].
use crate::{
    cli::{ApplyArgs, Cli, Command, Replay},
    error::{CtlError, Unsettled, is_ambiguous, is_host_decision},
    output, spec, target,
};
use etd_client::{
    CallError, ConnectionState, HostClient,
    grpc::{ClientOptions, GrpcHostClient},
    new_request_id,
};
use etd_contract::{
    Desired, InstanceState, Negotiated, Receipt,
    v1::{
        ApplyRequest, ClientKind, MutationHeader, RetryStartRequest, SetDesiredRequest,
        StreamLogsRequest,
    },
};
use etd_ipc::platform::LocalConnector;
use futures_util::StreamExt;
use std::{future::Future, io::Read, path::Path, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

/// Times an unanswered state change is sent again, unchanged.
const RETRIES: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);

struct Ctl {
    client: GrpcHostClient,
    negotiated: Negotiated,
    wait: Duration,
    json: bool,
}

pub async fn run(cli: Cli) -> Result<(), CtlError> {
    // Read local input first: a bad file must not need a host.
    let spec = match &cli.command {
        Command::Apply(args) => Some(read_spec(args)?),
        _ => None,
    };
    let endpoint = target::endpoint(cli.host, cli.endpoint)?;
    let connector = LocalConnector {
        expectation: target::expectation(cli.host, cli.host_dir)?,
    };
    let wait = Duration::from_secs(cli.timeout);
    let defaults = ClientOptions::default();
    let options = ClientOptions {
        client_kind: ClientKind::Cli,
        connect_timeout: wait,
        request_timeout: wait,
        recovery_timeout: wait.min(defaults.recovery_timeout),
        ..defaults
    };
    let client = GrpcHostClient::new(Arc::new(connector), endpoint, options);
    let negotiated = connected(&client, wait).await?;
    let ctl = Ctl {
        client,
        negotiated,
        wait,
        json: cli.json,
    };
    match cli.command {
        Command::Status { instance } => ctl.status(instance).await,
        Command::Apply(args) => match spec {
            Some(spec) => ctl.apply(args, spec).await,
            None => Err(CtlError::internal("no configuration was read".to_owned())),
        },
        Command::Start {
            instance,
            retry: true,
            replay,
        } => ctl.retry_start(instance, replay).await,
        Command::Start {
            instance,
            retry: false,
            replay,
        } => ctl.set_desired(instance, Desired::Running, replay).await,
        Command::Stop { instance, replay } => {
            ctl.set_desired(instance, Desired::Stopped, replay).await
        }
        Command::Logs {
            instance,
            tail,
            follow,
        } => {
            let request = StreamLogsRequest {
                instance_id: instance.unwrap_or_default(),
                tail_lines: tail,
                follow,
            };
            ctl.logs(request).await
        }
        Command::ReclaimReport => {
            let report = ctl.client.reclaim_report().await?;
            output::reclaim_report(&report, ctl.json)
        }
    }
}

/// Waits for the handshake. Gives up at once on a verdict that waiting cannot
/// change, otherwise after `wait` with the latest reason.
async fn connected(client: &GrpcHostClient, wait: Duration) -> Result<Negotiated, CallError> {
    let mut states = client.connection();
    let mut reason = CallError::Unavailable("connecting timed out".to_owned());
    let attempts = async {
        loop {
            match states.borrow_and_update().clone() {
                ConnectionState::Connected(negotiated) => return Ok(*negotiated),
                ConnectionState::UpgradeRequired {
                    host_major,
                    host_minor,
                } => {
                    return Err(CallError::VersionMismatch {
                        host_major,
                        host_minor,
                    });
                }
                ConnectionState::Closed => return Err(CallError::Cancelled),
                ConnectionState::Reconnecting { .. } => {
                    // Without a connection a call fails at once, with the
                    // reason of the last attempt.
                    if let Err(error) = client.snapshot().await {
                        if matches!(error, CallError::HostNotVerified(_)) {
                            return Err(error);
                        }
                        reason = error;
                    }
                }
                _ => {}
            }
            if states.changed().await.is_err() {
                return Err(CallError::Cancelled);
            }
        }
    };
    match timeout(wait, attempts).await {
        Ok(outcome) => outcome,
        Err(_) => Err(reason),
    }
}

fn read_spec(args: &ApplyArgs) -> Result<etd_contract::NetworkSpec, CtlError> {
    // A generated instance id would make the replay a different request.
    if args.replay.request_id.is_some() && args.instance.is_none() {
        return Err(CtlError::Input(
            "--request-id repeats an earlier apply; give its --instance too".to_owned(),
        ));
    }
    let (name, text) = if args.file == Path::new("-") {
        let mut text = String::new();
        let read = std::io::stdin().read_to_string(&mut text).map(|_| text);
        ("standard input".to_owned(), read)
    } else {
        let name = args.file.display().to_string();
        (name, std::fs::read_to_string(&args.file))
    };
    let text = text.map_err(|error| CtlError::Input(format!("cannot read {name}: {error}")))?;
    // Editors on Windows like to start UTF-8 files with a byte order mark.
    spec::parse(text.strip_prefix('\u{feff}').unwrap_or(&text))
        .map_err(|error| CtlError::Input(format!("{name}: {error}")))
}

impl Ctl {
    async fn status(&self, instance: Option<String>) -> Result<(), CtlError> {
        let mut snapshot = self.client.snapshot().await?;
        if let Some(id) = instance {
            snapshot
                .instances
                .retain(|view| output::instance_id(view) == id);
            if snapshot.instances.is_empty() {
                return Err(CtlError::UnknownInstance(id));
            }
        }
        output::status(&self.negotiated, &snapshot, self.json)
    }

    /// The header of a state change: the user's replayed one, or a fresh id
    /// over the current revision.
    async fn header(&self, replay: Replay) -> Result<MutationHeader, CtlError> {
        let expected_revision = match replay.expected_revision {
            Some(revision) => revision,
            None => self.client.snapshot().await?.revision,
        };
        Ok(MutationHeader {
            request_id: replay.request_id.unwrap_or_else(|| new_request_id().0),
            expected_revision,
        })
    }

    /// Sends a state change, repeating the identical request while its
    /// outcome stays unknown. `instance_flag` is what a later replay by hand
    /// needs besides the header.
    async fn mutate<F>(
        &self,
        header: &MutationHeader,
        instance_id: &str,
        instance_flag: Option<&str>,
        send: impl Fn() -> F,
    ) -> Result<Receipt, CtlError>
    where
        F: Future<Output = Result<Receipt, CallError>>,
    {
        let mut attempt = 0;
        let error = loop {
            match send().await {
                Ok(receipt) => return Ok(receipt),
                Err(error) if is_ambiguous(&error) && attempt < RETRIES => {}
                // A decision of the host settles the request, and so does
                // any definite failure of the first attempt.
                Err(error) if is_host_decision(&error) => return Err(error.into()),
                Err(error) if attempt == 0 && !is_ambiguous(&error) => return Err(error.into()),
                Err(error) => break error,
            }
            attempt += 1;
            sleep(RETRY_DELAY * attempt).await;
            // If the host stays away the next send reports why.
            let _ = connected(&self.client, self.wait).await;
        };
        Err(CtlError::Unknown(
            error,
            Box::new(Unsettled {
                request_id: header.request_id.clone(),
                expected_revision: header.expected_revision,
                instance_id: instance_id.to_owned(),
                instance_flag: instance_flag.map(str::to_owned),
            }),
        ))
    }

    async fn apply(
        &self,
        args: ApplyArgs,
        spec: etd_contract::NetworkSpec,
    ) -> Result<(), CtlError> {
        let desired = match (args.start, args.stop) {
            (true, _) => Desired::Running,
            (_, true) => Desired::Stopped,
            _ => Desired::Unspecified,
        };
        let instance_id = args.instance.unwrap_or_else(|| new_request_id().0);
        let flag = format!("--instance {instance_id}");
        let secret = spec.network_secret.clone().unwrap_or_default();
        let header = self.header(args.replay).await?;
        let request = ApplyRequest {
            header: Some(header.clone()),
            instance_id: instance_id.clone(),
            spec: Some(spec),
            desired: desired as i32,
        };
        let receipt = self
            .mutate(&header, &instance_id, Some(&flag), || {
                self.client.apply(request.clone())
            })
            .await
            .map_err(|error| error.scrubbed(&secret))?;
        output::receipt(&receipt, &instance_id, self.json)
    }

    async fn set_desired(
        &self,
        instance_id: String,
        desired: Desired,
        replay: Replay,
    ) -> Result<(), CtlError> {
        let header = self.header(replay).await?;
        let request = SetDesiredRequest {
            header: Some(header.clone()),
            instance_id: instance_id.clone(),
            desired: desired as i32,
        };
        let receipt = self
            .mutate(&header, &instance_id, None, || {
                self.client.set_desired(request.clone())
            })
            .await?;
        output::receipt(&receipt, &instance_id, self.json)?;
        if desired == Desired::Running && self.gave_up(&instance_id).await {
            output::warning(&format!(
                "the host gave up restarting this instance, and `start` alone does not \
                 retry it; run `etd-ctl start --retry {instance_id}`"
            ));
        }
        Ok(())
    }

    async fn gave_up(&self, instance_id: &str) -> bool {
        // Only a hint: the change is already accepted.
        self.client.snapshot().await.is_ok_and(|snapshot| {
            snapshot.instances.iter().any(|view| {
                output::instance_id(view) == instance_id
                    && view
                        .status
                        .as_ref()
                        .is_some_and(|status| status.state() == InstanceState::GaveUp)
            })
        })
    }

    async fn retry_start(&self, instance_id: String, replay: Replay) -> Result<(), CtlError> {
        let header = self.header(replay).await?;
        let request = RetryStartRequest {
            header: Some(header.clone()),
            instance_id: instance_id.clone(),
        };
        let receipt = self
            .mutate(&header, &instance_id, None, || {
                self.client.retry_start(request.clone())
            })
            .await?;
        output::receipt(&receipt, &instance_id, self.json)
    }

    async fn logs(&self, request: StreamLogsRequest) -> Result<(), CtlError> {
        let mut lines = self.client.logs(request);
        while let Some(line) = lines.next().await {
            // A reader that went away (`| head`) ends the command quietly.
            if !output::log_line(&line?, self.json)? {
                break;
            }
        }
        Ok(())
    }
}

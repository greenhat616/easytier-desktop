//! The tasks one host session runs; they only report to the actor.
use super::{
    BridgeConfig, Msg,
    request::{doubled, limited},
};
use etd_client::{CallError, ConnectionState, HostClient};
use etd_contract::{InstanceId, QueryKind};
use futures_util::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle as TaskHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

pub(super) fn spawn_cancellable(
    cancel: CancellationToken,
    task: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle<()> {
    tokio::spawn(async move {
        let _ = cancel.run_until_cancelled(task).await;
    })
}

/// Without a connection a call answers at once; the limit covers the race
/// with a connection that just came up.
const REASON_PROBE: Duration = Duration::from_millis(200);

pub(super) async fn follow_connection(
    session: u64,
    client: Arc<dyn HostClient>,
    inbox: mpsc::Sender<Msg>,
) {
    let mut connection = client.connection();
    loop {
        let state = connection.borrow_and_update().clone();
        let down = matches!(state, ConnectionState::Reconnecting { .. });
        if inbox
            .send(Msg::Connection { session, state })
            .await
            .is_err()
        {
            return;
        }
        // The state does not say why there is no connection; a call fails at
        // once with the reason.
        if down
            && let Ok(Err(CallError::HostNotVerified(reason))) =
                timeout(REASON_PROBE, client.snapshot()).await
        {
            let message = Msg::Unverified { session, reason };
            if inbox.send(message).await.is_err() {
                return;
            }
        }
        if connection.changed().await.is_err() {
            return;
        }
    }
}

/// Snapshot, then events from its cursor; again whenever the actor asks or
/// the stream ends.
pub(super) async fn follow_events(
    session: u64,
    client: Arc<dyn HostClient>,
    mut resync: watch::Receiver<u64>,
    inbox: mpsc::Sender<Msg>,
    config: BridgeConfig,
) {
    let mut connection = client.connection();
    let mut delay = config.retry_min;
    loop {
        // The client fails calls at once while it has no connection.
        if connection
            .wait_for(|state| matches!(state, ConnectionState::Connected(_)))
            .await
            .is_err()
        {
            return;
        }
        // Requests made before this snapshot are satisfied by it.
        resync.borrow_and_update();
        let snapshot = match limited(config.call_timeout, client.snapshot()).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::debug!(%error, "snapshot failed");
                sleep(delay).await;
                delay = doubled(delay, &config);
                continue;
            }
        };
        let cursor = snapshot.cursor.clone();
        let message = Msg::Snapshot {
            session,
            snapshot: Box::new(snapshot),
        };
        if inbox.send(message).await.is_err() {
            return;
        }
        let mut events = client.subscribe(cursor);
        let mut received = false;
        let asked = loop {
            tokio::select! {
                biased;
                changed = resync.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    break true;
                }
                item = events.next() => match item {
                    Some(Ok(event)) => {
                        received = true;
                        let message = Msg::Event { session, event: Box::new(event) };
                        if inbox.send(message).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(error)) => {
                        tracing::debug!(%error, "event stream failed");
                        break false;
                    }
                    None => break false,
                }
            }
        };
        drop(events);
        if asked {
            // A floor, so a host that keeps breaking its stream cannot make
            // this loop spin.
            sleep(config.retry_min / 4).await;
            continue;
        }
        // After a `ResyncRequired` the actor's request is already on its way;
        // the delay lets it arrive first.
        if inbox.send(Msg::StreamEnded { session }).await.is_err() {
            return;
        }
        if received {
            delay = config.retry_min;
        }
        sleep(delay).await;
        delay = doubled(delay, &config);
    }
}

pub(super) async fn poll_queries(
    watch: u64,
    instance: InstanceId,
    client: Arc<dyn HostClient>,
    inbox: mpsc::Sender<Msg>,
    config: BridgeConfig,
) {
    use etd_contract::capability;
    loop {
        let connected = matches!(*client.connection().borrow(), ConnectionState::Connected(_));
        if connected && let Some(negotiated) = client.negotiated() {
            for (kind, name) in [
                (QueryKind::Nodes, capability::QUERY_NODES),
                (QueryKind::Routes, capability::QUERY_ROUTES),
                (QueryKind::Traffic, capability::QUERY_TRAFFIC),
            ] {
                if !negotiated.has_capability(name) {
                    continue;
                }
                let result =
                    limited(config.call_timeout, client.query(instance.clone(), kind)).await;
                let message = Msg::Queried {
                    watch,
                    kind,
                    result,
                };
                if inbox.send(message).await.is_err() {
                    return;
                }
            }
        }
        sleep(config.query_interval).await;
    }
}

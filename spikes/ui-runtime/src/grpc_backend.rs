use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use async_channel::{Receiver, Sender};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("spike.v1");
}

use proto::{
    PingReply, PingRequest, StatusEvent, SubscribeRequest,
    fake_host_client::FakeHostClient,
    fake_host_server::{FakeHost, FakeHostServer},
};

/// Commands sent from GPUI foreground thread into the background Tokio runtime.
#[derive(Debug)]
pub enum BridgeCommand {
    Ping { seq: u64 },
}

/// Events emitted by the background Tokio/tonic client to the GPUI foreground thread.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    Connected {
        addr: SocketAddr,
    },
    StatusTick {
        seq: u64,
        state: String,
    },
    Pong {
        seq: u64,
        server_tick: u64,
        rtt: Duration,
    },
    SubscriptionStopped {
        last_seq: u64,
    },
    Error(String),
}

struct FakeHostImpl {
    tick: Arc<AtomicU64>,
    server_shutdown: CancellationToken,
}

#[tonic::async_trait]
impl FakeHost for FakeHostImpl {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let seq = request.into_inner().seq;
        let server_tick = self.tick.load(Ordering::Relaxed);
        Ok(Response::new(PingReply { seq, server_tick }))
    }

    type SubscribeStream = ReceiverStream<Result<StatusEvent, Status>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let mut seq = request.into_inner().from_seq;
        let tick = self.tick.clone();
        let shutdown = self.server_shutdown.clone();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(20));
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tx.closed() => break,
                    _ = interval.tick() => {
                        seq += 1;
                        tick.store(seq, Ordering::Relaxed);
                        let event = StatusEvent {
                            seq,
                            state: format!("running(tick={seq})"),
                        };
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Dedicated background-thread Tokio runtime + tonic client + in-process fake tonic server.
///
/// A1 reuse note: in `etd-app::bridge`, replace the in-process `FakeHostServer` setup with
/// `etd-client::GrpcHostClient::connect(...)` while keeping the exact same `async-channel`
/// boundary, `CancellationToken` hierarchy, and two-stage (`stop_subscription` -> `stop_tokio`)
/// teardown.
pub struct TokioBridge {
    cmd_tx: Sender<BridgeCommand>,
    evt_rx: Receiver<BridgeEvent>,
    sub_cancel: CancellationToken,
    sub_stopped_rx: Receiver<u64>,
    runtime_shutdown: CancellationToken,
    bg_thread: Option<JoinHandle<()>>,
}

impl TokioBridge {
    pub fn start() -> Result<Self> {
        let (cmd_tx, cmd_rx) = async_channel::bounded::<BridgeCommand>(64);
        let (evt_tx, evt_rx) = async_channel::bounded::<BridgeEvent>(256);
        let (sub_stopped_tx, sub_stopped_rx) = async_channel::bounded::<u64>(1);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<SocketAddr>>(1);

        let sub_cancel = CancellationToken::new();
        let runtime_shutdown = CancellationToken::new();

        let sub_cancel_bg = sub_cancel.clone();
        let runtime_shutdown_bg = runtime_shutdown.clone();

        let bg_thread = thread::Builder::new()
            .name("etd-tokio-bg".to_owned())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("etd-tokio-worker")
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(err) => {
                        let _ = ready_tx.send(Err(anyhow!("failed to build tokio runtime: {err}")));
                        return;
                    }
                };

                rt.block_on(async move {
                    run_tokio_actor(
                        cmd_rx,
                        evt_tx,
                        sub_cancel_bg,
                        sub_stopped_tx,
                        runtime_shutdown_bg,
                        ready_tx,
                    )
                    .await;
                });

                // Bounded shutdown ensures any lingering HTTP/2 background task cannot hang exit.
                rt.shutdown_timeout(Duration::from_secs(2));
            })
            .context("failed to spawn background tokio thread")?;

        let addr = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .context("timed out waiting for tokio/tonic startup")??;
        eprintln!("[bridge] background tokio + fake tonic server ready at {addr}");

        Ok(Self {
            cmd_tx,
            evt_rx,
            sub_cancel,
            sub_stopped_rx,
            runtime_shutdown,
            bg_thread: Some(bg_thread),
        })
    }

    pub fn events(&self) -> Receiver<BridgeEvent> {
        self.evt_rx.clone()
    }

    pub fn try_send_ping(&self, seq: u64) -> Result<()> {
        self.cmd_tx
            .try_send(BridgeCommand::Ping { seq })
            .map_err(|err| anyhow!("failed to enqueue ping command: {err}"))
    }

    /// Exit phase 1: stop the active gRPC subscription stream and confirm it closed.
    pub async fn stop_subscription(&self) -> Result<u64> {
        self.sub_cancel.cancel();
        let last_seq = self
            .sub_stopped_rx
            .recv()
            .await
            .context("subscription stopped signal channel closed unexpectedly")?;
        Ok(last_seq)
    }

    /// Exit phase 2: tear down the Tokio runtime and join the background OS thread.
    ///
    /// Call this from a background executor thread (not the GPUI UI thread) so the Win32
    /// message loop stays responsive while joining.
    pub fn stop_tokio(mut self) -> Result<()> {
        self.cmd_tx.close();
        self.runtime_shutdown.cancel();
        if let Some(handle) = self.bg_thread.take() {
            handle
                .join()
                .map_err(|_| anyhow!("background tokio thread panicked during shutdown"))?;
        }
        Ok(())
    }
}

async fn run_tokio_actor(
    cmd_rx: Receiver<BridgeCommand>,
    evt_tx: Sender<BridgeEvent>,
    sub_cancel: CancellationToken,
    sub_stopped_tx: Sender<u64>,
    runtime_shutdown: CancellationToken,
    ready_tx: std::sync::mpsc::SyncSender<Result<SocketAddr>>,
) {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            let _ = ready_tx.send(Err(anyhow!("bind 127.0.0.1:0 failed: {err}")));
            return;
        }
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            let _ = ready_tx.send(Err(anyhow!("local_addr failed: {err}")));
            return;
        }
    };

    let server_shutdown = runtime_shutdown.clone();
    let service = FakeHostImpl {
        tick: Arc::new(AtomicU64::new(0)),
        server_shutdown: server_shutdown.clone(),
    };

    let server_handle = tokio::spawn(async move {
        let incoming = TcpListenerStream::new(listener);
        if let Err(err) = tonic::transport::Server::builder()
            .add_service(FakeHostServer::new(service))
            .serve_with_incoming_shutdown(incoming, server_shutdown.cancelled_owned())
            .await
        {
            eprintln!("[bridge] fake tonic server exited with error: {err}");
        }
    });

    let endpoint = format!("http://{addr}");
    let channel = match tonic::transport::Endpoint::from_shared(endpoint)
        .expect("valid loopback URI")
        .connect_timeout(Duration::from_secs(2))
        .connect()
        .await
    {
        Ok(ch) => ch,
        Err(err) => {
            let _ = ready_tx.send(Err(anyhow!("tonic client connect failed: {err}")));
            runtime_shutdown.cancel();
            let _ = server_handle.await;
            return;
        }
    };

    let _ = ready_tx.send(Ok(addr));
    let _ = evt_tx.send(BridgeEvent::Connected { addr }).await;

    // 1. Spawn server-streaming subscription task with dedicated cancellation token.
    let mut sub_client = FakeHostClient::new(channel.clone());
    let sub_evt_tx = evt_tx.clone();
    let sub_task_cancel = sub_cancel.clone();
    let sub_handle = tokio::spawn(async move {
        let mut last_seq = 0u64;
        match sub_client.subscribe(SubscribeRequest { from_seq: 0 }).await {
            Ok(resp) => {
                let mut stream = resp.into_inner();
                loop {
                    tokio::select! {
                        biased;
                        _ = sub_task_cancel.cancelled() => {
                            drop(stream);
                            break;
                        }
                        msg = stream.message() => {
                            match msg {
                                Ok(Some(ev)) => {
                                    last_seq = ev.seq;
                                    // Bounded backpressure: drop oldest / skip if UI is closing.
                                    let _ = sub_evt_tx.try_send(BridgeEvent::StatusTick {
                                        seq: ev.seq,
                                        state: ev.state,
                                    });
                                }
                                Ok(None) => break,
                                Err(status) => {
                                    let _ = sub_evt_tx.try_send(BridgeEvent::Error(format!(
                                        "subscribe stream error: {status}"
                                    )));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(status) => {
                let _ = sub_evt_tx.try_send(BridgeEvent::Error(format!(
                    "subscribe rpc failed: {status}"
                )));
            }
        }
        let _ = sub_evt_tx.try_send(BridgeEvent::SubscriptionStopped { last_seq });
        let _ = sub_stopped_tx.send(last_seq).await;
    });

    // 2. Drive unary commands until runtime shutdown is requested.
    let mut rpc_client = FakeHostClient::new(channel);
    loop {
        tokio::select! {
            biased;
            _ = runtime_shutdown.cancelled() => break,
            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(BridgeCommand::Ping { seq }) => {
                        let started = Instant::now();
                        match rpc_client.ping(PingRequest { seq }).await {
                            Ok(reply) => {
                                let reply = reply.into_inner();
                                let _ = evt_tx.try_send(BridgeEvent::Pong {
                                    seq: reply.seq,
                                    server_tick: reply.server_tick,
                                    rtt: started.elapsed(),
                                });
                            }
                            Err(status) => {
                                let _ = evt_tx.try_send(BridgeEvent::Error(format!(
                                    "ping rpc failed: {status}"
                                )));
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // Ensure subscription & server tasks finish cleanly before runtime drop.
    sub_cancel.cancel();
    let _ = sub_handle.await;
    let _ = server_handle.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_ordered_shutdown_stop_subscription_then_tokio() -> Result<()> {
        let bridge = TokioBridge::start()?;
        let events = bridge.events();
        bridge.try_send_ping(1)?;

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_tick = false;
        let mut saw_pong = false;
        while Instant::now() < deadline && (!saw_tick || !saw_pong) {
            match events.recv_blocking() {
                Ok(BridgeEvent::StatusTick { .. }) => saw_tick = true,
                Ok(BridgeEvent::Pong { seq: 1, .. }) => saw_pong = true,
                Ok(_) => {}
                Err(err) => return Err(anyhow!("event channel closed early: {err}")),
            }
        }
        assert!(saw_tick, "expected tonic subscribe stream ticks");
        assert!(saw_pong, "expected tonic unary ping/pong");

        let started = Instant::now();
        let last_seq = futures_executor_block_on(bridge.stop_subscription())?;
        assert!(last_seq > 0, "expected positive last_seq before stop");
        bridge.stop_tokio()?;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "ordered bridge teardown exceeded 5s"
        );
        Ok(())
    }

    fn futures_executor_block_on<F: std::future::Future>(fut: F) -> F::Output {
        // Use a tiny one-shot current_thread tokio runtime only inside this unit test.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(fut)
    }
}

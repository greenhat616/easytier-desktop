//! Adapt authenticated local connections to tonic on both sides of HTTP/2.
use crate::{BoxConn, Connector, Endpoint, Listener, PeerIdentity};
use futures_util::{Stream, stream};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::{transport::Uri, transport::server::Connected};
use tower::Service;

pub struct ServerIo {
    stream: BoxConn,
    peer: PeerIdentity,
}

impl Connected for ServerIo {
    type ConnectInfo = PeerIdentity;
    fn connect_info(&self) -> PeerIdentity {
        self.peer.clone()
    }
}

impl AsyncRead for ServerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Feed directly to tonic's `serve_with_incoming[_shutdown]`.
pub fn incoming<L: Listener>(listener: L) -> impl Stream<Item = io::Result<ServerIo>> {
    stream::unfold(listener, |mut listener| async move {
        let item = listener
            .accept()
            .await
            .map(|(stream, peer)| ServerIo { stream, peer });
        Some((item, listener))
    })
}

/// A tower connector for tonic's `connect_with_connector`. Reconnects pass
/// through the same native verification as the initial connection.
#[derive(Clone)]
pub struct ClientIo {
    connector: Arc<dyn Connector>,
    endpoint: Endpoint,
}

impl ClientIo {
    pub fn new(connector: Arc<dyn Connector>, endpoint: Endpoint) -> Self {
        Self {
            connector,
            endpoint,
        }
    }
}

impl Service<Uri> for ClientIo {
    type Response = TokioIo<BoxConn>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let (stream, _) = this.connector.connect(&this.endpoint).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

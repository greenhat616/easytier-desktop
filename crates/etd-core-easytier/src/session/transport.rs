//! OS TCP adaptation only: upstream owns its framing and RPC protocol.
use easytier_core::{
    connectivity::protocol::raw::TunnelDialer,
    socket::tcp::{VirtualTcpSocket, VirtualTcpSplit},
    tunnel::{Tunnel, tcp::TcpTunnelUpgrader},
};
use easytier_proto::common::TunnelInfo;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use url::Url;

pub(super) struct LoopbackDialer(pub SocketAddr);

#[async_trait::async_trait]
impl TunnelDialer for LoopbackDialer {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        let stream =
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(self.0)).await??;
        stream.set_nodelay(true)?;
        let local = stream.local_addr()?;
        let remote = stream.peer_addr()?;
        Ok(TcpTunnelUpgrader::new(TunnelInfo {
            tunnel_type: "tcp".into(),
            local_addr: Some(tcp_url(local).into()),
            remote_addr: Some(tcp_url(remote).into()),
            resolved_remote_addr: Some(tcp_url(remote).into()),
        })
        .upgrade(Socket(stream))?)
    }

    fn remote_url(&self) -> Url {
        tcp_url(self.0)
    }
}

fn tcp_url(addr: SocketAddr) -> Url {
    // SocketAddr formatting supplies a numeric host and brackets IPv6.
    format!("tcp://{addr}").parse().expect("numeric TCP URL")
}

struct Socket(TcpStream);

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl VirtualTcpSocket for Socket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }
    fn into_split(self) -> VirtualTcpSplit {
        let (reader, writer) = self.0.into_split();
        (Box::new(reader), Box::new(writer))
    }
}

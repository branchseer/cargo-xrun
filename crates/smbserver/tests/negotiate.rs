//! End-to-end negotiate test using smb-rs as the in-process client.
//!
//! Hermetic: client and server are wired together via a single
//! `tokio::io::duplex` pipe. No sockets, no listener, no port races.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use smb::transport::{SmbTransport, SmbTransportRead, SmbTransportWrite};
use smb::transport::error::{Result as TransportResult, TransportError};
use smb::{Connection, ConnectionConfig, Guid};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

const FAKE_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 445);

/// Adapts a `tokio::io::DuplexStream` to smb-rs's `SmbTransport` trait.
///
/// Only the methods exercised by `Connection::from_transport` are
/// implemented; `connect`/`default_port` are unused on this code path.
struct DuplexTransport {
    reader: Option<ReadHalf<DuplexStream>>,
    writer: Option<WriteHalf<DuplexStream>>,
}

impl DuplexTransport {
    fn new(stream: DuplexStream) -> Self {
        let (r, w) = io::split(stream);
        Self { reader: Some(r), writer: Some(w) }
    }
}

impl SmbTransport for DuplexTransport {
    fn connect<'a>(
        &'a mut self,
        _server_name: &'a str,
        _addr: SocketAddr,
    ) -> BoxFuture<'a, TransportResult<()>> {
        async { Ok(()) }.boxed()
    }

    fn default_port(&self) -> u16 {
        445
    }

    fn split(
        self: Box<Self>,
    ) -> TransportResult<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        let r = self.reader.ok_or(TransportError::NotConnected)?;
        let w = self.writer.ok_or(TransportError::NotConnected)?;
        Ok((Box::new(ReadHalfTransport(r)), Box::new(WriteHalfTransport(w))))
    }

    fn remote_address(&self) -> TransportResult<SocketAddr> {
        Ok(FAKE_REMOTE)
    }
}

impl SmbTransportRead for DuplexTransport {
    fn receive_exact<'a>(
        &'a mut self,
        out_buf: &'a mut [u8],
    ) -> BoxFuture<'a, TransportResult<()>> {
        async move {
            let r = self.reader.as_mut().ok_or(TransportError::NotConnected)?;
            r.read_exact(out_buf).await?;
            Ok(())
        }
        .boxed()
    }
}

impl SmbTransportWrite for DuplexTransport {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, TransportResult<()>> {
        async move {
            let w = self.writer.as_mut().ok_or(TransportError::NotConnected)?;
            w.write_all(buf).await?;
            Ok(())
        }
        .boxed()
    }
}

struct ReadHalfTransport(ReadHalf<DuplexStream>);
struct WriteHalfTransport(WriteHalf<DuplexStream>);

impl SmbTransportRead for ReadHalfTransport {
    fn receive_exact<'a>(
        &'a mut self,
        out_buf: &'a mut [u8],
    ) -> BoxFuture<'a, TransportResult<()>> {
        async move {
            self.0.read_exact(out_buf).await?;
            Ok(())
        }
        .boxed()
    }
}

impl SmbTransportWrite for WriteHalfTransport {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, TransportResult<()>> {
        async move {
            self.0.write_all(buf).await?;
            Ok(())
        }
        .boxed()
    }
}

struct NoFs;
impl smbserver::Filesystem for NoFs {}

#[tokio::test]
#[ntest::timeout(3000)]
async fn client_negotiates_smb2() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = smbserver::Server::builder().build(NoFs);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        ..Default::default()
    };

    let conn = Connection::from_transport(transport, "test-server", Guid::generate(), config)
        .await
        .expect("NEGOTIATE returned an error");

    server_task.abort();
    drop(conn);
}

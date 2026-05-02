//! Shared helpers for integration tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use smb::transport::error::{Result as TransportResult, TransportError};
use smb::transport::{SmbTransport, SmbTransportRead, SmbTransportWrite};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

const FAKE_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 445);

/// Adapts a `tokio::io::DuplexStream` to smb-rs's `SmbTransport` trait so the
/// in-process duplex pipe can stand in for a TCP socket.
pub struct DuplexTransport {
    reader: Option<ReadHalf<DuplexStream>>,
    writer: Option<WriteHalf<DuplexStream>>,
}

impl DuplexTransport {
    pub fn new(stream: DuplexStream) -> Self {
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

pub struct NoFs;
impl smbserver::Filesystem for NoFs {
    fn open(&self, _path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "NoFs has no files",
        ))
    }
}

/// In-memory filesystem for tests. Files are pre-populated; opens look up
/// by exact path match. Writes are visible across handles to the same path.
#[derive(Default, Clone)]
pub struct InMemoryFs {
    files: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>>,
        >,
    >,
}

impl InMemoryFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) {
        let path = path.into();
        let content = content.into();
        self.files
            .lock()
            .unwrap()
            .insert(path, std::sync::Arc::new(std::sync::Mutex::new(content)));
    }

    /// Snapshot the current contents of `path`. Returns `None` if the file
    /// does not exist. Useful for asserting writes landed.
    pub fn snapshot(&self, path: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|data| data.lock().unwrap().clone())
    }
}

impl smbserver::Filesystem for InMemoryFs {
    fn open(&self, path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        match self.files.lock().unwrap().get(path) {
            Some(data) => Ok(std::sync::Arc::new(MemFile { data: data.clone() })),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such file: {path}"),
            )),
        }
    }
}

struct MemFile {
    data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl smbserver::FileHandle for MemFile {
    fn size(&self) -> u64 {
        self.data.lock().unwrap().len() as u64
    }

    fn read(&self, offset: u64, len: u32) -> std::io::Result<Vec<u8>> {
        let data = self.data.lock().unwrap();
        let start = offset as usize;
        if start >= data.len() {
            return Ok(Vec::new());
        }
        let end = (start + len as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }

    fn write(&self, offset: u64, payload: &[u8]) -> std::io::Result<u32> {
        let mut data = self.data.lock().unwrap();
        let start = offset as usize;
        let end = start + payload.len();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(payload);
        Ok(payload.len() as u32)
    }
}

/// Standard guest credentials used by test setups.
pub fn guest_identity() -> sspi::AuthIdentity {
    sspi::AuthIdentity {
        username: sspi::Username::parse("guest").expect("valid username"),
        password: sspi::Secret::from(String::new()),
    }
}

/// Drive smb-rs through NEGOTIATE + SESSION_SETUP + TREE_CONNECT and
/// hand back the connected Tree.
pub async fn connect_and_tree_connect(
    client_io: tokio::io::DuplexStream,
    share_path: &str,
) -> (smb::Connection, smb::Session, smb::Tree) {
    let transport = Box::new(DuplexTransport::new(client_io));
    let config = smb::ConnectionConfig {
        smb2_only_negotiate: true,
        allow_unsigned_guest_access: true,
        ..smb::ConnectionConfig::default()
    };
    let conn = smb::Connection::from_transport(
        transport,
        "test-server",
        smb::Guid::generate(),
        config,
    )
    .await
    .expect("NEGOTIATE failed");
    let session = conn
        .authenticate(guest_identity())
        .await
        .expect("SESSION_SETUP failed");
    let target =
        smb::UncPath::from_str(share_path).expect("valid UNC path");
    let tree = session
        .tree_connect(&target)
        .await
        .expect("TREE_CONNECT failed");
    (conn, session, tree)
}

use std::str::FromStr;

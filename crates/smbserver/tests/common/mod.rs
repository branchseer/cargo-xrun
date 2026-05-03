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

#[allow(dead_code)]
pub struct NoFs;
impl smbserver::Filesystem for NoFs {
    fn open(&self, _path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "NoFs has no files",
        ))
    }
}

/// File entry in the InMemoryFs map: shared content + per-entry metadata.
struct FileEntry {
    data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    created_at: u64,
    modified_at: u64,
}

/// In-memory filesystem for tests. Files are pre-populated; opens look up
/// by exact path match. Writes are visible across handles to the same path.
///
/// Directories are inferred from file paths plus an explicit set populated
/// by `add_directory` and `create_dir` (so empty directories can exist).
#[derive(Default, Clone)]
pub struct InMemoryFs {
    files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, FileEntry>>>,
    explicit_dirs: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Subscribers per directory path. `notify` fans out to all matching.
    watchers: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                String,
                Vec<tokio::sync::mpsc::UnboundedSender<smbserver::DirChange>>,
            >,
        >,
    >,
}

impl InMemoryFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: impl Into<String>, content: impl Into<Vec<u8>>) {
        self.add_file_with_timestamps(path, content, 0, 0);
    }

    /// Like `add_file` but with explicit FILETIME timestamps. Useful for
    /// QUERY_INFO tests that assert non-zero values on the wire.
    pub fn add_file_with_timestamps(
        &mut self,
        path: impl Into<String>,
        content: impl Into<Vec<u8>>,
        created_at: u64,
        modified_at: u64,
    ) {
        self.files.lock().unwrap().insert(
            path.into(),
            FileEntry {
                data: std::sync::Arc::new(std::sync::Mutex::new(content.into())),
                created_at,
                modified_at,
            },
        );
    }

    /// Mark `path` as an existing directory. Lets tests assert clients can
    /// open empty directories (no children to infer from).
    pub fn has_directory(&self, path: &str) -> bool {
        self.explicit_dirs.lock().unwrap().contains(path)
            || self.files.lock().unwrap().keys().any(|p| {
                let prefix = format!("{path}/");
                p.starts_with(&prefix)
            })
    }

    /// Push a synthetic change event to all watchers registered against
    /// `dir_path`. Lets tests trigger CHANGE_NOTIFY responses on demand.
    pub fn notify(&self, dir_path: &str, name: impl Into<String>, kind: smbserver::ChangeKind) {
        let path = name.into();
        if let Some(subs) = self.watchers.lock().unwrap().get_mut(dir_path) {
            subs.retain(|tx| {
                tx.send(smbserver::DirChange { path: path.clone(), kind }).is_ok()
            });
        }
    }

    /// Snapshot the current contents of `path`. Returns `None` if the file
    /// does not exist. Useful for asserting writes landed.
    pub fn snapshot(&self, path: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .map(|entry| entry.data.lock().unwrap().clone())
    }
}

impl smbserver::Filesystem for InMemoryFs {
    fn open(&self, path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        let files = self.files.lock().unwrap();
        // File match wins.
        if let Some(entry) = files.get(path) {
            return Ok(std::sync::Arc::new(MemFile {
                data: entry.data.clone(),
                created_at: entry.created_at,
                modified_at: entry.modified_at,
            }));
        }
        // Otherwise treat as directory if it's the root, was explicitly
        // created, or has any descendants.
        let is_root = path.is_empty();
        let prefix = if is_root { String::new() } else { format!("{path}/") };
        let has_children = files.keys().any(|p| p.starts_with(&prefix));
        let explicitly_created = self.explicit_dirs.lock().unwrap().contains(path);
        if is_root || has_children || explicitly_created {
            return Ok(std::sync::Arc::new(MemDir {
                fs: self.clone(),
                path: path.to_string(),
            }));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no such path: {path}"),
        ))
    }

    fn create(&self, path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        let mut files = self.files.lock().unwrap();
        let entry = files.entry(path.to_string()).or_insert_with(|| FileEntry {
            data: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            created_at: 0,
            modified_at: 0,
        });
        // Replace contents — SUPERSEDE/OVERWRITE_IF semantics.
        entry.data.lock().unwrap().clear();
        Ok(std::sync::Arc::new(MemFile {
            data: entry.data.clone(),
            created_at: entry.created_at,
            modified_at: entry.modified_at,
        }))
    }

    fn create_dir(
        &self,
        path: &str,
    ) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        if self.files.lock().unwrap().contains_key(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{path} exists as a file"),
            ));
        }
        self.explicit_dirs.lock().unwrap().insert(path.to_string());
        Ok(std::sync::Arc::new(MemDir {
            fs: self.clone(),
            path: path.to_string(),
        }))
    }

    fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
        let mut files = self.files.lock().unwrap();
        let data = files.remove(from).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("no such file: {from}"))
        })?;
        if files.contains_key(to) {
            // Restore source so the rename is atomic from the FS's POV.
            files.insert(from.to_string(), data);
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("destination exists: {to}"),
            ));
        }
        files.insert(to.to_string(), data);
        Ok(())
    }

    fn watch(&self, dir_path: &str, _recursive: bool) -> Option<Box<dyn smbserver::Watcher>> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<smbserver::DirChange>();
        self.watchers
            .lock()
            .unwrap()
            .entry(dir_path.to_string())
            .or_default()
            .push(tx);
        Some(Box::new(MemWatcher { rx }))
    }

    fn volume_info(&self) -> smbserver::VolumeInfo {
        smbserver::VolumeInfo {
            label: "InMemoryFs".to_string(),
            serial_number: 0xDEAD_BEEF,
            total_bytes: 1024 * 1024 * 1024,        // 1 GiB
            available_bytes: 512 * 1024 * 1024,     // 512 MiB
            bytes_per_sector: 512,
            sectors_per_unit: 8,
            fs_name: "InMemoryFs".to_string(),
            case_sensitive: true,
            max_component_length: 255,
        }
    }

    fn delete(&self, path: &str) -> std::io::Result<()> {
        if self.files.lock().unwrap().remove(path).is_some() {
            return Ok(());
        }
        if self.explicit_dirs.lock().unwrap().remove(path) {
            return Ok(());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no such file: {path}"),
        ))
    }
}

impl InMemoryFs {
    fn list_internal(&self, dir_path: &str) -> Vec<smbserver::DirEntry> {
        let files = self.files.lock().unwrap();
        let prefix = if dir_path.is_empty() {
            String::new()
        } else {
            format!("{dir_path}/")
        };
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut entries = Vec::new();
        for (path, entry) in files.iter() {
            if !path.starts_with(&prefix) {
                continue;
            }
            let rest = &path[prefix.len()..];
            if rest.is_empty() {
                continue;
            }
            match rest.find('/') {
                Some(slash) => {
                    let name = &rest[..slash];
                    if seen.insert(name.to_string()) {
                        entries.push(smbserver::DirEntry {
                            name: name.to_string(),
                            size: 0,
                            is_dir: true,
                        });
                    }
                }
                None => {
                    if seen.insert(rest.to_string()) {
                        entries.push(smbserver::DirEntry {
                            name: rest.to_string(),
                            size: entry.data.lock().unwrap().len() as u64,
                            is_dir: false,
                        });
                    }
                }
            }
        }
        // Stable ordering for deterministic tests.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

struct MemWatcher {
    rx: tokio::sync::mpsc::UnboundedReceiver<smbserver::DirChange>,
}

impl smbserver::Watcher for MemWatcher {
    fn next<'a>(
        &'a mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<Vec<smbserver::DirChange>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let first = self.rx.recv().await?;
            Some(vec![first])
        })
    }
}

struct MemDir {
    fs: InMemoryFs,
    path: String,
}

impl smbserver::FileHandle for MemDir {
    fn size(&self) -> u64 {
        0
    }
    fn is_directory(&self) -> bool {
        true
    }
    fn list_children(&self) -> std::io::Result<Vec<smbserver::DirEntry>> {
        Ok(self.fs.list_internal(&self.path))
    }
}

struct MemFile {
    data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    created_at: u64,
    modified_at: u64,
}

impl smbserver::FileHandle for MemFile {
    fn size(&self) -> u64 {
        self.data.lock().unwrap().len() as u64
    }

    fn metadata(&self) -> smbserver::FileMetadata {
        let size = self.data.lock().unwrap().len() as u64;
        smbserver::FileMetadata {
            size,
            allocation_size: size,
            creation_time: self.created_at,
            last_access_time: self.modified_at,
            last_write_time: self.modified_at,
            change_time: self.modified_at,
            is_directory: false,
        }
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

    fn truncate(&self, size: u64) -> std::io::Result<()> {
        let mut data = self.data.lock().unwrap();
        data.resize(size as usize, 0);
        Ok(())
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

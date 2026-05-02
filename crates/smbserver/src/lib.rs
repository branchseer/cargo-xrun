use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::Arc;

use binrw::{BinRead, BinWrite};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod fs;
pub mod ntlmssp;
pub mod wire;

pub use fs::{DirEntry, FileHandle, Filesystem};

use wire::close::{CloseRequest, CloseResponse};
use wire::create::{CreateRequest, CreateResponse};
use wire::echo::{EchoRequest, EchoResponse};
use wire::error::ErrorResponse;
use wire::flush::{FlushRequest, FlushResponse};
use wire::fscc::FileBothDirectoryInformation;
use wire::header::Header;
use wire::logoff::{LogoffRequest, LogoffResponse};
use wire::negotiate::{NegotiateRequest, NegotiateResponse};
use wire::query_directory::{QueryDirectoryRequest, QueryDirectoryResponse};
use wire::read::{ReadRequest, ReadResponse};
use wire::session_setup::{SessionSetupRequest, SessionSetupResponse};
use wire::tree_connect::{TreeConnectRequest, TreeConnectResponse};
use wire::tree_disconnect::{TreeDisconnectRequest, TreeDisconnectResponse};
use wire::write::{WriteRequest, WriteResponse};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const COMMAND_NEGOTIATE: u16 = 0x0000;
const COMMAND_SESSION_SETUP: u16 = 0x0001;
const COMMAND_LOGOFF: u16 = 0x0002;
const COMMAND_TREE_CONNECT: u16 = 0x0003;
const COMMAND_TREE_DISCONNECT: u16 = 0x0004;
const COMMAND_CREATE: u16 = 0x0005;
const COMMAND_CLOSE: u16 = 0x0006;
const COMMAND_FLUSH: u16 = 0x0007;
const COMMAND_READ: u16 = 0x0008;
const COMMAND_WRITE: u16 = 0x0009;
const COMMAND_ECHO: u16 = 0x000D;
const COMMAND_QUERY_DIRECTORY: u16 = 0x000E;
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
/// File attribute: directory. MS-FSCC §2.6.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// QUERY_DIRECTORY request flag.
const QUERY_DIR_FLAG_RESTART_SCANS: u8 = 0x01;
/// File attribute: regular file. MS-FSCC §2.6.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// CREATE Action: existing file was opened. MS-SMB2 §2.2.14.
const FILE_OPENED: u32 = 0x0000_0001;
/// CREATE Action: new file was created. MS-SMB2 §2.2.14.
const FILE_CREATED: u32 = 0x0000_0002;
/// CREATE Disposition values. MS-SMB2 §2.2.13.
const FILE_DISP_SUPERSEDE: u32 = 0x0000_0000;
const FILE_DISP_OPEN: u32 = 0x0000_0001;
const FILE_DISP_CREATE: u32 = 0x0000_0002;
const FILE_DISP_OPEN_IF: u32 = 0x0000_0003;
const FILE_DISP_OVERWRITE: u32 = 0x0000_0004;
const FILE_DISP_OVERWRITE_IF: u32 = 0x0000_0005;
/// Status returned for CREATE Create disposition when target exists.
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const DIALECT_SMB_2_1: u16 = 0x0210;
/// First session id we hand out. SMB session ids must be non-zero.
const FIRST_SESSION_ID: u64 = 0x1000_0000_0000_0001;
/// Hardcoded server GUID. Real servers MAY persist this; for now a static
/// value is fine — clients only echo it back during multichannel binding.
const SERVER_GUID: [u8; 16] = *b"smbserver-rs\0\0\0\0";

#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    /// Share name → backing filesystem. Names are case-insensitive on real
    /// servers; we match case-insensitively too (lowercased on insertion).
    shares: HashMap<String, Arc<dyn Filesystem>>,
}

#[derive(Default)]
pub struct ServerBuilder {
    shares: HashMap<String, Arc<dyn Filesystem>>,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    pub async fn serve_connection<S>(&self, mut io: S) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut conn = ConnectionState::new(self.inner.clone());
        loop {
            // SMB-over-TCP transport header: 1-byte zero + 24-bit big-endian length.
            let mut frame_header = [0u8; 4];
            match io.read_exact(&mut frame_header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let pdu_len = u32::from_be_bytes([0, frame_header[1], frame_header[2], frame_header[3]])
                as usize;
            let mut pdu = vec![0u8; pdu_len];
            io.read_exact(&mut pdu).await?;

            let response = match conn.handle_pdu(&pdu) {
                Some(bytes) => bytes,
                None => return Ok(()), // unsupported command — close connection
            };

            let len = response.len() as u32;
            let mut frame = Vec::with_capacity(4 + response.len());
            frame.extend_from_slice(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
            frame.extend_from_slice(&response);
            io.write_all(&frame).await?;
        }
    }
}

impl ServerBuilder {
    /// Register `fs` as the share named `name`. Multiple calls add
    /// multiple shares; clients route requests via the share component
    /// of their TREE_CONNECT path.
    pub fn share(mut self, name: impl Into<String>, fs: impl Filesystem) -> Self {
        self.shares.insert(name.into().to_lowercase(), Arc::new(fs));
        self
    }

    pub fn build(self) -> Server {
        Server {
            inner: Arc::new(Inner { shares: self.shares }),
        }
    }
}

/// Serialize a header + body pair into a single response buffer.
fn write_response<B>(header: Header, body: B, body_size_hint: usize) -> Vec<u8>
where
    B: BinWrite + binrw::meta::WriteEndian,
    for<'a> B: BinWrite<Args<'a> = ()>,
{
    let mut bytes = Vec::with_capacity(64 + body_size_hint);
    let mut out = Cursor::new(&mut bytes);
    header
        .write(&mut out)
        .expect("header serialize cannot fail");
    body.write(&mut out).expect("body serialize cannot fail");
    bytes
}

/// Resolve an SMB CREATE disposition into Filesystem ops, returning the
/// resulting handle and the `create_action` value to report to the client.
fn dispatch_create(
    fs: &dyn Filesystem,
    path: &str,
    disposition: u32,
) -> Result<(Arc<dyn FileHandle>, u32), u32> {
    match disposition {
        FILE_DISP_OPEN => fs
            .open(path)
            .map(|h| (h, FILE_OPENED))
            .map_err(map_io_err),
        FILE_DISP_CREATE => match fs.open(path) {
            Ok(_) => Err(STATUS_OBJECT_NAME_COLLISION),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs
                .create(path)
                .map(|h| (h, FILE_CREATED))
                .map_err(map_io_err),
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_OPEN_IF => match fs.open(path) {
            Ok(h) => Ok((h, FILE_OPENED)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs
                .create(path)
                .map(|h| (h, FILE_CREATED))
                .map_err(map_io_err),
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_SUPERSEDE | FILE_DISP_OVERWRITE_IF => match fs.create(path) {
            Ok(h) => Ok((h, FILE_CREATED)),
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_OVERWRITE => match fs.open(path) {
            Ok(_) => fs
                .create(path)
                .map(|h| (h, FILE_CREATED))
                .map_err(map_io_err),
            Err(e) => Err(map_io_err(e)),
        },
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

fn map_io_err(e: std::io::Error) -> u32 {
    match e.kind() {
        std::io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        std::io::ErrorKind::Unsupported => STATUS_ACCESS_DENIED,
        std::io::ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// Marshal a list of `DirEntry` as a chain of FILE_BOTH_DIR_INFORMATION
/// records, each padded to an 8-byte boundary, with `next_entry_offset`
/// patched to the byte distance to the next entry (0 for the last).
fn marshal_dir_entries(entries: &[DirEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut entry_starts = Vec::with_capacity(entries.len());

    for entry in entries {
        entry_starts.push(buf.len());
        let name_bytes: Vec<u8> = entry
            .name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let info = FileBothDirectoryInformation {
            next_entry_offset: 0,
            file_index: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            end_of_file: entry.size,
            allocation_size: entry.size,
            file_attributes: if entry.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
            ea_size: 0,
            short_name_length: 0,
            reserved: 0,
            short_name: [0; 24],
            file_name: name_bytes,
        };
        let mut record = Vec::new();
        info.write(&mut Cursor::new(&mut record))
            .expect("FileBothDirectoryInformation serialize cannot fail");
        buf.extend_from_slice(&record);
        // Pad to 8-byte boundary between entries.
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
    }

    // Patch next_entry_offset on every entry except the last.
    for i in 0..entry_starts.len().saturating_sub(1) {
        let here = entry_starts[i];
        let next = entry_starts[i + 1];
        let delta = (next - here) as u32;
        buf[here..here + 4].copy_from_slice(&delta.to_le_bytes());
    }
    buf
}

/// Extract the share name from a TREE_CONNECT path like
/// `\\server\share` or `\\server\share\subpath`. Returns `None` if the
/// path is malformed (no share component).
fn share_name_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('\\');
    // After trimming, expect "server\share" or "server\share\..."
    let (_server, rest) = trimmed.split_once('\\')?;
    let share = rest.split('\\').next()?;
    if share.is_empty() {
        None
    } else {
        Some(share.to_string())
    }
}

/// Decode a UTF-16LE byte buffer (as carried in SMB2 name fields) to UTF-8.
fn decode_utf16le(bytes: &[u8]) -> Result<String, std::string::FromUtf16Error> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units)
}

/// Per-TCP-connection state. Holds the file handle table and any other
/// state that lasts for the lifetime of one accepted socket.
struct ConnectionState {
    inner: Arc<Inner>,
    open_files: HashMap<u64, Arc<dyn FileHandle>>,
    next_file_id: u64,
    /// FileIds whose directory listing has been fully delivered. Cleared
    /// when the client sends QUERY_DIRECTORY with the RESTART_SCANS flag.
    listed_dirs: HashSet<u64>,
    /// TreeId → backing filesystem for that share. Populated on
    /// TREE_CONNECT, cleared on TREE_DISCONNECT.
    trees: HashMap<u32, Arc<dyn Filesystem>>,
    next_tree_id: u32,
}

impl ConnectionState {
    fn new(inner: Arc<Inner>) -> Self {
        Self {
            inner,
            open_files: HashMap::new(),
            next_file_id: 1,
            listed_dirs: HashSet::new(),
            trees: HashMap::new(),
            next_tree_id: 1,
        }
    }

    fn handle_pdu(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(pdu);
        let request_header = Header::read(&mut cursor).ok()?;

        match request_header.command {
            COMMAND_NEGOTIATE => Some(self.handle_negotiate(request_header, &mut cursor)),
            COMMAND_SESSION_SETUP => Some(self.handle_session_setup(request_header, &mut cursor)),
            COMMAND_TREE_CONNECT => Some(self.handle_tree_connect(request_header, &mut cursor)),
            COMMAND_CREATE => Some(self.handle_create(request_header, &mut cursor)),
            COMMAND_CLOSE => Some(self.handle_close(request_header, &mut cursor)),
            COMMAND_READ => Some(self.handle_read(request_header, &mut cursor)),
            COMMAND_WRITE => Some(self.handle_write(request_header, &mut cursor)),
            COMMAND_QUERY_DIRECTORY => {
                Some(self.handle_query_directory(request_header, &mut cursor))
            }
            COMMAND_TREE_DISCONNECT => {
                Some(self.handle_tree_disconnect(request_header, &mut cursor))
            }
            COMMAND_LOGOFF => Some(self.handle_logoff(request_header, &mut cursor)),
            COMMAND_FLUSH => Some(self.handle_flush(request_header, &mut cursor)),
            COMMAND_ECHO => Some(self.handle_echo(request_header, &mut cursor)),
            _ => None,
        }
    }

    fn handle_tree_disconnect(
        &mut self,
        request_header: Header,
        cursor: &mut Cursor<&[u8]>,
    ) -> Vec<u8> {
        let _ = TreeDisconnectRequest::read(cursor);
        self.trees.remove(&request_header.tree_id);
        let response_header = self.simple_response_header(&request_header, COMMAND_TREE_DISCONNECT);
        let response_body = TreeDisconnectResponse {
            structure_size: 4,
            reserved: 0,
        };
        write_response(response_header, response_body, 4)
    }

    fn handle_logoff(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let _ = LogoffRequest::read(cursor);
        let response_header = self.simple_response_header(&request_header, COMMAND_LOGOFF);
        let response_body = LogoffResponse {
            structure_size: 4,
            reserved: 0,
        };
        write_response(response_header, response_body, 4)
    }

    fn handle_flush(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let _ = FlushRequest::read(cursor);
        let response_header = self.simple_response_header(&request_header, COMMAND_FLUSH);
        let response_body = FlushResponse {
            structure_size: 4,
            reserved: 0,
        };
        write_response(response_header, response_body, 4)
    }

    fn handle_echo(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let _ = EchoRequest::read(cursor);
        let response_header = self.simple_response_header(&request_header, COMMAND_ECHO);
        let response_body = EchoResponse {
            structure_size: 4,
            reserved: 0,
        };
        write_response(response_header, response_body, 4)
    }

    fn simple_response_header(&self, request_header: &Header, command: u16) -> Header {
        Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        }
    }

    fn handle_query_directory(
        &mut self,
        request_header: Header,
        cursor: &mut Cursor<&[u8]>,
    ) -> Vec<u8> {
        let request = match QueryDirectoryRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let handle = match self.open_files.get(&request.file_id_volatile) {
            Some(h) => h.clone(),
            None => return self.error_response(request_header, STATUS_FILE_CLOSED),
        };

        if !handle.is_directory() {
            return self.error_response(request_header, STATUS_INVALID_PARAMETER);
        }

        if request.flags & QUERY_DIR_FLAG_RESTART_SCANS != 0 {
            self.listed_dirs.remove(&request.file_id_volatile);
        }

        if self.listed_dirs.contains(&request.file_id_volatile) {
            return self.error_response(request_header, STATUS_NO_MORE_FILES);
        }

        let entries = match handle.list_children() {
            Ok(e) => e,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        if entries.is_empty() {
            self.listed_dirs.insert(request.file_id_volatile);
            return self.error_response(request_header, STATUS_NO_MORE_FILES);
        }

        let buffer = marshal_dir_entries(&entries);
        self.listed_dirs.insert(request.file_id_volatile);

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_QUERY_DIRECTORY,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = QueryDirectoryResponse {
            structure_size: 9,
            output_buffer: buffer,
        };

        let mut bytes = Vec::with_capacity(64 + 8 + response_body.output_buffer.len());
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("query_directory response serialize cannot fail");
        bytes
    }

    fn handle_write(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match WriteRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let handle = match self.open_files.get(&request.file_id_volatile) {
            Some(h) => h.clone(),
            None => return self.error_response(request_header, STATUS_FILE_CLOSED),
        };

        let written = match handle.write(request.offset, &request.data) {
            Ok(n) => n,
            Err(e) => {
                let status = match e.kind() {
                    std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
                    std::io::ErrorKind::Unsupported => STATUS_ACCESS_DENIED,
                    _ => STATUS_INVALID_PARAMETER,
                };
                return self.error_response(request_header, status);
            }
        };

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_WRITE,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = WriteResponse {
            structure_size: 17,
            reserved: 0,
            count: written,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        let mut bytes = Vec::with_capacity(64 + 17);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("write response serialize cannot fail");
        bytes
    }

    fn handle_read(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match ReadRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let handle = match self.open_files.get(&request.file_id_volatile) {
            Some(h) => h.clone(),
            None => return self.error_response(request_header, STATUS_FILE_CLOSED),
        };

        let data = match handle.read(request.offset, request.length) {
            Ok(d) => d,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        if data.is_empty() && request.length > 0 {
            return self.error_response(request_header, STATUS_END_OF_FILE);
        }

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_READ,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = ReadResponse {
            structure_size: 17,
            reserved: 0,
            data_remaining: 0,
            flags: 0,
            data,
        };

        let mut bytes = Vec::with_capacity(64 + 16 + response_body.data.len());
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("read response serialize cannot fail");
        bytes
    }

    fn handle_close(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match CloseRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        // Pull the handle out (drop completes when nothing else holds it).
        let handle = self.open_files.remove(&request.file_id_volatile);
        self.listed_dirs.remove(&request.file_id_volatile);
        let size = handle.as_ref().map(|h| h.size()).unwrap_or(0);

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_CLOSE,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = CloseResponse {
            structure_size: 60,
            flags: 0,
            reserved: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: size,
            end_of_file: size,
            file_attributes: FILE_ATTRIBUTE_NORMAL,
        };

        let mut bytes = Vec::with_capacity(64 + 60);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("close response serialize cannot fail");
        bytes
    }

    fn handle_create(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match CreateRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let path = match decode_utf16le(&request.name) {
            Ok(p) => p,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let fs = match self.trees.get(&request_header.tree_id) {
            Some(fs) => fs.clone(),
            None => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let (handle, action) =
            match dispatch_create(&*fs, &path, request.create_disposition) {
                Ok(t) => t,
                Err(status) => return self.error_response(request_header, status),
            };

        let file_id = self.next_file_id;
        self.next_file_id += 1;
        let size = handle.size();
        let attrs = if handle.is_directory() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        self.open_files.insert(file_id, handle);

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_CREATE,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = CreateResponse {
            structure_size: 89,
            oplock_level: 0,
            flags: 0,
            create_action: action,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: size,
            end_of_file: size,
            file_attributes: attrs,
            reserved2: 0,
            file_id_persistent: file_id,
            file_id_volatile: file_id,
        };

        let mut bytes = Vec::with_capacity(64 + 89);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("create response serialize cannot fail");
        bytes
    }

    fn error_response(&self, request_header: Header, status: u32) -> Vec<u8> {
        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status,
            command: request_header.command,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: request_header.tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = ErrorResponse {
            structure_size: 9,
            error_context_count: 0,
            reserved: 0,
            error_data: vec![0],
        };

        let mut bytes = Vec::with_capacity(64 + 9);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail");
        response_body
            .write(&mut out)
            .expect("error response serialize cannot fail");
        bytes
    }

    fn handle_tree_connect(
        &mut self,
        request_header: Header,
        cursor: &mut Cursor<&[u8]>,
    ) -> Vec<u8> {
        let request = match TreeConnectRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let path = match decode_utf16le(&request.path) {
            Ok(p) => p,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let share_name = match share_name_from_path(&path) {
            Some(name) => name,
            None => return self.error_response(request_header, STATUS_BAD_NETWORK_NAME),
        };

        let fs = match self.inner.shares.get(&share_name.to_lowercase()) {
            Some(fs) => fs.clone(),
            None => return self.error_response(request_header, STATUS_BAD_NETWORK_NAME),
        };

        let tree_id = self.next_tree_id;
        self.next_tree_id += 1;
        self.trees.insert(tree_id, fs);

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_TREE_CONNECT,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id,
            session_id: request_header.session_id,
            signature: [0; 16],
        };

        let response_body = TreeConnectResponse {
            structure_size: 16,
            share_type: 0x01,
            reserved: 0,
            share_flags: 0x0000_0030,
            capabilities: 0,
            maximal_access: 0x001F_01FF,
        };

        write_response(response_header, response_body, 16)
    }

    fn handle_session_setup(
        &mut self,
        request_header: Header,
        cursor: &mut Cursor<&[u8]>,
    ) -> Vec<u8> {
        let request = SessionSetupRequest::read(cursor).ok();
        let is_authenticate = request
            .as_ref()
            .map(|r| ntlmssp::is_authenticate_message(&r.security_buffer))
            .unwrap_or(false);

        let session_id = if request_header.session_id == 0 {
            FIRST_SESSION_ID
        } else {
            request_header.session_id
        };

        let (status, security_buffer) = if is_authenticate {
            (STATUS_SUCCESS, vec![])
        } else {
            (STATUS_MORE_PROCESSING_REQUIRED, ntlmssp::challenge_message())
        };

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status,
            command: COMMAND_SESSION_SETUP,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: 0,
            session_id,
            signature: [0; 16],
        };

        let response_body = SessionSetupResponse {
            structure_size: 9,
            // SMB2_SESSION_FLAG_IS_GUEST so signing-required clients
            // accept us without a real session key. Real auth backends
            // would clear this and produce signed responses.
            session_flags: if status == STATUS_SUCCESS { 0x0001 } else { 0 },
            security_buffer,
        };

        let mut bytes = Vec::with_capacity(64 + 9);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail for fixed-size struct");
        response_body
            .write(&mut out)
            .expect("session_setup response serialize cannot fail");
        bytes
    }

    fn handle_negotiate(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        // Drain the request body so we faithfully exercise the parser even
        // though we don't use the values yet.
        let _ = NegotiateRequest::read(cursor);

        let response_header = Header {
            structure_size: 64,
            credit_charge: 0,
            status: STATUS_SUCCESS,
            command: COMMAND_NEGOTIATE,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: request_header.message_id,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        let response_body = NegotiateResponse {
            structure_size: 65,
            security_mode: 0,
            dialect_revision: DIALECT_SMB_2_1,
            negotiate_context_count: 0,
            server_guid: SERVER_GUID,
            capabilities: 0,
            max_transact_size: 0x0001_0000,
            max_read_size: 0x0001_0000,
            max_write_size: 0x0001_0000,
            system_time: 0,
            server_start_time: 0,
            negotiate_context_offset: 0,
            security_buffer: vec![],
        };

        let mut bytes = Vec::with_capacity(64 + 65);
        let mut cursor = Cursor::new(&mut bytes);
        response_header
            .write(&mut cursor)
            .expect("header serialize cannot fail for fixed-size struct");
        response_body
            .write(&mut cursor)
            .expect("negotiate response serialize cannot fail");
        bytes
    }
}

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use binrw::{BinRead, BinWrite};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod fs;
pub mod ntlmssp;
pub mod wire;

pub use fs::{FileHandle, Filesystem};

use wire::close::{CloseRequest, CloseResponse};
use wire::create::{CreateRequest, CreateResponse};
use wire::error::ErrorResponse;
use wire::header::Header;
use wire::negotiate::{NegotiateRequest, NegotiateResponse};
use wire::read::{ReadRequest, ReadResponse};
use wire::session_setup::{SessionSetupRequest, SessionSetupResponse};
use wire::tree_connect::{TreeConnectRequest, TreeConnectResponse};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const COMMAND_NEGOTIATE: u16 = 0x0000;
const COMMAND_SESSION_SETUP: u16 = 0x0001;
const COMMAND_TREE_CONNECT: u16 = 0x0003;
const COMMAND_CREATE: u16 = 0x0005;
const COMMAND_CLOSE: u16 = 0x0006;
const COMMAND_READ: u16 = 0x0008;
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
/// File attribute: regular file. MS-FSCC §2.6.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// CREATE Action: existing file was opened. MS-SMB2 §2.2.14.
const FILE_OPENED: u32 = 0x0000_0001;
const DIALECT_SMB_2_1: u16 = 0x0210;
/// First session id we hand out. SMB session ids must be non-zero.
const FIRST_SESSION_ID: u64 = 0x1000_0000_0000_0001;
/// Tree id we hand out on TREE_CONNECT. Must be non-zero.
const FIRST_TREE_ID: u32 = 0x0000_0001;
/// Hardcoded server GUID. Real servers MAY persist this; for now a static
/// value is fine — clients only echo it back during multichannel binding.
const SERVER_GUID: [u8; 16] = *b"smbserver-rs\0\0\0\0";

#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    fs: Box<dyn Filesystem>,
}

#[derive(Default)]
pub struct ServerBuilder {
    _private: (),
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
    pub fn build(self, fs: impl Filesystem) -> Server {
        Server {
            inner: Arc::new(Inner { fs: Box::new(fs) }),
        }
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
}

impl ConnectionState {
    fn new(inner: Arc<Inner>) -> Self {
        Self {
            inner,
            open_files: HashMap::new(),
            next_file_id: 1,
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
            _ => None,
        }
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

        let handle = match self.inner.fs.open(&path) {
            Ok(h) => h,
            Err(e) => {
                let status = match e.kind() {
                    std::io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
                    std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
                    _ => STATUS_INVALID_PARAMETER,
                };
                return self.error_response(request_header, status);
            }
        };

        let file_id = self.next_file_id;
        self.next_file_id += 1;
        let size = handle.size();
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
            create_action: FILE_OPENED,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: size,
            end_of_file: size,
            file_attributes: FILE_ATTRIBUTE_NORMAL,
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
        let _ = TreeConnectRequest::read(cursor);

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
            tree_id: FIRST_TREE_ID,
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

        let mut bytes = Vec::with_capacity(64 + 16);
        let mut out = Cursor::new(&mut bytes);
        response_header
            .write(&mut out)
            .expect("header serialize cannot fail for fixed-size struct");
        response_body
            .write(&mut out)
            .expect("tree_connect response serialize cannot fail");
        bytes
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

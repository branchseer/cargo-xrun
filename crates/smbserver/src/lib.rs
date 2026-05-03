//! Pure-Rust SMB2 server with a pluggable filesystem backend.
//!
//! # Quick start
//!
//! ```no_run
//! use smbserver::{FileHandle, Filesystem, Server};
//! use std::sync::Arc;
//!
//! struct MyFs;
//! impl Filesystem for MyFs {
//!     fn open(&self, _path: &str) -> std::io::Result<Arc<dyn FileHandle>> {
//!         Err(std::io::Error::new(std::io::ErrorKind::NotFound, ""))
//!     }
//! }
//!
//! # async fn run<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(io: S) {
//! let server = Server::builder().share("public", MyFs).build();
//! // For each accepted connection (TCP, in-process pipe, anything that
//! // implements AsyncRead + AsyncWrite + Unpin + Send):
//! let _ = server.serve_connection(io).await;
//! # }
//! ```
//!
//! # Architecture
//!
//! - [`Server`] holds the share registry and is cheaply cloneable. Spawn one
//!   `serve_connection` future per accepted socket.
//! - [`Filesystem`] is the pluggable backend trait. Methods have sensible
//!   defaults so a read-only backend only needs to implement `open`.
//! - [`FileHandle`] represents one open file/directory. Required: `size`.
//!   Optional: `read`, `write`, `truncate`, `flush`, `is_directory`,
//!   `metadata`, `list_children`.
//!
//! # Authentication
//!
//! The current SESSION_SETUP handler accepts any NTLMSSP exchange and
//! reports a guest session. There is no real credential validation. This
//! is suitable for testing and trusted networks; do not expose to the
//! public internet.

use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use binrw::{BinRead, BinWrite};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

pub mod fs;
pub mod ntlmssp;
pub mod wire;

pub use fs::{
    ChangeKind, DirChange, DirEntry, FileHandle, FileMetadata, Filesystem, VolumeInfo, Watcher,
};

use wire::close::{CloseRequest, CloseResponse};
use wire::create::{CreateRequest, CreateResponse};
use wire::echo::{EchoRequest, EchoResponse};
use wire::error::ErrorResponse;
use wire::flush::{FlushRequest, FlushResponse};
use wire::fscc::{
    FileBasicInformation, FileBothDirectoryInformation, FileDispositionInformation,
    FileEndOfFileInformation, FileFsAttributeInformation, FileFsFullSizeInformation,
    FileFsSizeInformation, FileFsVolumeInformation, FileNetworkOpenInformation,
    FileRenameInformation, FileStandardInformation,
};
use wire::header::Header;
use wire::logoff::{LogoffRequest, LogoffResponse};
use wire::negotiate::{NegotiateRequest, NegotiateResponse};
use wire::change_notify::{ChangeNotifyRequest, ChangeNotifyResponse};
use wire::query_directory::{QueryDirectoryRequest, QueryDirectoryResponse};
use wire::query_info::{QueryInfoRequest, QueryInfoResponse};
use wire::set_info::{SetInfoRequest, SetInfoResponse};
use wire::read::{ReadRequest, ReadResponse};
use wire::session_setup::{SessionSetupRequest, SessionSetupResponse};
use wire::tree_connect::{TreeConnectRequest, TreeConnectResponse};
use wire::tree_disconnect::{TreeDisconnectRequest, TreeDisconnectResponse};
use wire::write::{WriteRequest, WriteResponse};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;
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
const COMMAND_CHANGE_NOTIFY: u16 = 0x000F;
const COMMAND_QUERY_INFO: u16 = 0x0010;
const COMMAND_SET_INFO: u16 = 0x0011;
const COMMAND_CANCEL: u16 = 0x000C;
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_PENDING: u32 = 0x0000_0103;
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
/// CREATE Options bitfield values. MS-SMB2 §2.2.13.
const CREATE_OPT_DIRECTORY_FILE: u32 = 0x0000_0001;
const CREATE_OPT_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// CREATE Disposition values. MS-SMB2 §2.2.13.
const FILE_DISP_SUPERSEDE: u32 = 0x0000_0000;
const FILE_DISP_OPEN: u32 = 0x0000_0001;
const FILE_DISP_CREATE: u32 = 0x0000_0002;
const FILE_DISP_OPEN_IF: u32 = 0x0000_0003;
const FILE_DISP_OVERWRITE: u32 = 0x0000_0004;
const FILE_DISP_OVERWRITE_IF: u32 = 0x0000_0005;
/// Status returned for CREATE Create disposition when target exists.
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
/// Returned for QUERY_INFO/SET_INFO when the requested info class is unsupported.
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
/// Client opened with FILE_DIRECTORY_FILE but the path resolved to a file.
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
/// Client opened a file but the path resolved to a directory.
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
/// Generic "operation not supported" — returned for commands we don't
/// implement so the client can move on instead of seeing the connection close.
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// One of the parent directories in the path doesn't exist.
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
/// Returned in response to CANCEL'd operations.
const STATUS_CANCELLED: u32 = 0xC000_0120;
/// QUERY_DIRECTORY: caller's output buffer can't hold even one entry.
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// QUERY_INFO/SET_INFO type codes. MS-SMB2 §2.2.37.
const INFO_TYPE_FILE: u8 = 0x01;
const INFO_TYPE_FILESYSTEM: u8 = 0x02;
/// FileSystemInformationClass values. MS-FSCC §2.5.
const FS_INFO_VOLUME: u8 = 1;
const FS_INFO_SIZE: u8 = 3;
const FS_INFO_ATTRIBUTE: u8 = 5;
const FS_INFO_FULL_SIZE: u8 = 7;
/// Common FileInformationClass values for QUERY_INFO. MS-FSCC §2.4.
const FILE_INFO_BASIC: u8 = 4;
const FILE_INFO_STANDARD: u8 = 5;
const FILE_INFO_NAME: u8 = 9;
const FILE_INFO_ALL: u8 = 18;
const FILE_INFO_NETWORK_OPEN: u8 = 34;
/// FileInformationClass values used by SET_INFO. MS-FSCC §2.4.
const FILE_INFO_RENAME: u8 = 10;
const FILE_INFO_DISPOSITION: u8 = 13;
const FILE_INFO_END_OF_FILE: u8 = 20;
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

    pub async fn serve_connection<S>(&self, io: S) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(io);
        // Outbound channel — handlers send framed PDU bytes; the writer
        // task drains them serially so deferred handlers (CHANGE_NOTIFY,
        // CANCEL) can fire from spawned tasks without sharing the writer.
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut conn = ConnectionState::new(self.inner.clone(), tx.clone());

        let writer_task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });

        let read_result = loop {
            let mut frame_header = [0u8; 4];
            match reader.read_exact(&mut frame_header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
                Err(e) => break Err(e),
            }
            let pdu_len = u32::from_be_bytes([0, frame_header[1], frame_header[2], frame_header[3]])
                as usize;
            let mut pdu = vec![0u8; pdu_len];
            if let Err(e) = reader.read_exact(&mut pdu).await {
                break Err(e);
            }

            if let Some(response) = conn.handle_pdu_chain(&pdu) {
                let frame = frame_pdu(&response);
                if tx.send(frame).is_err() {
                    break Ok(());
                }
            }
            // None = handler deferred; will publish via tx when ready.
        };

        // Drop conn (and the tx clone it holds) so the writer task knows
        // no more frames are coming once any spawned handlers finish.
        drop(conn);
        drop(tx);
        let _ = writer_task.await;
        read_result
    }
}

/// Body of the CHANGE_NOTIFY background task: race the watcher's next
/// event against the CANCEL oneshot, then build the appropriate
/// response PDU bytes (always with FLAGS_ASYNC_COMMAND + AsyncId).
async fn run_change_notify(
    mut watcher: Box<dyn Watcher>,
    cancel_rx: oneshot::Receiver<()>,
    request_header: Header,
    async_id: u64,
    buffer_limit: u32,
) -> Vec<u8> {
    tokio::select! {
        biased;
        _ = cancel_rx => {
            async_error_response(&request_header, async_id, STATUS_CANCELLED)
        }
        events = watcher.next() => {
            match events {
                Some(events) => build_change_notify_success(&request_header, async_id, &events, buffer_limit),
                None => async_error_response(&request_header, async_id, STATUS_NOT_SUPPORTED),
            }
        }
    }
}

fn build_change_notify_success(
    request_header: &Header,
    async_id: u64,
    events: &[DirChange],
    buffer_limit: u32,
) -> Vec<u8> {
    let buffer = marshal_file_notify_information(events, buffer_limit as usize);
    let response_header = async_success_header(request_header, async_id, COMMAND_CHANGE_NOTIFY);
    let response_body = ChangeNotifyResponse {
        structure_size: 9,
        buffer,
    };
    write_response(response_header, response_body, 0)
}

/// Build the interim STATUS_PENDING response that goes out immediately
/// for any deferred async request, carrying the assigned AsyncId.
fn build_interim_pending(request_header: &Header, async_id: u64) -> Vec<u8> {
    let response_header = Header {
        structure_size: 64,
        credit_charge: 0,
        status: STATUS_PENDING,
        command: request_header.command,
        credits: 1,
        flags: SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
        next_command: 0,
        message_id: request_header.message_id,
        reserved: async_id as u32,
        tree_id: (async_id >> 32) as u32,
        session_id: request_header.session_id,
        signature: [0; 16],
    };
    let response_body = ErrorResponse {
        structure_size: 9,
        error_context_count: 0,
        reserved: 0,
        error_data: vec![0],
    };
    write_response(response_header, response_body, 9)
}

fn async_success_header(request_header: &Header, async_id: u64, command: u16) -> Header {
    Header {
        structure_size: 64,
        credit_charge: 0,
        status: STATUS_SUCCESS,
        command,
        credits: 1,
        flags: SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
        next_command: 0,
        message_id: request_header.message_id,
        reserved: async_id as u32,
        tree_id: (async_id >> 32) as u32,
        session_id: request_header.session_id,
        signature: [0; 16],
    }
}

fn async_error_response(request_header: &Header, async_id: u64, status: u32) -> Vec<u8> {
    let response_header = Header {
        structure_size: 64,
        credit_charge: 0,
        status,
        command: request_header.command,
        credits: 1,
        flags: SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
        next_command: 0,
        message_id: request_header.message_id,
        reserved: async_id as u32,
        tree_id: (async_id >> 32) as u32,
        session_id: request_header.session_id,
        signature: [0; 16],
    };
    let response_body = ErrorResponse {
        structure_size: 9,
        error_context_count: 0,
        reserved: 0,
        error_data: vec![0],
    };
    write_response(response_header, response_body, 9)
}

fn marshal_file_notify_information(events: &[DirChange], limit: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut entry_starts = Vec::with_capacity(events.len());
    for event in events {
        let name_bytes: Vec<u8> = event
            .path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let entry_size = 12 + name_bytes.len();
        let aligned = (entry_size + 3) & !3; // FileNotifyInformation aligns to 4
        if !buf.is_empty() && buf.len() + aligned > limit {
            break;
        }
        let start = buf.len();
        entry_starts.push(start);
        buf.extend_from_slice(&0u32.to_le_bytes()); // next_entry_offset (patched)
        buf.extend_from_slice(&event.kind.as_action().to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&name_bytes);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }
    for i in 0..entry_starts.len().saturating_sub(1) {
        let here = entry_starts[i];
        let next = entry_starts[i + 1];
        let delta = (next - here) as u32;
        buf[here..here + 4].copy_from_slice(&delta.to_le_bytes());
    }
    buf
}

fn error_response_for(request_header: &Header, status: u32) -> Vec<u8> {
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
    write_response(response_header, response_body, 9)
}

fn simple_success_header(request_header: &Header, command: u16) -> Header {
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

/// Wrap an SMB2 PDU in the 4-byte SMB-over-TCP transport header.
fn frame_pdu(pdu: &[u8]) -> Vec<u8> {
    let len = pdu.len() as u32;
    let mut frame = Vec::with_capacity(4 + pdu.len());
    frame.extend_from_slice(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    frame.extend_from_slice(pdu);
    frame
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

/// Marshal a single QUERY_INFO type=FILESYSTEM response body for the
/// requested FS info class.
fn query_fs_info(volume: &VolumeInfo, class: u8) -> Result<Vec<u8>, u32> {
    let label_utf16: Vec<u8> = volume
        .label
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let fs_name_utf16: Vec<u8> = volume
        .fs_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let bytes_per_unit = volume.bytes_per_sector as u64 * volume.sectors_per_unit as u64;
    let total_units = if bytes_per_unit == 0 {
        0
    } else {
        volume.total_bytes / bytes_per_unit
    };
    let avail_units = if bytes_per_unit == 0 {
        0
    } else {
        volume.available_bytes / bytes_per_unit
    };

    Ok(match class {
        FS_INFO_VOLUME => serialize_body(&FileFsVolumeInformation {
            volume_creation_time: 0,
            volume_serial_number: volume.serial_number,
            supports_objects: 0,
            reserved: 0,
            volume_label: label_utf16,
        }),
        FS_INFO_SIZE => serialize_body(&FileFsSizeInformation {
            total_allocation_units: total_units,
            available_allocation_units: avail_units,
            sectors_per_allocation_unit: volume.sectors_per_unit,
            bytes_per_sector: volume.bytes_per_sector,
        }),
        FS_INFO_FULL_SIZE => serialize_body(&FileFsFullSizeInformation {
            total_allocation_units: total_units,
            caller_available_allocation_units: avail_units,
            actual_available_allocation_units: avail_units,
            sectors_per_allocation_unit: volume.sectors_per_unit,
            bytes_per_sector: volume.bytes_per_sector,
        }),
        FS_INFO_ATTRIBUTE => {
            let mut attrs: u32 = 0x0000_0004 // CASE_PRESERVED_NAMES
                | 0x0000_0040 // PERSISTENT_ACLS — neutral
                | 0x0004_0000; // UNICODE_ON_DISK
            if volume.case_sensitive {
                attrs |= 0x0000_0001; // CASE_SENSITIVE_SEARCH
            }
            serialize_body(&FileFsAttributeInformation {
                file_system_attributes: attrs,
                maximum_component_name_length: volume.max_component_length as i32,
                file_system_name: fs_name_utf16,
            })
        }
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    })
}

/// Marshal a FileAllInformation (MS-FSCC §2.4.2): concatenation of
/// FileBasic + FileStandard + FileInternal + FileEa + FileAccess +
/// FilePosition + FileMode + FileAlignment + FileName.
fn marshal_file_all_information(meta: &FileMetadata, attrs: u32, path: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    // FileBasicInformation (40 bytes)
    buf.extend_from_slice(&meta.creation_time.to_le_bytes());
    buf.extend_from_slice(&meta.last_access_time.to_le_bytes());
    buf.extend_from_slice(&meta.last_write_time.to_le_bytes());
    buf.extend_from_slice(&meta.change_time.to_le_bytes());
    buf.extend_from_slice(&attrs.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    // FileStandardInformation (24 bytes)
    buf.extend_from_slice(&meta.allocation_size.to_le_bytes());
    buf.extend_from_slice(&meta.size.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // number_of_links
    buf.push(0); // delete_pending
    buf.push(meta.is_directory as u8);
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    // FileInternalInformation (8 bytes) — IndexNumber; we have no inode, use 0
    buf.extend_from_slice(&0u64.to_le_bytes());
    // FileEaInformation (4 bytes) — EaSize
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileAccessInformation (4 bytes) — AccessFlags; report a generous mask
    buf.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
    // FilePositionInformation (8 bytes) — CurrentByteOffset
    buf.extend_from_slice(&0u64.to_le_bytes());
    // FileModeInformation (4 bytes) — Mode
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileAlignmentInformation (4 bytes) — AlignmentRequirement (0 = byte)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileNameInformation: FileNameLength (4) + FileName (UTF-16LE).
    let name_bytes: Vec<u8> = path
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&name_bytes);
    buf
}

/// Serialize a single binrw struct to its wire bytes.
fn serialize_body<B>(value: &B) -> Vec<u8>
where
    B: BinWrite + binrw::meta::WriteEndian,
    for<'a> B: BinWrite<Args<'a> = ()>,
{
    let mut bytes = Vec::new();
    value
        .write(&mut Cursor::new(&mut bytes))
        .expect("body serialize cannot fail");
    bytes
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
///
/// `create_options` selects between file and directory creation: when the
/// `FILE_DIRECTORY_FILE` bit is set, creates route through `create_dir`
/// instead of `create`.
fn dispatch_create(
    fs: &dyn Filesystem,
    path: &str,
    disposition: u32,
    create_options: u32,
) -> Result<(Arc<dyn FileHandle>, u32), u32> {
    let create = || {
        if create_options & CREATE_OPT_DIRECTORY_FILE != 0 {
            fs.create_dir(path)
        } else {
            fs.create(path)
        }
    };

    match disposition {
        FILE_DISP_OPEN => fs
            .open(path)
            .map(|h| (h, FILE_OPENED))
            .map_err(map_io_err),
        FILE_DISP_CREATE => match fs.open(path) {
            Ok(_) => Err(STATUS_OBJECT_NAME_COLLISION),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create().map(|h| (h, FILE_CREATED)).map_err(map_io_err)
            }
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_OPEN_IF => match fs.open(path) {
            Ok(h) => Ok((h, FILE_OPENED)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create().map(|h| (h, FILE_CREATED)).map_err(map_io_err)
            }
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_SUPERSEDE | FILE_DISP_OVERWRITE_IF => match create() {
            Ok(h) => Ok((h, FILE_CREATED)),
            Err(e) => Err(map_io_err(e)),
        },
        FILE_DISP_OVERWRITE => match fs.open(path) {
            Ok(_) => create().map(|h| (h, FILE_CREATED)).map_err(map_io_err),
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

/// Wire size in bytes of a single FILE_BOTH_DIR_INFORMATION record
/// for the given entry, including 8-byte alignment padding to the next
/// entry. Used by the QUERY_DIRECTORY pagination loop.
fn file_both_dir_entry_wire_size(entry: &DirEntry) -> usize {
    let name_bytes = entry.name.encode_utf16().count() * 2;
    let raw = 94 + name_bytes; // fixed prefix per MS-FSCC §2.4.8
    (raw + 7) & !7
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

#[cfg(test)]
mod glob_tests {
    use super::glob_match;

    #[test]
    fn star_matches_anything() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn extension_pattern() {
        assert!(glob_match("*.txt", "notes.txt"));
        assert!(!glob_match("*.txt", "notes.bin"));
    }

    #[test]
    fn question_mark_matches_one_char() {
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("a?c", "axc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("a?c", "abbc"));
    }

    #[test]
    fn case_insensitive() {
        assert!(glob_match("*.TXT", "notes.txt"));
        assert!(glob_match("Hello*", "HELLO_world"));
    }

    #[test]
    fn star_in_middle() {
        assert!(glob_match("a*z", "abz"));
        assert!(glob_match("a*z", "az"));
        assert!(glob_match("a*z", "abcdefz"));
        assert!(!glob_match("a*z", "abcd"));
    }
}

/// Match a DOS-style glob `pattern` against `name`, case-insensitively.
/// Wildcards: `*` matches any (possibly empty) sequence, `?` matches any
/// single character. Used by QUERY_DIRECTORY filtering.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let nm: Vec<char> = name.chars().flat_map(char::to_lowercase).collect();
    glob_match_impl(&pat, &nm)
}

fn glob_match_impl(pattern: &[char], name: &[char]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some('*') => {
            // Try matching zero or more chars.
            for i in 0..=name.len() {
                if glob_match_impl(&pattern[1..], &name[i..]) {
                    return true;
                }
            }
            false
        }
        Some('?') => !name.is_empty() && glob_match_impl(&pattern[1..], &name[1..]),
        Some(&c) => name.first() == Some(&c) && glob_match_impl(&pattern[1..], &name[1..]),
    }
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
struct OpenFile {
    handle: Arc<dyn FileHandle>,
    /// Path passed to the original CREATE — needed for rename and delete.
    path: String,
    /// Set by SET_INFO FileDispositionInformation; acted on at CLOSE.
    delete_on_close: bool,
}

struct ConnectionState {
    inner: Arc<Inner>,
    open_files: HashMap<u64, OpenFile>,
    next_file_id: u64,
    /// Per-FileId queue of directory entries still to deliver. Each
    /// QUERY_DIRECTORY peels entries from the front until the client's
    /// output buffer would overflow; emptying the queue ends iteration
    /// with STATUS_NO_MORE_FILES. Cleared by RESTART_SCANS.
    pending_listings: HashMap<u64, VecDeque<DirEntry>>,
    /// TreeId → backing filesystem for that share. Populated on
    /// TREE_CONNECT, cleared on TREE_DISCONNECT.
    trees: HashMap<u32, Arc<dyn Filesystem>>,
    next_tree_id: u32,
    /// Channel to the writer task; deferred handlers (CHANGE_NOTIFY)
    /// publish their eventual responses through here.
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Active long-running requests, keyed by AsyncId (which we assign
    /// per request and echo back in the interim STATUS_PENDING response).
    /// CANCEL signals the corresponding oneshot to wake the parked task.
    cancellations: Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>,
    /// Counter for AsyncId issuance — never zero.
    next_async_id: u64,
}

impl ConnectionState {
    fn new(inner: Arc<Inner>, tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            inner,
            open_files: HashMap::new(),
            next_file_id: 1,
            pending_listings: HashMap::new(),
            trees: HashMap::new(),
            next_tree_id: 1,
            tx,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            next_async_id: 1,
        }
    }

    /// Walk a (possibly-compound) PDU, dispatch each chained command,
    /// concatenate the immediate responses (deferred ones publish via
    /// `tx` independently), patching `next_command` so the client can
    /// parse the chain.
    fn handle_pdu_chain(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0usize;
        let mut responses: Vec<Vec<u8>> = Vec::new();
        loop {
            // Peek the header to find next_command.
            let mut hdr_cursor = Cursor::new(&pdu[pos..]);
            let header = Header::read(&mut hdr_cursor).ok()?;
            let next = header.next_command as usize;
            let cmd_end = if next == 0 { pdu.len() } else { pos + next };
            let cmd_pdu = &pdu[pos..cmd_end];

            if let Some(resp) = self.handle_pdu(cmd_pdu) {
                responses.push(resp);
            }
            // None = deferred; the spawned task will publish its own framed PDU.

            if next == 0 {
                break;
            }
            pos = cmd_end;
        }

        if responses.is_empty() {
            return None;
        }

        // Concatenate with 8-byte padding between responses; patch
        // next_command in every response except the last.
        let mut combined: Vec<u8> = Vec::new();
        let mut starts = Vec::with_capacity(responses.len());
        for resp in &responses {
            while combined.len() % 8 != 0 {
                combined.push(0);
            }
            starts.push(combined.len());
            combined.extend_from_slice(resp);
        }
        for i in 0..responses.len().saturating_sub(1) {
            let here = starts[i];
            let there = starts[i + 1];
            let delta = (there - here) as u32;
            // next_command lives at offset 20 in the SMB2 header.
            combined[here + 20..here + 24].copy_from_slice(&delta.to_le_bytes());
        }
        Some(combined)
    }

    fn handle_pdu(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(pdu);
        let request_header = match Header::read(&mut cursor) {
            Ok(h) => h,
            // Malformed header — close the connection rather than try to reply
            // (no MessageId means no valid response).
            Err(_) => return None,
        };

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
            COMMAND_QUERY_INFO => Some(self.handle_query_info(request_header, &mut cursor)),
            COMMAND_SET_INFO => Some(self.handle_set_info(request_header, &mut cursor)),
            COMMAND_CHANGE_NOTIFY => self.handle_change_notify(request_header, &mut cursor),
            COMMAND_CANCEL => {
                self.handle_cancel(request_header);
                None
            }
            _ => Some(self.error_response(request_header, STATUS_NOT_SUPPORTED)),
        }
    }

    fn handle_cancel(&mut self, request_header: Header) {
        // Async cancellations use the AsyncId (overlay of reserved+tree_id).
        // Sync cancellations would use MessageId — we don't generate any
        // sync long-running responses, so this branch is reachable only in
        // unusual client flows.
        let key = if request_header.flags & SMB2_FLAGS_ASYNC_COMMAND != 0 {
            ((request_header.tree_id as u64) << 32) | (request_header.reserved as u64)
        } else {
            request_header.message_id
        };
        if let Ok(mut map) = self.cancellations.lock()
            && let Some(canceller) = map.remove(&key)
        {
            let _ = canceller.send(());
        }
    }

    /// CHANGE_NOTIFY: returns `None` (deferred). Spawns a task that
    /// waits on either the next watch event or a CANCEL signal, then
    /// publishes the response through `self.tx`.
    fn handle_change_notify(
        &mut self,
        request_header: Header,
        cursor: &mut Cursor<&[u8]>,
    ) -> Option<Vec<u8>> {
        let request = match ChangeNotifyRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return Some(self.error_response(request_header, STATUS_INVALID_PARAMETER)),
        };

        let entry = match self.open_files.get(&request.file_id_volatile) {
            Some(of) => of,
            None => return Some(self.error_response(request_header, STATUS_FILE_CLOSED)),
        };
        if !entry.handle.is_directory() {
            return Some(self.error_response(request_header, STATUS_INVALID_PARAMETER));
        }
        let path = entry.path.clone();

        let fs = match self.trees.get(&request_header.tree_id) {
            Some(fs) => fs.clone(),
            None => return Some(self.error_response(request_header, STATUS_INVALID_PARAMETER)),
        };

        let watcher = match fs.watch(&path, request.flags & 0x0001 != 0 /* WATCH_TREE */) {
            Some(w) => w,
            None => return Some(self.error_response(request_header, STATUS_NOT_SUPPORTED)),
        };

        // Allocate an AsyncId so the client can target this request with
        // an async CANCEL.
        let async_id = self.next_async_id;
        self.next_async_id += 1;

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        if let Ok(mut map) = self.cancellations.lock() {
            map.insert(async_id, cancel_tx);
        }

        // Send the interim STATUS_PENDING response immediately so the
        // client knows the AsyncId for this long-running request.
        let interim = build_interim_pending(&request_header, async_id);
        let _ = self.tx.send(frame_pdu(&interim));

        let tx = self.tx.clone();
        let cancellations = self.cancellations.clone();
        let buffer_limit = request.output_buffer_length;
        tokio::spawn(async move {
            let response = run_change_notify(
                watcher,
                cancel_rx,
                request_header,
                async_id,
                buffer_limit,
            )
            .await;
            if let Ok(mut map) = cancellations.lock() {
                map.remove(&async_id);
            }
            let _ = tx.send(frame_pdu(&response));
        });

        None
    }

    fn handle_set_info(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match SetInfoRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        if request.info_type != INFO_TYPE_FILE {
            return self.error_response(request_header, STATUS_INVALID_INFO_CLASS);
        }

        let result = match request.file_info_class {
            FILE_INFO_END_OF_FILE => {
                let info = match FileEndOfFileInformation::read(&mut Cursor::new(&request.buffer))
                {
                    Ok(i) => i,
                    Err(_) => {
                        return self.error_response(request_header, STATUS_INVALID_PARAMETER);
                    }
                };
                let entry = match self.open_files.get(&request.file_id_volatile) {
                    Some(of) => of,
                    None => return self.error_response(request_header, STATUS_FILE_CLOSED),
                };
                entry.handle.truncate(info.end_of_file)
            }
            FILE_INFO_DISPOSITION => {
                let info = match FileDispositionInformation::read(&mut Cursor::new(
                    &request.buffer,
                )) {
                    Ok(i) => i,
                    Err(_) => {
                        return self.error_response(request_header, STATUS_INVALID_PARAMETER);
                    }
                };
                let entry = match self.open_files.get_mut(&request.file_id_volatile) {
                    Some(of) => of,
                    None => return self.error_response(request_header, STATUS_FILE_CLOSED),
                };
                entry.delete_on_close = info.delete_pending != 0;
                Ok(())
            }
            FILE_INFO_RENAME => {
                let info = match FileRenameInformation::read(&mut Cursor::new(&request.buffer)) {
                    Ok(i) => i,
                    Err(_) => {
                        return self.error_response(request_header, STATUS_INVALID_PARAMETER);
                    }
                };
                let new_path = match decode_utf16le(&info.file_name) {
                    Ok(p) => p,
                    Err(_) => {
                        return self.error_response(request_header, STATUS_INVALID_PARAMETER);
                    }
                };
                let old_path = match self.open_files.get(&request.file_id_volatile) {
                    Some(of) => of.path.clone(),
                    None => return self.error_response(request_header, STATUS_FILE_CLOSED),
                };
                let fs = match self.trees.get(&request_header.tree_id) {
                    Some(fs) => fs.clone(),
                    None => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
                };
                let r = fs.rename(&old_path, &new_path);
                if r.is_ok() {
                    if let Some(of) = self.open_files.get_mut(&request.file_id_volatile) {
                        of.path = new_path;
                    }
                }
                r
            }
            _ => return self.error_response(request_header, STATUS_INVALID_INFO_CLASS),
        };

        if let Err(e) = result {
            return self.error_response(request_header, map_io_err(e));
        }

        let response_header = self.simple_response_header(&request_header, COMMAND_SET_INFO);
        let response_body = SetInfoResponse { structure_size: 2 };
        write_response(response_header, response_body, 0)
    }

    fn handle_query_info(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match QueryInfoRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let (handle, path) = match self.open_files.get(&request.file_id_volatile) {
            Some(of) => (of.handle.clone(), of.path.clone()),
            None => return self.error_response(request_header, STATUS_FILE_CLOSED),
        };

        let buffer = match request.info_type {
            INFO_TYPE_FILE => match self.query_file_info(
                &handle,
                &path,
                request.file_info_class,
            ) {
                Ok(b) => b,
                Err(status) => return self.error_response(request_header, status),
            },
            INFO_TYPE_FILESYSTEM => {
                let fs = match self.trees.get(&request_header.tree_id) {
                    Some(fs) => fs.clone(),
                    None => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
                };
                match query_fs_info(&fs.volume_info(), request.file_info_class) {
                    Ok(b) => b,
                    Err(status) => return self.error_response(request_header, status),
                }
            }
            _ => return self.error_response(request_header, STATUS_INVALID_INFO_CLASS),
        };

        let response_header = self.simple_response_header(&request_header, COMMAND_QUERY_INFO);
        let response_body = QueryInfoResponse {
            structure_size: 9,
            output_buffer: buffer,
        };
        write_response(response_header, response_body, 0)
    }

    fn query_file_info(
        &self,
        handle: &Arc<dyn FileHandle>,
        path: &str,
        file_info_class: u8,
    ) -> Result<Vec<u8>, u32> {
        let meta = handle.metadata();
        let attrs = if meta.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };

        Ok(match file_info_class {
            FILE_INFO_BASIC => serialize_body(&FileBasicInformation {
                creation_time: meta.creation_time,
                last_access_time: meta.last_access_time,
                last_write_time: meta.last_write_time,
                change_time: meta.change_time,
                file_attributes: attrs,
                reserved: 0,
            }),
            FILE_INFO_STANDARD => serialize_body(&FileStandardInformation {
                allocation_size: meta.allocation_size,
                end_of_file: meta.size,
                number_of_links: 1,
                delete_pending: 0,
                directory: meta.is_directory as u8,
                reserved: 0,
            }),
            FILE_INFO_NETWORK_OPEN => serialize_body(&FileNetworkOpenInformation {
                creation_time: meta.creation_time,
                last_access_time: meta.last_access_time,
                last_write_time: meta.last_write_time,
                change_time: meta.change_time,
                allocation_size: meta.allocation_size,
                end_of_file: meta.size,
                file_attributes: attrs,
                reserved: 0,
            }),
            FILE_INFO_ALL => marshal_file_all_information(&meta, attrs, path),
            FILE_INFO_NAME => {
                let name_bytes: Vec<u8> = path
                    .encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                let mut buf = Vec::with_capacity(4 + name_bytes.len());
                buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(&name_bytes);
                buf
            }
            _ => return Err(STATUS_INVALID_INFO_CLASS),
        })
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
        let request = match FlushRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        if let Some(of) = self.open_files.get(&request.file_id_volatile)
            && let Err(e) = of.handle.flush()
        {
            return self.error_response(request_header, map_io_err(e));
        }

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
            Some(of) => of.handle.clone(),
            None => return self.error_response(request_header, STATUS_FILE_CLOSED),
        };

        if !handle.is_directory() {
            return self.error_response(request_header, STATUS_INVALID_PARAMETER);
        }

        let restart = request.flags & QUERY_DIR_FLAG_RESTART_SCANS != 0;
        if restart {
            self.pending_listings.remove(&request.file_id_volatile);
        }

        // Initialize the pending list on first call (or after RESTART_SCANS).
        if !self.pending_listings.contains_key(&request.file_id_volatile) {
            let entries = match handle.list_children() {
                Ok(e) => e,
                Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
            };
            let pattern = decode_utf16le(&request.file_name).ok();
            let filtered: VecDeque<DirEntry> = entries
                .into_iter()
                .filter(|e| match pattern.as_deref() {
                    None | Some("") | Some("*") => true,
                    Some(p) => glob_match(p, &e.name),
                })
                .collect();
            self.pending_listings
                .insert(request.file_id_volatile, filtered);
        }

        let pending = self
            .pending_listings
            .get_mut(&request.file_id_volatile)
            .expect("just inserted");

        if pending.is_empty() {
            self.pending_listings.remove(&request.file_id_volatile);
            return self.error_response(request_header, STATUS_NO_MORE_FILES);
        }

        // Peel entries that fit into the client's output buffer.
        let limit = request.output_buffer_length as usize;
        let mut taken = 0;
        let mut total_size = 0usize;
        for entry in pending.iter() {
            let s = file_both_dir_entry_wire_size(entry);
            if total_size + s > limit {
                break;
            }
            total_size += s;
            taken += 1;
        }

        if taken == 0 {
            // Even one entry doesn't fit. Spec: STATUS_INFO_LENGTH_MISMATCH.
            return self.error_response(request_header, STATUS_INFO_LENGTH_MISMATCH);
        }

        let chunk: Vec<DirEntry> = pending.drain(..taken).collect();
        let buffer = marshal_dir_entries(&chunk);

        let response_header = self.simple_response_header(&request_header, COMMAND_QUERY_DIRECTORY);
        let response_body = QueryDirectoryResponse {
            structure_size: 9,
            output_buffer: buffer,
        };
        write_response(response_header, response_body, total_size + 8)
    }

    fn handle_write(&mut self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
        let request = match WriteRequest::read(cursor) {
            Ok(r) => r,
            Err(_) => return self.error_response(request_header, STATUS_INVALID_PARAMETER),
        };

        let handle = match self.open_files.get(&request.file_id_volatile) {
            Some(of) => of.handle.clone(),
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
            Some(of) => of.handle.clone(),
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

        // Pull the handle out, snapshot whatever we need from it before
        // dropping (so the FS sees no live handle when delete runs).
        let entry = self.open_files.remove(&request.file_id_volatile);
        self.pending_listings.remove(&request.file_id_volatile);
        let size = entry.as_ref().map(|e| e.handle.size()).unwrap_or(0);
        let to_delete = entry
            .as_ref()
            .filter(|e| e.delete_on_close)
            .map(|e| e.path.clone());
        drop(entry);
        if let Some(path) = to_delete
            && let Some(fs) = self.trees.get(&request_header.tree_id)
        {
            let _ = fs.delete(&path);
        }

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

        let (handle, action) = match dispatch_create(
            &*fs,
            &path,
            request.create_disposition,
            request.create_options,
        ) {
            Ok(t) => t,
            Err(status) => return self.error_response(request_header, status),
        };

        // Type check: enforce the client's stated intent.
        let want_dir = request.create_options & CREATE_OPT_DIRECTORY_FILE != 0;
        let want_non_dir = request.create_options & CREATE_OPT_NON_DIRECTORY_FILE != 0;
        if want_dir && !handle.is_directory() {
            return self.error_response(request_header, STATUS_NOT_A_DIRECTORY);
        }
        if want_non_dir && handle.is_directory() {
            return self.error_response(request_header, STATUS_FILE_IS_A_DIRECTORY);
        }

        let file_id = self.next_file_id;
        self.next_file_id += 1;
        let size = handle.size();
        let attrs = if handle.is_directory() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        self.open_files.insert(
            file_id,
            OpenFile {
                handle,
                path: path.clone(),
                delete_on_close: false,
            },
        );

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

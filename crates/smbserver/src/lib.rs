use std::io::Cursor;
use std::sync::Arc;

use binrw::{BinRead, BinWrite};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod wire;

use wire::header::Header;
use wire::negotiate::{NegotiateRequest, NegotiateResponse};

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const COMMAND_NEGOTIATE: u16 = 0x0000;
const STATUS_SUCCESS: u32 = 0x0000_0000;
const DIALECT_SMB_2_1: u16 = 0x0210;
/// Hardcoded server GUID. Real servers MAY persist this; for now a static
/// value is fine — clients only echo it back during multichannel binding.
const SERVER_GUID: [u8; 16] = *b"smbserver-rs\0\0\0\0";

pub trait Filesystem: Send + Sync + 'static {}

#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    #[allow(dead_code)]
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

            let response = match self.handle_pdu(&pdu) {
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

    fn handle_pdu(&self, pdu: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(pdu);
        let request_header = Header::read(&mut cursor).ok()?;

        match request_header.command {
            COMMAND_NEGOTIATE => Some(self.handle_negotiate(request_header, &mut cursor)),
            _ => None,
        }
    }

    fn handle_negotiate(&self, request_header: Header, cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
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

impl ServerBuilder {
    pub fn build(self, fs: impl Filesystem) -> Server {
        Server {
            inner: Arc::new(Inner { fs: Box::new(fs) }),
        }
    }
}

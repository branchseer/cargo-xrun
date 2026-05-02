//! Spec-fidelity tests against bytes captured from smb-rs (a real, MIT-licensed
//! SMB2 client).
//!
//! Each fixture is the exact wire bytes smb-rs sends/expects for a given PDU.
//! Tests assert:
//!   1. our parser yields a struct whose serialization matches the fixture
//!      byte-for-byte (validates field layout, widths, endianness, calc'd
//!      offsets); and
//!   2. parse(fixture) reaches expected field values (sanity check).
//!
//! Bytes are captured at runtime by running the in-process duplex harness
//! and reading what smb-rs sends. The first time a fixture is needed, run
//! the corresponding `*_capture` test with `--ignored --nocapture` and paste
//! the hex into the const below.

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use binrw::{BinRead, BinWrite};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use smb::transport::error::{Result as TransportResult, TransportError};
use smb::transport::{SmbTransport, SmbTransportRead, SmbTransportWrite};
use smb::{Connection, ConnectionConfig, Guid};
use smbserver::wire::header::Header;
use smbserver::wire::negotiate::NegotiateRequest;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

const FAKE_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 445);

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
    fn default_port(&self) -> u16 { 445 }
    fn split(
        self: Box<Self>,
    ) -> TransportResult<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        let r = self.reader.ok_or(TransportError::NotConnected)?;
        let w = self.writer.ok_or(TransportError::NotConnected)?;
        Ok((Box::new(ReadHalfTransport(r)), Box::new(WriteHalfTransport(w))))
    }
    fn remote_address(&self) -> TransportResult<SocketAddr> { Ok(FAKE_REMOTE) }
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

/// Drive smb-rs through a duplex pipe and return the first batch of bytes it
/// sends server-ward. The smb-rs task is aborted after capture; it never
/// receives a response.
async fn capture_client_bytes() -> Vec<u8> {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

    let client_task = tokio::spawn(async move {
        let transport = Box::new(DuplexTransport::new(client_io));
        let config = ConnectionConfig {
            smb2_only_negotiate: true,
            ..Default::default()
        };
        let _ = Connection::from_transport(transport, "test", Guid::generate(), config).await;
    });

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), server_io.read(&mut buf))
        .await
        .expect("smb-rs did not write within 2s")
        .expect("read failed");
    buf.truncate(n);

    client_task.abort();
    buf
}

/// Strip the 4-byte SMB-over-TCP transport header (NetBIOS-style 24-bit length
/// + 1 reserved byte) and return the SMB2 PDU.
fn strip_transport_header(framed: &[u8]) -> &[u8] {
    assert!(framed.len() >= 4, "frame too short for transport header");
    &framed[4..]
}

/// Capture helper — run with:
///   `cargo test -p smbserver --test golden_smbrs capture_negotiate_request_dump \
///        -- --ignored --nocapture`
/// then paste the printed hex into `NEGOTIATE_REQUEST_FROM_SMBRS` below.
#[tokio::test]
#[ignore = "capture-only — paste output into NEGOTIATE_REQUEST_FROM_SMBRS"]
async fn capture_negotiate_request_dump() {
    let framed = capture_client_bytes().await;
    let pdu = strip_transport_header(&framed);
    println!("// Captured {} bytes (NEGOTIATE Request PDU, transport header stripped):", pdu.len());
    for chunk in pdu.chunks(12) {
        for b in chunk {
            print!("0x{:02X}, ", b);
        }
        println!();
    }
}

/// Bytes captured from smb-rs `Connection::from_transport` with
/// `smb2_only_negotiate=true`. Includes the SMB 3.1.1 negotiate-context
/// chain after offset 112; our codec only covers the prefix through the
/// fixed dialects array. Replace if smb-rs changes its NEGOTIATE format.
#[rustfmt::skip]
const NEGOTIATE_REQUEST_FROM_SMBRS: &[u8] = &[
    // SMB2 header (64 bytes)
    0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // NegotiateRequest fixed (36 bytes) — StructureSize=36, DialectCount=5,
    // SecurityMode=1 (signing enabled), Reserved=0, Capabilities=0xE7,
    // ClientGuid (16), ClientStartTime overlapped with 3.1.1
    // NegotiateContextOffset=0x70 NegotiateContextCount=5 Reserved2=0
    0x24, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0xE7, 0x00, 0x00, 0x00,
    0x75, 0x91, 0xC7, 0x69, 0x79, 0x09, 0x02, 0x39, 0x57, 0x96, 0xFE, 0x2D,
    0x43, 0xCD, 0x54, 0x59, 0x70, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    // Dialects[5] (10 bytes): SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03,
    // Padding to 8-byte boundary, then negotiate contexts (not yet modelled)
    0x00, 0x00,
    0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00,
    0x01, 0x00, 0x1D, 0x25, 0x93, 0xCC, 0x3B, 0x39, 0xC2, 0x45, 0x9E, 0xDD,
    0x4B, 0x54, 0x43, 0x95, 0x54, 0x4F, 0x3E, 0xEE, 0x23, 0x3F, 0xB4, 0x33,
    0x7F, 0xCD, 0x6F, 0x5E, 0x41, 0x79, 0xFF, 0x77, 0x80, 0xAE, 0x00, 0x00,
    0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x00, 0x6D, 0x00,
    0x62, 0x00, 0x2D, 0x00, 0x63, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x65, 0x00,
    0x6E, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
];

#[test]
fn smbrs_negotiate_request_round_trips_through_our_codec() {
    if NEGOTIATE_REQUEST_FROM_SMBRS.is_empty() {
        // Fixture not yet captured — run capture_negotiate_request_dump.
        eprintln!(
            "skipping: NEGOTIATE_REQUEST_FROM_SMBRS is empty. \
             Run: cargo test -p smbserver --test golden_smbrs \
             capture_negotiate_request_dump -- --ignored --nocapture"
        );
        return;
    }

    let mut cursor = Cursor::new(NEGOTIATE_REQUEST_FROM_SMBRS);

    let header = Header::read(&mut cursor).expect("our codec failed to parse smb-rs's SMB2 header");
    assert_eq!(header.command, 0x0000, "expected NEGOTIATE command");
    assert_eq!(header.structure_size, 64, "spec: SMB2 header is 64 bytes");

    let request = NegotiateRequest::read(&mut cursor)
        .expect("our codec failed to parse smb-rs's NEGOTIATE Request");
    assert_eq!(request.structure_size, 36, "spec: NEGOTIATE Request StructureSize");
    assert!(!request.dialects.is_empty(), "smb-rs always offers at least one dialect");

    // Re-serialize and compare byte-for-byte to the captured fixture.
    let mut round = Vec::new();
    {
        let mut cursor = Cursor::new(&mut round);
        header.write(&mut cursor).expect("header serialize failed");
        request.write(&mut cursor).expect("request serialize failed");
    }

    // The captured bytes may include negotiate contexts (3.1.1) or padding
    // we don't model yet — compare only the prefix our codec covered.
    let covered = round.len();
    assert_eq!(
        &round[..],
        &NEGOTIATE_REQUEST_FROM_SMBRS[..covered],
        "our serialization diverges from smb-rs's bytes at offset {} \
         (left = our re-serialization, right = smb-rs's bytes)",
        round
            .iter()
            .zip(NEGOTIATE_REQUEST_FROM_SMBRS.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(covered)
    );
}

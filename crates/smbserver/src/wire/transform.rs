//! SMB2 TRANSFORM_HEADER. MS-SMB2 §2.2.41.
//!
//! 52-byte fixed envelope wrapping an encrypted SMB2 message. The encrypted
//! payload follows; carried here as opaque bytes.

use binrw::binrw;

pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];

#[binrw]
#[brw(little, magic = b"\xFDSMB")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformHeader {
    pub signature: [u8; 16],
    pub nonce: [u8; 16],
    #[br(temp)]
    #[bw(calc = encrypted_payload.len() as u32)]
    original_message_size: u32,
    pub reserved: u16,
    /// Dialect 3.0/3.0.2: Flags. Dialect 3.1.1: EncryptionAlgorithm.
    pub flags: u16,
    pub session_id: u64,
    #[br(count = original_message_size)]
    pub encrypted_payload: Vec<u8>,
}

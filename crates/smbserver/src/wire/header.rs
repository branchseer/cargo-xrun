//! SMB2 Packet Header (SYNC form). MS-SMB2 §2.2.1.2.
//!
//! Fixed 64-byte header that precedes every SMB2 PDU. The async form
//! (FLAGS_ASYNC_COMMAND set, AsyncId replaces Reserved+TreeId) is not
//! modelled here yet.

use binrw::{BinRead, BinWrite};

pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
pub const STRUCTURE_SIZE: u16 = 64;

#[derive(Debug, Clone, PartialEq, Eq, BinRead, BinWrite)]
#[brw(little, magic = b"\xFESMB")]
pub struct Header {
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            structure_size: STRUCTURE_SIZE,
            credit_charge: 0,
            status: 0,
            command: 0,
            credits: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        }
    }
}

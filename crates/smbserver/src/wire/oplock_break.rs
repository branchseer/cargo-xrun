//! SMB2 OPLOCK_BREAK Notification/Acknowledgment/Response.
//! MS-SMB2 §2.2.23.1 / §2.2.24.1 / §2.2.25.1.
//!
//! All three share the same 24-byte layout. Lease-break variants
//! (StructureSize 36/44) live in `lease_break.rs`.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OplockBreakNotification {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub reserved: u8,
    pub reserved2: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OplockBreakAcknowledgment {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub reserved: u8,
    pub reserved2: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OplockBreakResponse {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub reserved: u8,
    pub reserved2: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

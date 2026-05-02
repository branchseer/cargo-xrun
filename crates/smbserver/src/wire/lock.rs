//! SMB2 LOCK Request/Response. MS-SMB2 §2.2.26 / §2.2.27.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: u32,
    pub reserved: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRequest {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = locks.len() as u16)]
    lock_count: u16,
    /// 4-bit lock sequence number in the low nibble; 28-bit lock sequence
    /// index in the upper bits. Treated as opaque u32 on the wire.
    pub lock_sequence: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

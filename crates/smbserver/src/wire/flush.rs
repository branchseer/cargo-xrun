//! SMB2 FLUSH Request/Response. MS-SMB2 §2.2.17 / §2.2.18.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRequest {
    pub structure_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

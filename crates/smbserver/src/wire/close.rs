//! SMB2 CLOSE Request/Response. MS-SMB2 §2.2.15 / §2.2.16.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub reserved: u32,
    /// FileId.Persistent.
    pub file_id_persistent: u64,
    /// FileId.Volatile.
    pub file_id_volatile: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResponse {
    pub structure_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
}

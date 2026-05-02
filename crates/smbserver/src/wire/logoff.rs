//! SMB2 LOGOFF Request/Response. MS-SMB2 §2.2.7 / §2.2.8.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoffRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoffResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

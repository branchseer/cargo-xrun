//! SMB2 TREE_DISCONNECT Request/Response. MS-SMB2 §2.2.11 / §2.2.12.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

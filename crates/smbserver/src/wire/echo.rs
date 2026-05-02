//! SMB2 ECHO Request/Response. MS-SMB2 §2.2.28 / §2.2.29.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoResponse {
    pub structure_size: u16,
    pub reserved: u16,
}

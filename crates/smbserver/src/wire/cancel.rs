//! SMB2 CANCEL Request. MS-SMB2 §2.2.30. (No response — server replies
//! to the cancelled command with STATUS_CANCELLED via the original MID.)

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    pub structure_size: u16,
    pub reserved: u16,
}

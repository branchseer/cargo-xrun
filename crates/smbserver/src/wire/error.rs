//! SMB2 ERROR Response. MS-SMB2 §2.2.2.
//!
//! Returned in place of any normal response when an SMB2 command fails.
//! `error_data` carries optional context (e.g., symlink redirect data);
//! must be at least 1 byte per spec, even if the value is unused.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    pub structure_size: u16,
    pub error_context_count: u8,
    pub reserved: u8,
    #[br(temp)]
    #[bw(calc = error_data.len() as u32)]
    byte_count: u32,
    #[br(count = byte_count)]
    pub error_data: Vec<u8>,
}

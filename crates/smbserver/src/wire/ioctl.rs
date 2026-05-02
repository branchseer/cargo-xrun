//! SMB2 IOCTL Request/Response. MS-SMB2 §2.2.31 / §2.2.32.
//!
//! Initial coverage: input buffer only, output buffer assumed empty
//! (the common case for client-issued ioctls). Output-bearing requests
//! land in a follow-up iteration once the layout is parameterised.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlRequest {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(temp)]
    #[bw(calc = if input_buffer.is_empty() { 0 } else { 64 + 56 })]
    input_offset: u32,
    #[br(temp)]
    #[bw(calc = input_buffer.len() as u32)]
    input_count: u32,
    pub max_input_response: u32,
    #[br(temp)]
    #[bw(calc = 0)]
    output_offset: u32,
    #[br(temp)]
    #[bw(calc = 0)]
    output_count: u32,
    pub max_output_response: u32,
    pub flags: u32,
    pub reserved2: u32,
    #[br(count = input_count)]
    pub input_buffer: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(temp)]
    #[bw(calc = 0)]
    input_offset: u32,
    #[br(temp)]
    #[bw(calc = 0)]
    input_count: u32,
    #[br(temp)]
    #[bw(calc = if output_buffer.is_empty() { 0 } else { 64 + 48 })]
    output_offset: u32,
    #[br(temp)]
    #[bw(calc = output_buffer.len() as u32)]
    output_count: u32,
    pub flags: u32,
    pub reserved2: u32,
    #[br(count = output_count)]
    pub output_buffer: Vec<u8>,
}

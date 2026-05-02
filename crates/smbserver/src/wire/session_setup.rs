//! SMB2 SESSION_SETUP Request/Response. MS-SMB2 §2.2.5 / §2.2.6.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupRequest {
    pub structure_size: u16,
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
    pub channel: u32,
    #[br(temp)]
    #[bw(calc = if security_buffer.is_empty() { 0 } else { 88 })]
    security_buffer_offset: u16,
    #[br(temp)]
    #[bw(calc = security_buffer.len() as u16)]
    security_buffer_length: u16,
    pub previous_session_id: u64,
    #[br(count = security_buffer_length)]
    pub security_buffer: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    pub structure_size: u16,
    pub session_flags: u16,
    #[br(temp)]
    #[bw(calc = if security_buffer.is_empty() { 0 } else { 72 })]
    security_buffer_offset: u16,
    #[br(temp)]
    #[bw(calc = security_buffer.len() as u16)]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    pub security_buffer: Vec<u8>,
}

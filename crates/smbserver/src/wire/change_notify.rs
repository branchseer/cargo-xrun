//! SMB2 CHANGE_NOTIFY Request/Response. MS-SMB2 §2.2.35 / §2.2.36.
//!
//! The response buffer is a chain of FILE_NOTIFY_INFORMATION records
//! (MS-FSCC §2.4.42). For codec purposes we treat it as opaque bytes.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub output_buffer_length: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub completion_filter: u32,
    pub reserved: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyResponse {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = if buffer.is_empty() { 0 } else { 64 + 8 })]
    output_buffer_offset: u16,
    #[br(temp)]
    #[bw(calc = buffer.len() as u32)]
    output_buffer_length: u32,
    #[br(count = output_buffer_length)]
    pub buffer: Vec<u8>,
}

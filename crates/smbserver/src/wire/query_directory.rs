//! SMB2 QUERY_DIRECTORY Request/Response. MS-SMB2 §2.2.33 / §2.2.34.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    pub structure_size: u16,
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(temp)]
    #[bw(calc = if file_name.is_empty() { 0 } else { 64 + 32 })]
    file_name_offset: u16,
    #[br(temp)]
    #[bw(calc = file_name.len() as u16)]
    file_name_length: u16,
    pub output_buffer_length: u32,
    /// UTF-16LE search pattern (e.g. b"*").
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryResponse {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = if output_buffer.is_empty() { 0 } else { 64 + 8 })]
    output_buffer_offset: u16,
    #[br(temp)]
    #[bw(calc = output_buffer.len() as u32)]
    output_buffer_length: u32,
    #[br(count = output_buffer_length)]
    pub output_buffer: Vec<u8>,
}

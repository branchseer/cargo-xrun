//! SMB2 QUERY_INFO Request/Response. MS-SMB2 §2.2.37 / §2.2.38.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    pub structure_size: u16,
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32,
    #[br(temp)]
    #[bw(calc = if input_buffer.is_empty() { 0 } else { 64 + 40 })]
    input_buffer_offset: u16,
    pub reserved: u16,
    #[br(temp)]
    #[bw(calc = input_buffer.len() as u32)]
    input_buffer_length: u32,
    pub additional_information: u32,
    pub flags: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(count = input_buffer_length)]
    pub input_buffer: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoResponse {
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

//! SMB2 SET_INFO Request/Response. MS-SMB2 §2.2.39 / §2.2.40.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoRequest {
    pub structure_size: u16,
    pub info_type: u8,
    pub file_info_class: u8,
    #[br(temp)]
    #[bw(calc = buffer.len() as u32)]
    buffer_length: u32,
    #[br(temp)]
    #[bw(calc = if buffer.is_empty() { 0 } else { 64 + 32 })]
    buffer_offset: u16,
    pub reserved: u16,
    pub additional_information: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(count = buffer_length)]
    pub buffer: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoResponse {
    pub structure_size: u16,
}

//! SMB2 WRITE Request/Response. MS-SMB2 §2.2.21 / §2.2.22.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = if data.is_empty() { 0 } else { 64 + 48 })]
    data_offset: u16,
    #[br(temp)]
    #[bw(calc = data.len() as u32)]
    length: u32,
    pub offset: u64,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub channel: u32,
    pub remaining_bytes: u32,
    /// 0 unless RDMA write channel info follows the data buffer.
    pub write_channel_info_offset: u16,
    /// 0 unless RDMA write channel info follows the data buffer.
    pub write_channel_info_length: u16,
    pub flags: u32,
    #[br(count = length)]
    pub data: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub count: u32,
    pub remaining: u32,
    pub write_channel_info_offset: u16,
    pub write_channel_info_length: u16,
}

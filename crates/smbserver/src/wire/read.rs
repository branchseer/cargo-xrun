//! SMB2 READ Request/Response. MS-SMB2 §2.2.19 / §2.2.20.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub structure_size: u16,
    /// SMB 3.x: ChannelInfoOffset bits when used; padding otherwise.
    pub padding: u8,
    pub flags: u8,
    pub length: u32,
    pub offset: u64,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub minimum_count: u32,
    pub channel: u32,
    pub remaining_bytes: u32,
    #[br(temp)]
    #[bw(calc = if read_channel_info.is_empty() { 0 } else { 64 + 48 })]
    read_channel_info_offset: u16,
    #[br(temp)]
    #[bw(calc = read_channel_info.len() as u16)]
    read_channel_info_length: u16,
    /// SMB 3.x RDMA channel info; empty otherwise (1-byte placeholder per
    /// spec is the caller's responsibility).
    #[br(count = read_channel_info_length)]
    pub read_channel_info: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = if data.is_empty() { 0 } else { 64 + 16 })]
    data_offset: u8,
    pub reserved: u8,
    #[br(temp)]
    #[bw(calc = data.len() as u32)]
    data_length: u32,
    pub data_remaining: u32,
    /// SMB 3.x flags (READ_RESPONSE_FLAG_RDMA_TRANSFORM); reserved on older.
    pub flags: u32,
    #[br(count = data_length)]
    pub data: Vec<u8>,
}

//! SMB2 TREE_CONNECT Request/Response. MS-SMB2 §2.2.9 / §2.2.10.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectRequest {
    pub structure_size: u16,
    /// SMB 3.1.1: extension flags (CLUSTER_RECONNECT, REDIRECT_TO_OWNER,
    /// EXTENSION_PRESENT). Reserved on earlier dialects.
    pub flags: u16,
    #[br(temp)]
    #[bw(calc = if path.is_empty() { 0 } else { 72 })]
    path_offset: u16,
    #[br(temp)]
    #[bw(calc = path.len() as u16)]
    path_length: u16,
    /// UTF-16LE share path, e.g. b"\\server\share".
    #[br(count = path_length)]
    pub path: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectResponse {
    pub structure_size: u16,
    pub share_type: u8,
    pub reserved: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

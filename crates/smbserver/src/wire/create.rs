//! SMB2 CREATE Request/Response. MS-SMB2 §2.2.13 / §2.2.14.
//!
//! Initial coverage: name-only CREATE (no create contexts). The contexts
//! chain has its own framing rules (8-byte alignment, linked list of
//! variable-length entries) and is added separately.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub structure_size: u16,
    pub security_flags: u8,
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub smb_create_flags: u64,
    pub reserved: u64,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    #[br(temp)]
    #[bw(calc = if name.is_empty() { 0 } else { 64 + 56 })]
    name_offset: u16,
    #[br(temp)]
    #[bw(calc = name.len() as u16)]
    name_length: u16,
    #[br(temp)]
    #[bw(calc = 0)]
    create_contexts_offset: u32,
    #[br(temp)]
    #[bw(calc = 0)]
    create_contexts_length: u32,
    /// UTF-16LE pathname; empty when create-contexts-only requests are
    /// modelled in a future iteration.
    #[br(count = name_length)]
    pub name: Vec<u8>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResponse {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub reserved2: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    #[br(temp)]
    #[bw(calc = 0)]
    create_contexts_offset: u32,
    #[br(temp)]
    #[bw(calc = 0)]
    create_contexts_length: u32,
}

/// MS-SMB2 §2.2.13.2 — SMB2_CREATE_CONTEXT wrapper. The `buffer` holds
/// `Name` (offset = `name_offset`, length = `name_length`) followed by
/// padding to an 8-byte boundary, then `Data` (offset = `data_offset`,
/// length = `data_length`), then trailing pad to the next context.
/// Modelled as opaque bytes here; structured Name/Data accessors land
/// in a follow-up iteration.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContext {
    pub next: u32,
    pub name_offset: u16,
    pub name_length: u16,
    pub reserved: u16,
    pub data_offset: u16,
    #[br(temp)]
    #[bw(calc = data_length_for_buffer(buffer.len(), *data_offset))]
    data_length: u32,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub buffer: Vec<u8>,
}

/// MS-SMB2 §2.2.13.2.3 — Data of the "DHnQ" CreateContext.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableHandleRequest {
    /// Reserved 16 zero bytes per spec.
    pub durable_request: [u8; 16],
}

/// MS-SMB2 §2.2.13.2.8 — Data of the "RqLs" CreateContext (lease v1, 32 bytes).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_flags: u32,
    pub lease_duration: u64,
}

/// MS-SMB2 §2.2.13.2.10 — Data of the "RqLs" CreateContext (lease v2, 52 bytes).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequestV2 {
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_flags: u32,
    pub lease_duration: u64,
    pub parent_lease_key: [u8; 16],
    pub epoch: u16,
    pub reserved: u16,
}

/// MS-SMB2 §2.2.13.2.13 — Data of the "App" CreateContext.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInstanceId {
    pub structure_size: u16,
    pub reserved: u16,
    pub app_instance_id: [u8; 16],
}

fn data_length_for_buffer(buffer_len: usize, data_offset: u16) -> u32 {
    // 16 bytes of fixed CreateContext header precede the buffer; data_offset
    // is from the start of the context, so subtract the header.
    let header_len = 16u32;
    let data_offset = data_offset as u32;
    if data_offset < header_len {
        return 0;
    }
    let data_start_in_buffer = data_offset - header_len;
    let buffer_len = buffer_len as u32;
    buffer_len.saturating_sub(data_start_in_buffer)
}

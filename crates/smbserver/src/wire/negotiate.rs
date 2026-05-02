//! SMB2 NEGOTIATE messages. MS-SMB2 §2.2.3 / §2.2.4.
//!
//! Initial coverage: pre-3.1.1 layout (no negotiate-context list). The
//! `client_start_time` field overlaps with the 3.1.1 context offset/count
//! tuple — that variant lands in a follow-up iteration.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    pub structure_size: u16,
    #[br(temp)]
    #[bw(calc = dialects.len() as u16)]
    dialect_count: u16,
    pub security_mode: u16,
    pub reserved: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    pub client_start_time: u64,
    #[br(count = dialect_count)]
    pub dialects: Vec<u16>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    pub structure_size: u16,
    pub security_mode: u16,
    pub dialect_revision: u16,
    /// 0 for pre-3.1.1; populated only when negotiate contexts are present.
    pub negotiate_context_count: u16,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    #[br(temp)]
    #[bw(calc = if security_buffer.is_empty() { 0 } else { 128 })]
    security_buffer_offset: u16,
    #[br(temp)]
    #[bw(calc = security_buffer.len() as u16)]
    security_buffer_length: u16,
    /// 0 for pre-3.1.1.
    pub negotiate_context_offset: u32,
    #[br(count = security_buffer_length)]
    pub security_buffer: Vec<u8>,
}

/// MS-SMB2 §2.2.3.1: SMB2 NEGOTIATE_CONTEXT wrapper. Specific context
/// payloads (PreauthIntegrity, Encryption, Compression, ...) live in
/// `data` and are decoded by their own structs in follow-up iterations.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    pub context_type: u16,
    #[br(temp)]
    #[bw(calc = data.len() as u16)]
    data_length: u16,
    pub reserved: u32,
    #[br(count = data_length)]
    pub data: Vec<u8>,
}

/// MS-SMB2 §2.2.3.1.1 — payload of NegotiateContext type 0x0001.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreauthIntegrityCapabilities {
    #[br(temp)]
    #[bw(calc = hash_algorithms.len() as u16)]
    hash_algorithm_count: u16,
    #[br(temp)]
    #[bw(calc = salt.len() as u16)]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    pub hash_algorithms: Vec<u16>,
    #[br(count = salt_length)]
    pub salt: Vec<u8>,
}

/// MS-SMB2 §2.2.3.1.2 — payload of NegotiateContext type 0x0002.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionCapabilities {
    #[br(temp)]
    #[bw(calc = ciphers.len() as u16)]
    cipher_count: u16,
    #[br(count = cipher_count)]
    pub ciphers: Vec<u16>,
}

/// MS-SMB2 §2.2.3.1.3 — payload of NegotiateContext type 0x0003.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionCapabilities {
    #[br(temp)]
    #[bw(calc = compression_algorithms.len() as u16)]
    compression_algorithm_count: u16,
    pub padding: u16,
    pub flags: u32,
    #[br(count = compression_algorithm_count)]
    pub compression_algorithms: Vec<u16>,
}

/// MS-SMB2 §2.2.3.1.4 — payload of NegotiateContext type 0x0005.
/// Whole context body is the UTF-16LE server netname; no fixed header.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetnameNegotiateContextId {
    #[br(parse_with = binrw::helpers::until_eof)]
    pub netname: Vec<u8>,
}

/// MS-SMB2 §2.2.3.1.6 — payload of NegotiateContext type 0x0006.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCapabilities {
    pub flags: u32,
}

/// MS-SMB2 §2.2.3.1.7 — payload of NegotiateContext type 0x0008.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCapabilities {
    #[br(temp)]
    #[bw(calc = signing_algorithms.len() as u16)]
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    pub signing_algorithms: Vec<u16>,
}

/// MS-SMB2 §2.2.3.1.5 — payload of NegotiateContext type 0x0007.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaTransformCapabilities {
    #[br(temp)]
    #[bw(calc = rdma_transforms.len() as u16)]
    transform_count: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    #[br(count = transform_count)]
    pub rdma_transforms: Vec<u16>,
}

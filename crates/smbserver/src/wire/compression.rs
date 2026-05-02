//! SMB2 COMPRESSION_TRANSFORM_HEADER. MS-SMB2 §2.2.42.
//!
//! Initial coverage: unchained variant (Flags == 0). The chained form
//! (Flags == 1) carries a different layout and lands separately.

use binrw::binrw;

pub const COMPRESSION_PROTOCOL_ID: [u8; 4] = [0xFC, b'S', b'M', b'B'];

#[binrw]
#[brw(little, magic = b"\xFCSMB")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionTransformHeaderUnchained {
    pub original_compressed_segment_size: u32,
    pub compression_algorithm: u16,
    /// Always 0 for the unchained form.
    pub flags: u16,
    /// Offset (in bytes) from the end of this header to the compressed
    /// payload — bytes before the offset are sent uncompressed.
    pub offset: u32,
    /// Uncompressed prefix followed by compressed payload, length implied
    /// by the surrounding NetBIOS framing.
    #[br(parse_with = binrw::helpers::until_eof)]
    pub payload: Vec<u8>,
}

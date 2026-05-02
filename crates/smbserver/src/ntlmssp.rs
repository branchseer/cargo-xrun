//! Minimal NTLMSSP server-side message generation. MS-NLMP §2.2.
//!
//! Only the fields needed for an "accept everything" handshake against
//! smb-rs. No real credential validation.

pub const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
pub const MESSAGE_TYPE_NEGOTIATE: u32 = 1;
pub const MESSAGE_TYPE_CHALLENGE: u32 = 2;
pub const MESSAGE_TYPE_AUTHENTICATE: u32 = 3;

/// NEGOTIATE_FLAGS bits we care about (MS-NLMP §2.2.2.5).
pub mod flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub const NEGOTIATE_EXTENDED_SECURITY: u32 = 0x0008_0000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub const NEGOTIATE_56: u32 = 0x8000_0000;
}

/// True if `buf` is an NTLMSSP AUTHENTICATE_MESSAGE (Type 3).
pub fn is_authenticate_message(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    if &buf[..8] != SIGNATURE.as_slice() {
        return false;
    }
    let msg_type = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    msg_type == MESSAGE_TYPE_AUTHENTICATE
}

/// Build an NTLMSSP CHALLENGE_MESSAGE (Type 2).
///
/// The challenge is a fixed value — for an "accept everything" handler
/// we never validate the eventual AUTHENTICATE response so randomness
/// would only make the wire bytes harder to debug.
pub fn challenge_message() -> Vec<u8> {
    let server_challenge: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
    let negotiate_flags = flags::NEGOTIATE_UNICODE
        | flags::REQUEST_TARGET
        | flags::NEGOTIATE_NTLM
        | flags::NEGOTIATE_ALWAYS_SIGN
        | flags::TARGET_TYPE_SERVER
        | flags::NEGOTIATE_EXTENDED_SECURITY
        | flags::NEGOTIATE_TARGET_INFO
        | flags::NEGOTIATE_VERSION
        | flags::NEGOTIATE_128
        | flags::NEGOTIATE_KEY_EXCH
        | flags::NEGOTIATE_56;

    // 4-byte AV_EOL terminator: AvId=0, AvLen=0
    let target_info: [u8; 4] = [0, 0, 0, 0];
    let target_info_offset: u32 = 56; // immediately after the fixed header
    let target_info_len = target_info.len() as u16;

    let mut buf = Vec::with_capacity(56 + target_info.len());
    buf.extend_from_slice(SIGNATURE);
    buf.extend_from_slice(&MESSAGE_TYPE_CHALLENGE.to_le_bytes());
    // TargetNameFields: empty
    buf.extend_from_slice(&0u16.to_le_bytes()); // len
    buf.extend_from_slice(&0u16.to_le_bytes()); // max len
    buf.extend_from_slice(&target_info_offset.to_le_bytes()); // points wherever; len 0 means unread
    // NegotiateFlags
    buf.extend_from_slice(&negotiate_flags.to_le_bytes());
    // ServerChallenge
    buf.extend_from_slice(&server_challenge);
    // Reserved
    buf.extend_from_slice(&[0u8; 8]);
    // TargetInfoFields
    buf.extend_from_slice(&target_info_len.to_le_bytes());
    buf.extend_from_slice(&target_info_len.to_le_bytes());
    buf.extend_from_slice(&target_info_offset.to_le_bytes());
    // Version: ProductMajor=10, ProductMinor=0, Build=17763, Reserved=0,0,0, NTLMRevision=15
    buf.extend_from_slice(&[10, 0, 0xE3, 0x45, 0, 0, 0, 0x0F]);
    // TargetInfo
    buf.extend_from_slice(&target_info);
    buf
}

//! SMB2 LEASE_BREAK Notification/Acknowledgment/Response.
//! MS-SMB2 §2.2.23.2 / §2.2.24.2 / §2.2.25.2.

use binrw::binrw;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakNotification {
    pub structure_size: u16,
    pub new_epoch: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub current_lease_state: u32,
    pub new_lease_state: u32,
    pub break_reason: u32,
    pub access_mask_hint: u32,
    pub share_mask_hint: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakAcknowledgment {
    pub structure_size: u16,
    pub reserved: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_duration: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_duration: u64,
}

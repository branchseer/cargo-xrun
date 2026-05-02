//! Internal self-consistency checks for SMB2 PDU types.
//!
//! Each test asserts `parse(serialize(value)) == value` for a single value
//! of one PDU type. Useful for catching bugs in `#[bw(calc = ...)]` /
//! `#[br(temp)]` width or count mismatches.
//!
//! These tests do **not** validate spec-fidelity — wrong field order, wrong
//! widths, wrong endianness all silently pass as long as the struct is
//! internally consistent. For real validation against an interoperable
//! implementation's bytes, see `tests/golden_smbrs.rs`.

use std::io::Cursor;

use binrw::{BinRead, BinWrite};
use smbserver::wire::cancel::CancelRequest;
use smbserver::wire::change_notify::{ChangeNotifyRequest, ChangeNotifyResponse};
use smbserver::wire::close::{CloseRequest, CloseResponse};
use smbserver::wire::compression::CompressionTransformHeaderUnchained;
use smbserver::wire::create::{
    AppInstanceId, CreateContext, CreateRequest, CreateResponse, DurableHandleRequest,
    LeaseRequest, LeaseRequestV2,
};
use smbserver::wire::echo::{EchoRequest, EchoResponse};
use smbserver::wire::error::ErrorResponse;
use smbserver::wire::flush::{FlushRequest, FlushResponse};
use smbserver::wire::fscc::{
    FileAllocationInformation, FileBasicInformation, FileBothDirectoryInformation,
    FileDirectoryInformation, FileDispositionInformation, FileEndOfFileInformation,
    FileFsAttributeInformation, FileFsFullSizeInformation, FileFsSizeInformation,
    FileFsVolumeInformation, FileFullDirectoryInformation, FileIdBothDirectoryInformation,
    FileNamesInformation, FileNetworkOpenInformation, FileNotifyInformation,
    FilePositionInformation, FileRenameInformation, FileStandardInformation,
};
use smbserver::wire::header::Header;
use smbserver::wire::ioctl::{IoctlRequest, IoctlResponse};
use smbserver::wire::lease_break::{
    LeaseBreakAcknowledgment, LeaseBreakNotification, LeaseBreakResponse,
};
use smbserver::wire::lock::{LockElement, LockRequest, LockResponse};
use smbserver::wire::logoff::{LogoffRequest, LogoffResponse};
use smbserver::wire::negotiate::{
    CompressionCapabilities, EncryptionCapabilities, NegotiateContext, NegotiateRequest,
    NegotiateResponse, NetnameNegotiateContextId, PreauthIntegrityCapabilities,
    RdmaTransformCapabilities, SigningCapabilities, TransportCapabilities,
};
use smbserver::wire::oplock_break::{
    OplockBreakAcknowledgment, OplockBreakNotification, OplockBreakResponse,
};
use smbserver::wire::query_directory::{QueryDirectoryRequest, QueryDirectoryResponse};
use smbserver::wire::query_info::{QueryInfoRequest, QueryInfoResponse};
use smbserver::wire::read::{ReadRequest, ReadResponse};
use smbserver::wire::session_setup::{SessionSetupRequest, SessionSetupResponse};
use smbserver::wire::set_info::{SetInfoRequest, SetInfoResponse};
use smbserver::wire::transform::TransformHeader;
use smbserver::wire::tree_connect::{TreeConnectRequest, TreeConnectResponse};
use smbserver::wire::tree_disconnect::{TreeDisconnectRequest, TreeDisconnectResponse};
use smbserver::wire::write::{WriteRequest, WriteResponse};

fn roundtrip<T>(value: &T) -> T
where
    T: for<'a> BinRead<Args<'a> = ()>
        + for<'a> BinWrite<Args<'a> = ()>
        + binrw::meta::ReadEndian
        + binrw::meta::WriteEndian,
{
    let mut buf = Vec::new();
    value
        .write(&mut Cursor::new(&mut buf))
        .expect("serialize failed");
    T::read(&mut Cursor::new(&buf)).expect("parse failed")
}

#[test]
fn header_roundtrip() {
    let original = Header {
        credit_charge: 1,
        status: 0,
        command: 0x0000, // NEGOTIATE
        credits: 1,
        flags: 0,
        next_command: 0,
        message_id: 42,
        reserved: 0,
        tree_id: 0,
        session_id: 0xDEAD_BEEF_CAFE_F00D,
        signature: [0xAB; 16],
        ..Header::default()
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn lease_break_notification_roundtrip() {
    let original = LeaseBreakNotification {
        structure_size: 44,
        new_epoch: 7,
        flags: 0x0000_0001, // NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED
        lease_key: [0x33; 16],
        current_lease_state: 0x07, // RWH
        new_lease_state: 0x05,     // RH
        break_reason: 0,
        access_mask_hint: 0,
        share_mask_hint: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lease_break_acknowledgment_roundtrip() {
    let original = LeaseBreakAcknowledgment {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: [0x44; 16],
        lease_state: 0x05, // RH
        lease_duration: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lease_break_response_roundtrip() {
    let original = LeaseBreakResponse {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: [0x55; 16],
        lease_state: 0x05,
        lease_duration: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn oplock_break_notification_roundtrip() {
    let original = OplockBreakNotification {
        structure_size: 24,
        oplock_level: 0x08, // II
        reserved: 0,
        reserved2: 0,
        file_id_persistent: 0xAAAA_AAAA_AAAA_AAAA,
        file_id_volatile: 0xBBBB_BBBB_BBBB_BBBB,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn oplock_break_acknowledgment_roundtrip() {
    let original = OplockBreakAcknowledgment {
        structure_size: 24,
        oplock_level: 0x00, // NONE
        reserved: 0,
        reserved2: 0,
        file_id_persistent: 0xCCCC_CCCC_CCCC_CCCC,
        file_id_volatile: 0xDDDD_DDDD_DDDD_DDDD,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn oplock_break_response_roundtrip() {
    let original = OplockBreakResponse {
        structure_size: 24,
        oplock_level: 0x00,
        reserved: 0,
        reserved2: 0,
        file_id_persistent: 0xEEEE_EEEE_EEEE_EEEE,
        file_id_volatile: 0xFFFF_FFFF_FFFF_FFFF,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lock_request_roundtrip() {
    let original = LockRequest {
        structure_size: 48,
        lock_sequence: 0x0000_0001,
        file_id_persistent: 0x1111_1111_1111_1111,
        file_id_volatile: 0x2222_2222_2222_2222,
        locks: vec![
            LockElement { offset: 0, length: 4096, flags: 0x01, reserved: 0 },
            LockElement { offset: 8192, length: 1024, flags: 0x02, reserved: 0 },
        ],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lock_response_roundtrip() {
    let original = LockResponse { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn set_info_request_roundtrip() {
    let original = SetInfoRequest {
        structure_size: 33,
        info_type: 0x01,
        file_info_class: 0x14, // FileEndOfFileInformation
        reserved: 0,
        additional_information: 0,
        file_id_persistent: 0xAAAA_5555_AAAA_5555,
        file_id_volatile: 0x5555_AAAA_5555_AAAA,
        buffer: 1024u64.to_le_bytes().to_vec(),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn set_info_response_roundtrip() {
    let original = SetInfoResponse { structure_size: 2 };
    assert_eq!(roundtrip(&original), original);
}

fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

#[test]
fn file_network_open_information_roundtrip() {
    let original = FileNetworkOpenInformation {
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 4,
        allocation_size: 8192,
        end_of_file: 5000,
        file_attributes: 0x80,
        reserved: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_fs_volume_information_roundtrip() {
    let original = FileFsVolumeInformation {
        volume_creation_time: 0x01D8_0000_0000_AAAA,
        volume_serial_number: 0xDEAD_BEEF,
        supports_objects: 0,
        reserved: 0,
        volume_label: utf16_le("DATA"),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_fs_full_size_information_roundtrip() {
    let original = FileFsFullSizeInformation {
        total_allocation_units: 0x1000_0000,
        caller_available_allocation_units: 0x0800_0000,
        actual_available_allocation_units: 0x0900_0000,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_directory_information_roundtrip() {
    let original = FileDirectoryInformation {
        next_entry_offset: 0,
        file_index: 0,
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 4,
        end_of_file: 100,
        allocation_size: 4096,
        file_attributes: 0x80,
        file_name: utf16_le("a.txt"),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_full_directory_information_roundtrip() {
    let original = FileFullDirectoryInformation {
        next_entry_offset: 0,
        file_index: 0,
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 4,
        end_of_file: 200,
        allocation_size: 4096,
        file_attributes: 0x20,
        ea_size: 16,
        file_name: utf16_le("b.bin"),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_names_information_roundtrip() {
    let original = FileNamesInformation {
        next_entry_offset: 0,
        file_index: 7,
        file_name: utf16_le("c"),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_id_both_directory_information_roundtrip() {
    let name: Vec<u8> = "data.bin"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = FileIdBothDirectoryInformation {
        next_entry_offset: 0,
        file_index: 0,
        creation_time: 0x01D8_BEEF_0000_0001,
        last_access_time: 0x01D8_BEEF_0000_0002,
        last_write_time: 0x01D8_BEEF_0000_0003,
        change_time: 0x01D8_BEEF_0000_0004,
        end_of_file: 1024,
        allocation_size: 4096,
        file_attributes: 0x80, // NORMAL
        ea_size: 0,
        short_name_length: 0,
        reserved1: 0,
        short_name: [0; 24],
        reserved2: 0,
        file_id: 0x0123_4567_89AB_CDEF,
        file_name: name,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_fs_attribute_information_roundtrip() {
    let fs_name: Vec<u8> = "NTFS"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = FileFsAttributeInformation {
        file_system_attributes: 0x000F_007F, // CASE_SENSITIVE_SEARCH | UNICODE_ON_DISK | ...
        maximum_component_name_length: 255,
        file_system_name: fs_name,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_fs_size_information_roundtrip() {
    let original = FileFsSizeInformation {
        total_allocation_units: 0x0010_0000,
        available_allocation_units: 0x0008_0000,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_both_directory_information_roundtrip() {
    let name: Vec<u8> = "report.docx"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut short_name = [0u8; 24];
    let short: Vec<u8> = "REPORT~1.DOC"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    short_name[..short.len()].copy_from_slice(&short);
    let original = FileBothDirectoryInformation {
        next_entry_offset: 0,
        file_index: 0,
        creation_time: 0x01D8_0000_0000_0001,
        last_access_time: 0x01D8_0000_0000_0002,
        last_write_time: 0x01D8_0000_0000_0003,
        change_time: 0x01D8_0000_0000_0004,
        end_of_file: 4096,
        allocation_size: 8192,
        file_attributes: 0x20, // ARCHIVE
        ea_size: 0,
        short_name_length: short.len() as u8,
        reserved: 0,
        short_name,
        file_name: name,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_notify_information_roundtrip() {
    let name: Vec<u8> = "modified.txt"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = FileNotifyInformation {
        next_entry_offset: 0,
        action: 0x0000_0003, // FILE_ACTION_MODIFIED
        file_name: name,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_position_information_roundtrip() {
    let original = FilePositionInformation { current_byte_offset: 0x9999 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_rename_information_roundtrip() {
    let target: Vec<u8> = "newname.txt"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = FileRenameInformation {
        replace_if_exists: 1,
        reserved: [0; 7],
        root_directory: 0,
        file_name: target,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_end_of_file_information_roundtrip() {
    let original = FileEndOfFileInformation { end_of_file: 0x1234_5678 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_allocation_information_roundtrip() {
    let original = FileAllocationInformation { allocation_size: 0x10_0000 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_disposition_information_roundtrip() {
    let original = FileDispositionInformation { delete_pending: 1 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_basic_information_roundtrip() {
    let original = FileBasicInformation {
        creation_time: 0x01D8_FAFA_BEEF_F101,
        last_access_time: 0x01D8_FAFA_BEEF_F102,
        last_write_time: 0x01D8_FAFA_BEEF_F103,
        change_time: 0x01D8_FAFA_BEEF_F104,
        file_attributes: 0x0000_0020, // ARCHIVE
        reserved: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn file_standard_information_roundtrip() {
    let original = FileStandardInformation {
        allocation_size: 8192,
        end_of_file: 5000,
        number_of_links: 1,
        delete_pending: 0,
        directory: 0,
        reserved: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn rdma_transform_capabilities_roundtrip() {
    let original = RdmaTransformCapabilities {
        reserved1: 0,
        reserved2: 0,
        rdma_transforms: vec![0x0001], // ENCRYPTION
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn netname_negotiate_context_id_roundtrip() {
    let netname: Vec<u8> = "fileserver.local"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = NetnameNegotiateContextId { netname };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn transport_capabilities_roundtrip() {
    let original = TransportCapabilities { flags: 0x0000_0001 }; // ACCEPT_TRANSPORT_LEVEL_SECURITY
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn signing_capabilities_roundtrip() {
    let original = SigningCapabilities {
        signing_algorithms: vec![0x0002, 0x0001, 0x0000], // AES-GMAC, AES-CMAC, HMAC-SHA256
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn encryption_capabilities_roundtrip() {
    let original = EncryptionCapabilities {
        ciphers: vec![0x0002, 0x0001], // AES-128-GCM, AES-128-CCM
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn compression_capabilities_roundtrip() {
    let original = CompressionCapabilities {
        padding: 0,
        flags: 0x0000_0001, // CHAINED
        compression_algorithms: vec![0x0001, 0x0003], // LZNT1, LZ77+Huffman
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn preauth_integrity_capabilities_roundtrip() {
    let original = PreauthIntegrityCapabilities {
        hash_algorithms: vec![0x0001], // SHA-512
        salt: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn negotiate_context_roundtrip() {
    let original = NegotiateContext {
        context_type: 0x0001, // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        reserved: 0,
        data: vec![0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xAA, 0xBB],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn durable_handle_request_roundtrip() {
    let original = DurableHandleRequest { durable_request: [0; 16] };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lease_request_roundtrip() {
    let original = LeaseRequest {
        lease_key: [0xAB; 16],
        lease_state: 0x07, // RWH
        lease_flags: 0,
        lease_duration: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn lease_request_v2_roundtrip() {
    let original = LeaseRequestV2 {
        lease_key: [0xCD; 16],
        lease_state: 0x07,
        lease_flags: 0x04, // PARENT_LEASE_KEY_SET
        lease_duration: 0,
        parent_lease_key: [0xEF; 16],
        epoch: 1,
        reserved: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn app_instance_id_roundtrip() {
    let original = AppInstanceId {
        structure_size: 20,
        reserved: 0,
        app_instance_id: [0x01; 16],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn create_context_roundtrip() {
    // Name "DHnQ" (4 bytes) at offset 16, padded to 8 (4 bytes pad),
    // Data at offset 24, length 16 (DurableHandleRequest body shape).
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"DHnQ"); // name
    buffer.extend_from_slice(&[0u8; 4]); // pad to 8
    buffer.extend_from_slice(&[0xAA; 16]); // data
    let original = CreateContext {
        next: 0,
        name_offset: 16,
        name_length: 4,
        reserved: 0,
        data_offset: 24,
        buffer,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn create_response_roundtrip() {
    let original = CreateResponse {
        structure_size: 89,
        oplock_level: 0xFF, // LEASE
        flags: 0,
        create_action: 1, // OPENED
        creation_time: 0x01D8_FAFA_BEEF_F001,
        last_access_time: 0x01D8_FAFA_BEEF_F002,
        last_write_time: 0x01D8_FAFA_BEEF_F003,
        change_time: 0x01D8_FAFA_BEEF_F004,
        allocation_size: 8192,
        end_of_file: 5000,
        file_attributes: 0x0000_0080,
        reserved2: 0,
        file_id_persistent: 0x1234_5678_90AB_CDEF,
        file_id_volatile: 0xFEDC_BA09_8765_4321,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn create_request_roundtrip() {
    let name: Vec<u8> = "Documents\\file.txt"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0xFF, // LEASE
        impersonation_level: 2,       // Impersonation
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_019F, // GENERIC_READ | etc.
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1, // OPEN
        create_options: 0x0000_0040, // NON_DIRECTORY_FILE
        name,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn compression_transform_header_unchained_roundtrip() {
    let original = CompressionTransformHeaderUnchained {
        original_compressed_segment_size: 256,
        compression_algorithm: 0x0003, // LZ77+Huffman
        flags: 0,
        offset: 0,
        payload: vec![0xCD; 32],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn transform_header_roundtrip() {
    let original = TransformHeader {
        signature: [0x77; 16],
        nonce: [0x88; 16],
        reserved: 0,
        flags: 0x0001, // ENCRYPTED
        session_id: 0xABCD_EF01_2345_6789,
        encrypted_payload: vec![0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn ioctl_request_roundtrip() {
    let original = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: 0x0011_400C, // FSCTL_PIPE_TRANSCEIVE
        file_id_persistent: 0x0102_0304_0506_0708,
        file_id_volatile: 0x0807_0605_0403_0201,
        max_input_response: 0,
        max_output_response: 1024,
        flags: 0x0000_0001, // SMB2_0_IOCTL_IS_FSCTL
        reserved2: 0,
        input_buffer: b"\x01\x00\x00\x00ping".to_vec(),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn ioctl_response_roundtrip() {
    let original = IoctlResponse {
        structure_size: 49,
        reserved: 0,
        ctl_code: 0x0011_400C,
        file_id_persistent: 0x0102_0304_0506_0708,
        file_id_volatile: 0x0807_0605_0403_0201,
        flags: 0,
        reserved2: 0,
        output_buffer: b"pong\x00\x00\x00\x00".to_vec(),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn query_directory_request_roundtrip() {
    let pattern: Vec<u8> = "*".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let original = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: 0x25, // FileIdBothDirectoryInformation
        flags: 0x01,                  // RESTART_SCANS
        file_index: 0,
        file_id_persistent: 0xCAFE_F00D_DEAD_BEEF,
        file_id_volatile: 0xBEEF_DEAD_F00D_CAFE,
        output_buffer_length: 65536,
        file_name: pattern,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn query_directory_response_roundtrip() {
    let original = QueryDirectoryResponse {
        structure_size: 9,
        output_buffer: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn query_info_request_roundtrip() {
    let original = QueryInfoRequest {
        structure_size: 41,
        info_type: 0x01, // FILE
        file_info_class: 0x05, // FileStandardInformation
        output_buffer_length: 4096,
        reserved: 0,
        additional_information: 0,
        flags: 0,
        file_id_persistent: 0x9999_8888_7777_6666,
        file_id_volatile: 0x5555_4444_3333_2222,
        input_buffer: vec![],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn query_info_response_roundtrip() {
    let original = QueryInfoResponse {
        structure_size: 9,
        output_buffer: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn change_notify_request_roundtrip() {
    let original = ChangeNotifyRequest {
        structure_size: 32,
        flags: 0x0001, // WATCH_TREE
        output_buffer_length: 4096,
        file_id_persistent: 0x0F0F_0F0F_0F0F_0F0F,
        file_id_volatile: 0xF0F0_F0F0_F0F0_F0F0,
        completion_filter: 0x0000_017F,
        reserved: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn change_notify_response_roundtrip() {
    let original = ChangeNotifyResponse {
        structure_size: 9,
        buffer: vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn cancel_request_roundtrip() {
    let original = CancelRequest { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn flush_request_roundtrip() {
    let original = FlushRequest {
        structure_size: 24,
        reserved1: 0,
        reserved2: 0,
        file_id_persistent: 0xDEAD_BEEF_F00D_F00D,
        file_id_volatile: 0xCAFE_BABE_DEAD_BEEF,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn flush_response_roundtrip() {
    let original = FlushResponse { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn write_request_roundtrip() {
    let original = WriteRequest {
        structure_size: 49,
        offset: 1024,
        file_id_persistent: 0xAAAA_BBBB_CCCC_DDDD,
        file_id_volatile: 0x1111_2222_3333_4444,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0x0000_0001, // WRITE_THROUGH
        data: b"payload bytes".to_vec(),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn write_response_roundtrip() {
    let original = WriteResponse {
        structure_size: 17,
        reserved: 0,
        count: 13,
        remaining: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn read_request_roundtrip() {
    let original = ReadRequest {
        structure_size: 49,
        padding: 0x50,
        flags: 0,
        length: 4096,
        offset: 0,
        file_id_persistent: 0x0011_2233_4455_6677,
        file_id_volatile: 0x8899_AABB_CCDD_EEFF,
        minimum_count: 1,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info: vec![],
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn read_response_roundtrip() {
    let original = ReadResponse {
        structure_size: 17,
        reserved: 0,
        data_remaining: 0,
        flags: 0,
        data: b"hello, smb world!".to_vec(),
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn close_request_roundtrip() {
    let original = CloseRequest {
        structure_size: 24,
        flags: 0x0001, // POSTQUERY_ATTRIB
        reserved: 0,
        file_id_persistent: 0x0123_4567_89AB_CDEF,
        file_id_volatile: 0xFEDC_BA98_7654_3210,
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn close_response_roundtrip() {
    let original = CloseResponse {
        structure_size: 60,
        flags: 0x0001,
        reserved: 0,
        creation_time: 0x01D8_FAFA_BEEF_F00D,
        last_access_time: 0x01D8_FAFA_BEEF_F00E,
        last_write_time: 0x01D8_FAFA_BEEF_F00F,
        change_time: 0x01D8_FAFA_BEEF_F010,
        allocation_size: 4096,
        end_of_file: 1024,
        file_attributes: 0x0000_0080, // NORMAL
    };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn echo_request_roundtrip() {
    let original = EchoRequest { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn echo_response_roundtrip() {
    let original = EchoResponse { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn logoff_request_roundtrip() {
    let original = LogoffRequest { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn logoff_response_roundtrip() {
    let original = LogoffResponse { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn tree_disconnect_request_roundtrip() {
    let original = TreeDisconnectRequest { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn tree_disconnect_response_roundtrip() {
    let original = TreeDisconnectResponse { structure_size: 4, reserved: 0 };
    assert_eq!(roundtrip(&original), original);
}

#[test]
fn tree_connect_request_roundtrip() {
    // "\\srv\share" in UTF-16LE
    let path: Vec<u8> = "\\\\srv\\share"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let original = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path,
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn tree_connect_response_roundtrip() {
    let original = TreeConnectResponse {
        structure_size: 16,
        share_type: 0x01, // DISK
        reserved: 0,
        share_flags: 0x0000_0030,
        capabilities: 0x0000_0008,
        maximal_access: 0x001F_01FF,
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn session_setup_request_roundtrip() {
    let original = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0x0000_0001,
        channel: 0,
        previous_session_id: 0,
        security_buffer: vec![0x60, 0x82, 0x01, 0x37, 0x06, 0x06, 0x2B, 0x06],
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn session_setup_response_roundtrip() {
    let original = SessionSetupResponse {
        structure_size: 9,
        session_flags: 0x0001, // GUEST
        security_buffer: vec![0xA1, 0x82, 0x01, 0x05, 0x30, 0x82, 0x01, 0x01],
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn error_response_roundtrip() {
    let original = ErrorResponse {
        structure_size: 9,
        error_context_count: 0,
        reserved: 0,
        error_data: vec![0x00],
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn negotiate_response_roundtrip() {
    let original = NegotiateResponse {
        structure_size: 65,
        security_mode: 0x0001,
        dialect_revision: 0x0210,
        negotiate_context_count: 0,
        server_guid: [0x22; 16],
        capabilities: 0x0000_0007,
        max_transact_size: 0x0010_0000,
        max_read_size: 0x0010_0000,
        max_write_size: 0x0010_0000,
        system_time: 0x01D8_FAFA_BEEF_F00D,
        server_start_time: 0,
        negotiate_context_offset: 0,
        security_buffer: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

#[test]
fn negotiate_request_roundtrip() {
    let original = NegotiateRequest {
        structure_size: 36,
        security_mode: 0x0001, // SIGNING_ENABLED
        reserved: 0,
        capabilities: 0x0000_007F,
        client_guid: [0x11; 16],
        client_start_time: 0,
        dialects: vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311],
    };
    let decoded = roundtrip(&original);
    assert_eq!(decoded, original);
}

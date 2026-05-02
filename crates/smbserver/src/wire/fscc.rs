//! MS-FSCC file information classes used as bodies of QUERY_INFO,
//! SET_INFO, QUERY_DIRECTORY, and CHANGE_NOTIFY exchanges.

use binrw::binrw;

/// MS-FSCC §2.4.7. FileInformationClass = FileBasicInformation (4).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBasicInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_attributes: u32,
    pub reserved: u32,
}

/// MS-FSCC §2.4.41. FileInformationClass = FileStandardInformation (5).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub reserved: u16,
}

/// MS-FSCC §2.4.13. FileInformationClass = FileEndOfFileInformation (20).
/// Used as the SET_INFO body to truncate or extend a file.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEndOfFileInformation {
    pub end_of_file: u64,
}

/// MS-FSCC §2.4.4. FileInformationClass = FileAllocationInformation (19).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAllocationInformation {
    pub allocation_size: u64,
}

/// MS-FSCC §2.4.11. FileInformationClass = FileDispositionInformation (13).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDispositionInformation {
    pub delete_pending: u8,
}

/// MS-FSCC §2.4.32. FileInformationClass = FilePositionInformation (14).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePositionInformation {
    pub current_byte_offset: u64,
}

/// MS-FSCC §2.4.8. FileInformationClass = FileBothDirectoryInformation (3).
/// Single record; chained via `next_entry_offset` (0 = last).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBothDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    pub reserved: u8,
    /// 8.3 short name in UTF-16LE; padded with zeros to 24 bytes.
    pub short_name: [u8; 24],
    /// UTF-16LE long file name.
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.4.27. FileInformationClass = FileNetworkOpenInformation (34).
/// Compact "all-at-once" info: timestamps + sizes + attributes.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub reserved: u32,
}

/// MS-FSCC §2.5.9. FileSystemInformationClass = FileFsVolumeInformation (1).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: u64,
    pub volume_serial_number: u32,
    #[br(temp)]
    #[bw(calc = volume_label.len() as u32)]
    volume_label_length: u32,
    pub supports_objects: u8,
    pub reserved: u8,
    /// UTF-16LE volume label.
    #[br(count = volume_label_length)]
    pub volume_label: Vec<u8>,
}

/// MS-FSCC §2.5.4. FileSystemInformationClass = FileFsFullSizeInformation (7).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// MS-FSCC §2.4.10. FileInformationClass = FileDirectoryInformation (1).
/// Minimal directory entry — no short name, no EA size.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.4.14. FileInformationClass = FileFullDirectoryInformation (2).
/// Like FileDirectoryInformation plus EaSize.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFullDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    pub ea_size: u32,
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.4.26. FileInformationClass = FileNamesInformation (12).
/// Names-only directory listing — no timestamps or sizes.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNamesInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.4.17. FileInformationClass = FileIdBothDirectoryInformation (37).
/// Same as FileBothDirectoryInformation but carries a 64-bit FileId.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdBothDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    pub reserved1: u8,
    pub short_name: [u8; 24],
    pub reserved2: u16,
    pub file_id: u64,
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.5.1. FileSystemInformationClass = FileFsAttributeInformation (5).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFsAttributeInformation {
    pub file_system_attributes: u32,
    pub maximum_component_name_length: i32,
    #[br(temp)]
    #[bw(calc = file_system_name.len() as u32)]
    file_system_name_length: u32,
    /// UTF-16LE filesystem name, e.g. b"NTFS".
    #[br(count = file_system_name_length)]
    pub file_system_name: Vec<u8>,
}

/// MS-FSCC §2.5.8. FileSystemInformationClass = FileFsSizeInformation (3).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// MS-FSCC §2.4.42. Single FileNotifyInformation record. Records form a
/// linked chain via `next_entry_offset` (0 = last); each is the body of a
/// CHANGE_NOTIFY response entry.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotifyInformation {
    pub next_entry_offset: u32,
    pub action: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    /// UTF-16LE relative path of the affected file.
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

/// MS-FSCC §2.4.37 — SMB2 wire form (FileInformationClass = FileRenameInformation, 10).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRenameInformation {
    pub replace_if_exists: u8,
    pub reserved: [u8; 7],
    pub root_directory: u64,
    #[br(temp)]
    #[bw(calc = file_name.len() as u32)]
    file_name_length: u32,
    /// UTF-16LE target path.
    #[br(count = file_name_length)]
    pub file_name: Vec<u8>,
}

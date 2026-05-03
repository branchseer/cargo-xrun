//! Pluggable filesystem layer.
//!
//! The trait is synchronous for now — in-memory and other lock-free
//! backends can implement directly; blocking I/O backends should
//! delegate to `tokio::task::spawn_blocking` at the call site.

use std::io;
use std::sync::Arc;

pub trait Filesystem: Send + Sync + 'static {
    /// Open `path` (relative to the share root, separator `/`) for reading.
    /// Path components are UTF-8; the server has already decoded the
    /// UTF-16LE sent on the wire.
    fn open(&self, path: &str) -> io::Result<Arc<dyn FileHandle>>;

    /// Create a new file at `path` and return a handle to it.
    ///
    /// Default impl rejects all creates with `ErrorKind::Unsupported`,
    /// preserving the read-only contract for existing implementations.
    fn create(&self, _path: &str) -> io::Result<Arc<dyn FileHandle>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Filesystem is read-only",
        ))
    }

    /// Create a new directory at `path` and return a handle to it.
    /// Default rejects with `Unsupported`.
    fn create_dir(&self, _path: &str) -> io::Result<Arc<dyn FileHandle>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Filesystem does not support mkdir",
        ))
    }

    /// Rename `from` to `to`. Default rejects with `Unsupported`.
    fn rename(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Filesystem does not support rename",
        ))
    }

    /// Delete the file at `path`. Default rejects with `Unsupported`.
    fn delete(&self, _path: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Filesystem does not support delete",
        ))
    }

    /// Volume-level metadata returned in response to QUERY_INFO with
    /// info_type = FILESYSTEM. Default returns reasonable placeholders.
    fn volume_info(&self) -> VolumeInfo {
        VolumeInfo::default()
    }

    /// Begin watching `dir_path` for changes (CHANGE_NOTIFY).
    ///
    /// Returning `None` means the backend does not support watching;
    /// the server will reply STATUS_NOT_SUPPORTED so clients fall back
    /// to polling. Backends that do support watching return a
    /// [`Watcher`] whose `next` future yields the next batch of changes.
    fn watch(&self, _dir_path: &str, _recursive: bool) -> Option<Box<dyn Watcher>> {
        None
    }
}

/// Asynchronous notification source for CHANGE_NOTIFY.
///
/// `next` resolves with the next batch of changes (one or more), or
/// `None` if the watch is closed (the directory was removed, the
/// backend gave up, etc.).
pub trait Watcher: Send {
    fn next<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<DirChange>>> + Send + 'a>>;
}

/// One change reported by a [`Watcher`].
#[derive(Debug, Clone)]
pub struct DirChange {
    /// Path relative to the share root, using `/` as separator.
    pub path: String,
    pub kind: ChangeKind,
}

/// What happened to the file. Mirrors `FILE_ACTION_*` codes from
/// MS-FSCC §2.4.42.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    RenamedOldName,
    RenamedNewName,
}

impl ChangeKind {
    pub fn as_action(self) -> u32 {
        match self {
            ChangeKind::Added => 0x0000_0001,
            ChangeKind::Removed => 0x0000_0002,
            ChangeKind::Modified => 0x0000_0003,
            ChangeKind::RenamedOldName => 0x0000_0004,
            ChangeKind::RenamedNewName => 0x0000_0005,
        }
    }
}

/// Volume-level metadata for QUERY_INFO type = FILESYSTEM responses.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Volume label (UTF-8); marshalled as UTF-16LE on the wire.
    pub label: String,
    pub serial_number: u32,
    /// Total bytes on the volume. Use `u64::MAX` for "unlimited".
    pub total_bytes: u64,
    /// Bytes still available for the caller to allocate.
    pub available_bytes: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_unit: u32,
    /// Filesystem identifier shown to clients, e.g. "NTFS", "ext4".
    pub fs_name: String,
    pub case_sensitive: bool,
    pub max_component_length: u32,
}

impl Default for VolumeInfo {
    fn default() -> Self {
        Self {
            label: String::new(),
            serial_number: 0xDEAD_BEEF,
            total_bytes: u64::MAX,
            available_bytes: u64::MAX,
            bytes_per_sector: 512,
            sectors_per_unit: 8,
            fs_name: "smbserver-rs".to_string(),
            case_sensitive: false,
            max_component_length: 255,
        }
    }
}

pub trait FileHandle: Send + Sync {
    /// Total file size in bytes — used to populate the CREATE Response
    /// `end_of_file` field and to bound READs. Directories report 0.
    fn size(&self) -> u64;

    /// True for directory handles. Default false (file).
    fn is_directory(&self) -> bool {
        false
    }

    /// Full metadata for QUERY_INFO responses. The default composes
    /// from `size()` and `is_directory()` with zero timestamps;
    /// backends with real timestamps should override.
    fn metadata(&self) -> FileMetadata {
        FileMetadata {
            size: self.size(),
            allocation_size: self.size(),
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            is_directory: self.is_directory(),
        }
    }

    /// Read up to `len` bytes starting at `offset`. Returns fewer bytes
    /// than requested only at end-of-file.
    fn read(&self, _offset: u64, _len: u32) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileHandle does not support reads",
        ))
    }

    /// Write `data` at `offset`, extending the file as needed. Returns
    /// the number of bytes accepted (typically `data.len()`).
    fn write(&self, _offset: u64, _data: &[u8]) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileHandle is read-only",
        ))
    }

    /// List the immediate children of this directory handle. Called
    /// in response to QUERY_DIRECTORY. Default: not a directory.
    fn list_children(&self) -> io::Result<Vec<DirEntry>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileHandle is not a directory",
        ))
    }

    /// Truncate or extend the file to exactly `size` bytes. Called in
    /// response to SET_INFO with FileEndOfFileInformation. Extending
    /// zero-fills. Default: rejected.
    fn truncate(&self, _size: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileHandle does not support truncate",
        ))
    }

    /// Flush any buffered writes to durable storage. Called in response
    /// to FLUSH. Default returns Ok (most backends are write-through).
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// One entry returned by `FileHandle::list_children`. The server marshals
/// these into FILE_BOTH_DIR_INFORMATION records on the wire.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Metadata for a single open handle. Returned by `FileHandle::metadata`
/// and consumed by the server's QUERY_INFO handler.
///
/// Timestamps are Windows FILETIME (100-ns ticks since 1601-01-01 UTC).
/// Zero is acceptable for backends without real timestamps.
#[derive(Debug, Clone, Default)]
pub struct FileMetadata {
    pub size: u64,
    pub allocation_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub is_directory: bool,
}

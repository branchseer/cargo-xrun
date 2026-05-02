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

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
}

pub trait FileHandle: Send + Sync {
    /// Total file size in bytes — used to populate the CREATE Response
    /// `end_of_file` field and to bound READs.
    fn size(&self) -> u64;

    /// Read up to `len` bytes starting at `offset`. Returns fewer bytes
    /// than requested only at end-of-file.
    fn read(&self, offset: u64, len: u32) -> io::Result<Vec<u8>>;
}

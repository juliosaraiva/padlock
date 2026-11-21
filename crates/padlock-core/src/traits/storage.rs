//! Storage backend trait for vault persistence.
//!
//! This trait abstracts the underlying storage mechanism for vault data,
//! allowing the core library to remain independent of filesystem details.
//! Production code uses a filesystem backend; tests use an in-memory backend.

use crate::error::Result;

/// Abstraction over vault file storage.
///
/// Implementations handle reading and writing the vault binary file.
/// The core library interacts with storage exclusively through this trait,
/// enabling test isolation and future alternative backends.
///
/// # Implementors
///
/// - `FilesystemBackend` (production): reads/writes vault files on disk
/// - `InMemoryBackend` (testing): stores vault data in memory
pub trait StorageBackend: Send + Sync {
    /// Write the complete vault data to storage.
    ///
    /// This should be an atomic operation where possible. The data
    /// includes the full vault file contents (header, index, entries, HMAC).
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails.
    fn write_vault(&self, data: &[u8]) -> Result<()>;

    /// Read the complete vault data from storage.
    ///
    /// Returns the full vault file contents as a byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault does not exist or cannot be read.
    fn read_vault(&self) -> Result<Vec<u8>>;

    /// Check whether a vault exists in storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the existence check cannot be performed.
    fn vault_exists(&self) -> Result<bool>;

    /// Write a backup copy of the vault data.
    ///
    /// Used during atomic write operations to preserve the previous
    /// vault state before replacing it.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup write fails.
    fn write_backup(&self, data: &[u8]) -> Result<()>;

    /// Write vault data from multiple segments without assembling a full buffer.
    ///
    /// The default implementation concatenates segments and calls `write_vault()`.
    /// Filesystem backends can override this to write segments sequentially,
    /// reducing peak memory usage for large vaults.
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails.
    fn write_vault_segments(&self, segments: &[&[u8]]) -> Result<()> {
        let total: usize = segments.iter().map(|s| s.len()).sum();
        let mut data = Vec::with_capacity(total);
        for segment in segments {
            data.extend_from_slice(segment);
        }
        self.write_vault(&data)
    }
}

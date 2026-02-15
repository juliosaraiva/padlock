//! Filesystem-based vault storage backend.
//!
//! Implements the `StorageBackend` trait for reading and writing vault
//! files from the filesystem with proper permission enforcement.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, VaultError};
use crate::traits::storage::StorageBackend;

/// Filesystem storage backend for vault persistence.
///
/// Reads and writes vault files at a specified path with
/// atomic write support and file permission enforcement.
pub struct FilesystemBackend {
    /// Path to the vault file.
    vault_path: PathBuf,
}

impl FilesystemBackend {
    /// Create a new filesystem backend for the given vault path.
    #[must_use]
    pub fn new(vault_path: PathBuf) -> Self {
        Self { vault_path }
    }

    /// Get the vault file path.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }
}

impl StorageBackend for FilesystemBackend {
    fn write_vault(&self, data: &[u8]) -> crate::error::Result<()> {
        crate::vault::atomic::atomic_write(&self.vault_path, data)
    }

    fn read_vault(&self) -> crate::error::Result<Vec<u8>> {
        fs::read(&self.vault_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Vault(VaultError::NotFound {
                    path: self.vault_path.display().to_string(),
                })
            } else {
                Error::Io(e)
            }
        })
    }

    fn vault_exists(&self) -> crate::error::Result<bool> {
        Ok(self.vault_path.exists())
    }

    fn write_backup(&self, data: &[u8]) -> crate::error::Result<()> {
        let backup_path = self.vault_path.with_extension("bak");
        crate::vault::atomic::atomic_write(&backup_path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_filesystem_backend_write_read_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        let backend = FilesystemBackend::new(path);

        let data = b"vault file contents";
        backend.write_vault(data).unwrap();
        let read_data = backend.read_vault().unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_filesystem_backend_vault_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        let backend = FilesystemBackend::new(path);

        assert!(!backend.vault_exists().unwrap());
        backend.write_vault(b"data").unwrap();
        assert!(backend.vault_exists().unwrap());
    }

    #[test]
    fn test_filesystem_backend_read_nonexistent_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.padlock");
        let backend = FilesystemBackend::new(path);

        let result = backend.read_vault();
        assert!(result.is_err());
    }

    #[test]
    fn test_filesystem_backend_write_backup() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        let backend = FilesystemBackend::new(path.clone());

        backend.write_backup(b"backup data").unwrap();
        let backup_path = path.with_extension("bak");
        assert!(backup_path.exists());
    }
}

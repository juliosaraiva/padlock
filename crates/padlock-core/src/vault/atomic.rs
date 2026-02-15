//! Atomic file write operations for crash-safe vault updates.
//!
//! Implements the write-tmp-fsync-rename pattern to ensure vault writes
//! are all-or-nothing. If the process crashes during a write, the
//! previous vault file remains intact.
//!
//! # Write Sequence
//!
//! 1. Write data to a temporary file in the same directory
//! 2. `fsync` the temporary file to ensure data is on disk
//! 3. Rename the temporary file to the target path (atomic on POSIX)
//! 4. `fsync` the parent directory to ensure the rename is durable

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{Error, VaultError};

/// Atomically write data to a file.
///
/// Uses a temporary file and rename to ensure crash-safety.
/// The previous file (if any) remains intact until the rename succeeds.
///
/// # Errors
///
/// Returns `VaultError::AtomicWriteFailed` if any step fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> crate::error::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: "no parent directory".to_string(),
        })
    })?;

    // Create parent directory if needed
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::Vault(VaultError::AtomicWriteFailed {
                reason: format!("failed to create directory: {e}"),
            })
        })?;
    }

    // Write to temporary file
    let tmp_path = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path).map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to create temp file: {e}"),
        })
    })?;

    file.write_all(data).map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to write temp file: {e}"),
        })
    })?;

    // Fsync the file
    file.sync_all().map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to fsync temp file: {e}"),
        })
    })?;

    // Set file permissions (0o600: owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp_path, perms).map_err(|e| {
            Error::Vault(VaultError::AtomicWriteFailed {
                reason: format!("failed to set permissions: {e}"),
            })
        })?;
    }

    // Atomic rename
    fs::rename(&tmp_path, path).map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to rename: {e}"),
        })
    })?;

    // Fsync the parent directory
    fsync_dir(parent)?;

    Ok(())
}

/// Fsync a directory to ensure rename durability.
fn fsync_dir(path: &Path) -> crate::error::Result<()> {
    let dir = fs::File::open(path).map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to open dir for fsync: {e}"),
        })
    })?;
    dir.sync_all().map_err(|e| {
        Error::Vault(VaultError::AtomicWriteFailed {
            reason: format!("failed to fsync dir: {e}"),
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        atomic_write(&path, b"test data").unwrap();
        assert!(path.exists());
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"test data");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"second");
    }

    #[test]
    fn test_atomic_write_no_temp_file_left() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        atomic_write(&path, b"data").unwrap();
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists(), "temp file should be cleaned up");
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_write_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.padlock");
        atomic_write(&path, b"data").unwrap();
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

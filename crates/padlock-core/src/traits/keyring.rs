//! Platform keyring trait for OS-level secret storage.
//!
//! This trait abstracts access to platform-specific keyrings such as
//! macOS Keychain or Linux Secret Service. The MVP uses a no-op
//! implementation; platform integrations are planned for v1.1.

use crate::error::Result;

/// Abstraction over OS-level keyring/keychain services.
///
/// Allows the vault to optionally store encryption keys in the
/// platform keyring for convenience features like biometric unlock.
///
/// # MVP Implementation
///
/// The MVP ships with `NoOpKeyring` which always reports unavailability.
/// Platform-specific implementations will be added in v1.1.
pub trait PlatformKeyring: Send + Sync {
    /// Retrieve a key from the platform keyring.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not found or the keyring is unavailable.
    fn get_key(&self, identifier: &str) -> Result<Vec<u8>>;

    /// Store a key in the platform keyring.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be stored.
    fn set_key(&self, identifier: &str, key: &[u8]) -> Result<()>;

    /// Delete a key from the platform keyring.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be deleted.
    fn delete_key(&self, identifier: &str) -> Result<()>;

    /// Check whether the platform keyring is available.
    fn is_available(&self) -> bool;
}

/// No-op keyring implementation for the MVP.
///
/// Always reports the keyring as unavailable. Used as the default
/// implementation until platform-specific keyrings are implemented.
pub struct NoOpKeyring;

impl PlatformKeyring for NoOpKeyring {
    fn get_key(&self, _identifier: &str) -> Result<Vec<u8>> {
        Err(crate::error::Error::NotSupported(
            "platform keyring not available in MVP".to_string(),
        ))
    }

    fn set_key(&self, _identifier: &str, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    fn delete_key(&self, _identifier: &str) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        false
    }
}

//! Mock implementations of core traits for testing.
//!
//! Provides in-memory implementations of `StorageBackend`,
//! `UserConfirmation`, `PlatformKeyring`, and `AuditLogger`
//! for use in unit and integration tests.

use padlock_core::error::Result;
use padlock_core::traits::storage::StorageBackend;
use padlock_core::traits::user::UserConfirmation;
use padlock_core::types::AuditEvent;
use std::sync::{Arc, Mutex};

/// In-memory storage backend for testing.
///
/// Stores vault data in memory instead of on disk.
/// Useful for fast, isolated tests that do not require filesystem I/O.
pub struct InMemoryBackend {
    vault_data: Arc<Mutex<Option<Vec<u8>>>>,
    backup_data: Arc<Mutex<Option<Vec<u8>>>>,
}

impl InMemoryBackend {
    /// Create a new empty in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vault_data: Arc::new(Mutex::new(None)),
            backup_data: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn write_vault(&self, data: &[u8]) -> Result<()> {
        let mut vault = self.vault_data.lock().map_err(|e| {
            padlock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        *vault = Some(data.to_vec());
        Ok(())
    }

    fn read_vault(&self) -> Result<Vec<u8>> {
        let vault = self.vault_data.lock().map_err(|e| {
            padlock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        vault.clone().ok_or_else(|| {
            padlock_core::error::Error::Vault(padlock_core::error::VaultError::NotFound {
                path: "<in-memory>".to_string(),
            })
        })
    }

    fn vault_exists(&self) -> Result<bool> {
        let vault = self.vault_data.lock().map_err(|e| {
            padlock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        Ok(vault.is_some())
    }

    fn write_backup(&self, data: &[u8]) -> Result<()> {
        let mut backup = self.backup_data.lock().map_err(|e| {
            padlock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        *backup = Some(data.to_vec());
        Ok(())
    }
}

/// Test prompt that returns predetermined responses.
///
/// Useful for testing vault operations that require user interaction
/// without actual terminal input.
pub struct TestPrompt {
    password: String,
    yes_no_response: bool,
}

impl TestPrompt {
    /// Create a test prompt with a fixed password response.
    #[must_use]
    pub fn new(password: &str) -> Self {
        Self {
            password: password.to_string(),
            yes_no_response: true,
        }
    }

    /// Create a test prompt with custom yes/no response.
    #[must_use]
    pub fn with_responses(password: &str, yes_no: bool) -> Self {
        Self {
            password: password.to_string(),
            yes_no_response: yes_no,
        }
    }
}

impl UserConfirmation for TestPrompt {
    fn prompt_password(&self, _prompt: &str) -> Result<String> {
        Ok(self.password.clone())
    }

    fn prompt_yes_no(&self, _prompt: &str) -> Result<bool> {
        Ok(self.yes_no_response)
    }

    fn show_message(&self, _message: &str) -> Result<()> {
        Ok(())
    }
}

/// In-memory audit logger for testing.
///
/// Stores audit events in a vector for later inspection.
pub struct TestAuditLogger {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl TestAuditLogger {
    /// Create a new test audit logger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get all recorded audit events.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Default for TestAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl padlock_core::traits::audit::AuditLogger for TestAuditLogger {
    fn log_event(&self, event: &AuditEvent) -> Result<()> {
        let mut events = self.events.lock().map_err(|e| {
            padlock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        events.push(event.clone());
        Ok(())
    }
}

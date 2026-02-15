//! Core domain types shared across multiple modules.
//!
//! This module defines fundamental types used throughout the Padlock
//! library, including identifiers, timestamps, and audit events.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for a vault entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(Uuid);

impl EntryId {
    /// Create a new random entry identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an entry identifier from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Convert to raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for EntryId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryId({})", self.0)
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a vault instance.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(Uuid);

impl VaultId {
    /// Create a new random vault identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a vault identifier from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Convert to raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for VaultId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultId({})", self.0)
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unix timestamp wrapper for consistent time handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Create a timestamp for the current time.
    #[must_use]
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp())
    }

    /// Create a timestamp from a Unix epoch seconds value.
    #[must_use]
    pub fn from_epoch_secs(secs: i64) -> Self {
        Self(secs)
    }

    /// Get the Unix epoch seconds value.
    #[must_use]
    pub fn as_epoch_secs(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Actions that can be recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// A new vault was initialized.
    VaultInit,
    /// The vault was unlocked.
    VaultUnlock,
    /// The vault was locked.
    VaultLock,
    /// The vault passphrase was changed.
    VaultPassphraseChange,
    /// A credential entry was created.
    EntryCreate,
    /// A credential entry was read.
    EntryRead,
    /// A credential entry was updated.
    EntryUpdate,
    /// A credential entry was deleted.
    EntryDelete,
    /// An SSH signing operation was performed.
    SshSign,
    /// SSH key identities were listed.
    SshListKeys,
    /// A Git commit was signed.
    GitSign,
    /// A new session was created.
    SessionCreate,
    /// A session was successfully resumed.
    SessionResume,
    /// A session was explicitly destroyed.
    SessionDestroy,
    /// A session expired.
    SessionExpired,
    /// An invalid session token was presented.
    SessionInvalidToken,
}

/// Result of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// The operation succeeded.
    Success,
    /// The operation failed.
    Failure,
}

/// A single audit log event.
///
/// Audit events record all vault operations for compliance and forensic
/// investigation. They intentionally exclude any secret data -- only
/// resource identifiers, action types, and timestamps are recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: Timestamp,
    /// What action was performed.
    pub action: AuditAction,
    /// The identifier of the affected resource, if applicable.
    pub resource_id: Option<String>,
    /// Whether the operation succeeded or failed.
    pub result: AuditResult,
    /// A description of the error if the operation failed.
    pub error_message: Option<String>,
}

impl AuditEvent {
    /// Create a new successful audit event.
    #[must_use]
    pub fn success(action: AuditAction, resource_id: Option<String>) -> Self {
        Self {
            timestamp: Timestamp::now(),
            action,
            resource_id,
            result: AuditResult::Success,
            error_message: None,
        }
    }

    /// Create a new failed audit event.
    #[must_use]
    pub fn failure(action: AuditAction, resource_id: Option<String>, error: String) -> Self {
        Self {
            timestamp: Timestamp::now(),
            action,
            resource_id,
            result: AuditResult::Failure,
            error_message: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_id_new_is_unique() {
        let id1 = EntryId::new();
        let id2 = EntryId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_vault_id_new_is_unique() {
        let id1 = VaultId::new();
        let id2 = VaultId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_timestamp_ordering() {
        let t1 = Timestamp::from_epoch_secs(100);
        let t2 = Timestamp::from_epoch_secs(200);
        assert!(t1 < t2);
    }

    #[test]
    fn test_audit_event_success_creation() {
        let event = AuditEvent::success(AuditAction::VaultInit, None);
        assert_eq!(event.action, AuditAction::VaultInit);
        assert_eq!(event.result, AuditResult::Success);
        assert!(event.error_message.is_none());
    }

    #[test]
    fn test_audit_event_failure_creation() {
        let event = AuditEvent::failure(
            AuditAction::VaultUnlock,
            None,
            "wrong passphrase".to_string(),
        );
        assert_eq!(event.action, AuditAction::VaultUnlock);
        assert_eq!(event.result, AuditResult::Failure);
        assert_eq!(event.error_message.as_deref(), Some("wrong passphrase"));
    }

    #[test]
    fn test_entry_id_round_trip_bytes() {
        let id = EntryId::new();
        let bytes = id.as_bytes();
        let uuid = Uuid::from_bytes(*bytes);
        let recovered = EntryId::from_uuid(uuid);
        assert_eq!(id, recovered);
    }
}

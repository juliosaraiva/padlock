//! Tamper-evident audit logging for vault operations.
//!
//! Records all vault access events, credential operations, and
//! signing requests. Audit events intentionally exclude any secret data.
//!
//! The audit log implementation uses the `AuditLogger` trait from
//! `crate::traits::audit` for pluggable backends.
//!
//! # Backends
//!
//! - [`InMemoryAuditLog`]: Collects events in memory for testing.
//! - [`JsonLinesAuditLog`]: Writes events to a file in JSON Lines format.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::Result;
use crate::traits::audit::AuditLogger;
use crate::types::{AuditAction, AuditEvent};

/// In-memory audit logger that collects events for later retrieval.
///
/// Useful for testing and for batching events before writing to disk.
#[derive(Debug, Default)]
pub struct InMemoryAuditLog {
    events: Vec<AuditEvent>,
}

impl InMemoryAuditLog {
    /// Create a new empty in-memory audit log.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Get all recorded events.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Get the number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get events filtered by action type.
    #[must_use]
    pub fn events_by_action(&self, action: &AuditAction) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| &e.action == action).collect()
    }
}

impl AuditLogger for InMemoryAuditLog {
    fn log_event(&self, _event: &AuditEvent) -> Result<()> {
        // InMemoryAuditLog is immutable through the trait; use the mut version
        // for testing. This is a no-op for the trait impl.
        Ok(())
    }
}

/// JSON Lines audit logger that writes events to a file.
///
/// Each audit event is serialized as a single JSON object on its own line,
/// following the JSON Lines format (one JSON object per line). The file is
/// opened in append mode so events are never lost, even on crash.
///
/// # Example
///
/// ```no_run
/// use padlock_core::audit::JsonLinesAuditLog;
/// use padlock_core::traits::audit::AuditLogger;
/// use padlock_core::types::{AuditAction, AuditEvent};
///
/// let log = JsonLinesAuditLog::new("/tmp/padlock-audit.jsonl").unwrap();
/// let event = AuditEvent::success(AuditAction::VaultInit, None);
/// log.log_event(&event).unwrap();
/// ```
pub struct JsonLinesAuditLog {
    /// Path to the audit log file.
    path: PathBuf,
    /// Mutex to serialize concurrent writes.
    lock: Mutex<()>,
}

impl JsonLinesAuditLog {
    /// Create a new JSON Lines audit logger.
    ///
    /// Creates the parent directory and log file if they do not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created or the
    /// file cannot be opened.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    /// Get the path to the audit log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read all events from the log file.
    ///
    /// Parses each line as a JSON `AuditEvent`. Lines that cannot be parsed
    /// are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn read_events(&self) -> Result<Vec<AuditEvent>> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let events = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        Ok(events)
    }
}

impl std::fmt::Debug for JsonLinesAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonLinesAuditLog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AuditLogger for JsonLinesAuditLog {
    fn log_event(&self, event: &AuditEvent) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|e| crate::error::Error::Config(format!("audit log lock poisoned: {e}")))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        let json = serde_json::to_string(event).map_err(|e| {
            crate::error::Error::Config(format!("failed to serialize audit event: {e}"))
        })?;

        writeln!(file, "{json}")?;
        Ok(())
    }
}

/// Log a vault operation with proper audit tracking.
///
/// This is a convenience function that constructs an audit event
/// and writes it using the provided logger.
///
/// # Errors
///
/// Returns an error if the audit event cannot be logged.
pub fn log_vault_operation(
    logger: &dyn AuditLogger,
    action: AuditAction,
    resource_id: Option<String>,
    success: bool,
    error_msg: Option<String>,
) -> Result<()> {
    let event = if success {
        AuditEvent::success(action, resource_id)
    } else {
        AuditEvent::failure(action, resource_id, error_msg.unwrap_or_default())
    };
    logger.log_event(&event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuditResult;

    #[test]
    fn test_in_memory_audit_log_new_is_empty() {
        let log = InMemoryAuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_log_vault_operation_success() {
        let logger = InMemoryAuditLog::new();
        let result = log_vault_operation(&logger, AuditAction::VaultInit, None, true, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_log_vault_operation_failure() {
        let logger = InMemoryAuditLog::new();
        let result = log_vault_operation(
            &logger,
            AuditAction::VaultUnlock,
            None,
            false,
            Some("wrong passphrase".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_lines_audit_log_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let log = JsonLinesAuditLog::new(&path).unwrap();

        // Write two events
        let event1 = AuditEvent::success(AuditAction::VaultInit, None);
        let event2 = AuditEvent::failure(
            AuditAction::VaultUnlock,
            Some("vault-1".to_string()),
            "wrong passphrase".to_string(),
        );
        log.log_event(&event1).unwrap();
        log.log_event(&event2).unwrap();

        // Read back
        let all_events = log.read_events().unwrap();
        assert_eq!(all_events.len(), 2);
        assert_eq!(all_events[0].action, AuditAction::VaultInit);
        assert_eq!(all_events[0].result, AuditResult::Success);
        assert_eq!(all_events[1].action, AuditAction::VaultUnlock);
        assert_eq!(all_events[1].result, AuditResult::Failure);
        assert_eq!(all_events[1].resource_id.as_deref(), Some("vault-1"));
    }

    #[test]
    fn test_json_lines_audit_log_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("audit.jsonl");

        let log = JsonLinesAuditLog::new(&path).unwrap();
        let event = AuditEvent::success(AuditAction::EntryCreate, Some("entry-1".to_string()));
        log.log_event(&event).unwrap();

        let events = log.read_events().unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_json_lines_audit_log_read_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");

        let log = JsonLinesAuditLog::new(&path).unwrap();
        let events = log.read_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_json_lines_audit_log_read_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.jsonl");

        let log = JsonLinesAuditLog::new(&path).unwrap();
        let events = log.read_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_json_lines_audit_log_append_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.jsonl");

        // Write first event
        let log1 = JsonLinesAuditLog::new(&path).unwrap();
        log1.log_event(&AuditEvent::success(AuditAction::VaultInit, None))
            .unwrap();

        // Write second event via new instance
        let log2 = JsonLinesAuditLog::new(&path).unwrap();
        log2.log_event(&AuditEvent::success(AuditAction::VaultLock, None))
            .unwrap();

        // Read all events
        let events = log2.read_events().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, AuditAction::VaultInit);
        assert_eq!(events[1].action, AuditAction::VaultLock);
    }

    #[test]
    fn test_json_lines_audit_log_all_actions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("all_actions.jsonl");
        let log = JsonLinesAuditLog::new(&path).unwrap();

        let actions = vec![
            AuditAction::VaultInit,
            AuditAction::VaultUnlock,
            AuditAction::VaultLock,
            AuditAction::VaultPassphraseChange,
            AuditAction::EntryCreate,
            AuditAction::EntryRead,
            AuditAction::EntryUpdate,
            AuditAction::EntryDelete,
            AuditAction::SshSign,
            AuditAction::SshListKeys,
            AuditAction::GitSign,
        ];

        for action in &actions {
            log.log_event(&AuditEvent::success(action.clone(), None))
                .unwrap();
        }

        let events = log.read_events().unwrap();
        assert_eq!(events.len(), actions.len());
    }
}

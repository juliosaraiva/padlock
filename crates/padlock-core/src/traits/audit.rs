//! Audit logger trait for recording vault operations.
//!
//! This trait abstracts audit logging so the core library can record
//! events without depending on a specific log storage mechanism.

use crate::error::Result;
use crate::types::AuditEvent;

/// Abstraction over audit event logging.
///
/// All vault operations (unlock, lock, read, write, delete) are logged
/// through this trait. Implementations may write to files, databases,
/// or in-memory buffers for testing.
pub trait AuditLogger: Send + Sync {
    /// Record an audit event.
    ///
    /// The event is durably persisted by the implementation. No secret
    /// data should be included in audit events -- only resource identifiers,
    /// action types, and timestamps.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be recorded.
    fn log_event(&self, event: &AuditEvent) -> Result<()>;
}

//! Session manager trait for the daemon session cache.
//!
//! Abstracts session lifecycle operations so the core domain
//! does not depend on a specific in-memory implementation.

use crate::crypto::secret_buf::SecretBuf;
use crate::error::Result;
use crate::session::types::{SessionAlgorithm, SessionDuration, SessionInfo, SessionToken};

/// Manages the lifecycle of cached vault sessions.
///
/// Implementations must ensure:
/// - Token comparison is constant-time
/// - Expiry is based on monotonic time
/// - All key material is mlock'd and zeroized on drop
pub trait SessionManager: Send + Sync {
    /// Create a new session, caching the KEK and MACKEY.
    ///
    /// Returns an opaque session token that the client stores to
    /// resume this session later.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::TooManySessions` if the limit is reached.
    /// Returns `SessionError::KeyOperationFailed` if wrapping fails.
    fn create_session(
        &self,
        kek: &SecretBuf,
        mackey: &SecretBuf,
        vault_id: &[u8; 16],
        duration: SessionDuration,
        algorithm: SessionAlgorithm,
    ) -> Result<SessionToken>;

    /// Resume a session, recovering the cached KEK and MACKEY.
    ///
    /// Token lookup uses constant-time comparison. Returns the
    /// unwrapped KEK and MACKEY if the session is valid and not expired.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidSession` if the token is not found.
    /// Returns `SessionError::Expired` if the session has timed out.
    fn resume_session(&self, token: &[u8; 32]) -> Result<(SecretBuf, SecretBuf)>;

    /// Destroy a specific session by its token.
    ///
    /// The SEK and wrapped keys are zeroized and removed.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidSession` if the token is not found.
    fn destroy_session(&self, token: &[u8; 32]) -> Result<()>;

    /// Get public information about a session.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidSession` if the token is not found.
    fn session_status(&self, token: &[u8; 32]) -> Result<SessionInfo>;

    /// Destroy all active sessions.
    ///
    /// Used during daemon shutdown or `padlock lock`.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn destroy_all_sessions(&self) -> Result<()>;

    /// Sweep and remove all expired sessions.
    ///
    /// Returns the number of sessions removed.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn sweep_expired(&self) -> Result<usize>;
}

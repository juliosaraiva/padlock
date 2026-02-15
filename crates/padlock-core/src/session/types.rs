//! Core types for the session caching mechanism.
//!
//! Sessions allow the daemon to cache derived vault keys in memory
//! so that CLI commands can skip passphrase re-entry and Argon2id
//! derivation for a user-configurable duration.

use std::fmt;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::secret_buf::SecretBuf;
use crate::types::Timestamp;

/// Algorithm used for session key wrapping.
///
/// Provides algorithm agility for future post-quantum readiness.
/// The protocol version byte ensures both sides agree on the algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SessionAlgorithm {
    /// X25519 + HKDF-SHA-256 + XChaCha20-Poly1305 (current).
    XChaCha20Poly1305HkdfSha256 = 1,
    // Future: MlKem768XChaCha20Poly1305 = 2,
}

impl SessionAlgorithm {
    /// Parse an algorithm from its wire byte.
    ///
    /// # Errors
    ///
    /// Returns `None` if the byte does not correspond to a known algorithm.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::XChaCha20Poly1305HkdfSha256),
            _ => None,
        }
    }

    /// Encode this algorithm as its wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Predefined session durations.
///
/// Enforced by enum — no arbitrary values accepted.
/// Maximum duration is 24 hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionDuration {
    /// 1 hour (3600 seconds).
    OneHour,
    /// 2 hours (7200 seconds).
    TwoHours,
    /// 4 hours (14400 seconds).
    FourHours,
    /// 8 hours (28800 seconds).
    EightHours,
    /// 12 hours (43200 seconds).
    TwelveHours,
    /// 24 hours (86400 seconds) — maximum.
    TwentyFourHours,
}

impl SessionDuration {
    /// Get the duration in seconds.
    #[must_use]
    pub fn as_secs(&self) -> u64 {
        match self {
            Self::OneHour => 3600,
            Self::TwoHours => 7200,
            Self::FourHours => 14_400,
            Self::EightHours => 28_800,
            Self::TwelveHours => 43_200,
            Self::TwentyFourHours => 86_400,
        }
    }

    /// Get the duration as a `std::time::Duration`.
    #[must_use]
    pub fn as_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.as_secs())
    }

    /// Parse a human-readable duration string (e.g., "1h", "4h", "24h").
    ///
    /// # Errors
    ///
    /// Returns `None` if the string does not match a known duration.
    #[must_use]
    pub fn from_str_label(s: &str) -> Option<Self> {
        match s {
            "1h" => Some(Self::OneHour),
            "2h" => Some(Self::TwoHours),
            "4h" => Some(Self::FourHours),
            "8h" => Some(Self::EightHours),
            "12h" => Some(Self::TwelveHours),
            "24h" => Some(Self::TwentyFourHours),
            _ => None,
        }
    }

    /// Get a human-readable label for this duration.
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::TwoHours => "2h",
            Self::FourHours => "4h",
            Self::EightHours => "8h",
            Self::TwelveHours => "12h",
            Self::TwentyFourHours => "24h",
        }
    }
}

impl fmt::Display for SessionDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_label())
    }
}

/// Opaque session token — 256-bit random, stored in a `SecretBuf`.
///
/// The token is used by clients to resume an existing session.
/// It is stored in mlock'd memory and zeroized on drop.
/// No `Clone` implementation to prevent accidental copies.
pub struct SessionToken {
    bytes: SecretBuf,
}

/// Size of a session token in bytes.
pub const SESSION_TOKEN_SIZE: usize = 32;

impl SessionToken {
    /// Generate a new random session token.
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut buf = SecretBuf::new(SESSION_TOKEN_SIZE);
        rand::rngs::OsRng.fill_bytes(buf.as_mut_slice());
        Self { bytes: buf }
    }

    /// Create a token from existing raw bytes.
    ///
    /// The caller is responsible for ensuring the source bytes are
    /// securely zeroized after this call.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SESSION_TOKEN_SIZE]) -> Self {
        Self {
            bytes: SecretBuf::from_bytes(bytes),
        }
    }

    /// Access the raw token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionToken(***)")
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes // SecretBuf uses constant-time comparison
    }
}

impl Eq for SessionToken {}

/// A cached session stored in the daemon's memory.
///
/// The KEK and MACKEY are wrapped (encrypted) by a random Session
/// Encryption Key (SEK) that is itself stored in mlock'd memory.
/// The session expires based on a monotonic clock to prevent
/// wall-clock manipulation attacks.
pub struct Session {
    /// Unique session identifier.
    pub id: Uuid,
    /// Opaque token used by clients to resume this session.
    pub token: SessionToken,
    /// KEK encrypted by SEK.
    pub wrapped_kek: Vec<u8>,
    /// MACKEY encrypted by SEK.
    pub wrapped_mackey: Vec<u8>,
    /// Nonce used for wrapping KEK.
    pub kek_nonce: [u8; 24],
    /// Nonce used for wrapping MACKEY.
    pub mackey_nonce: [u8; 24],
    /// Session Encryption Key (mlock'd, zeroized on drop).
    pub sek: SecretBuf,
    /// Algorithm used for this session.
    pub algorithm: SessionAlgorithm,
    /// When the session was created (monotonic, immune to clock manipulation).
    pub created_at: Instant,
    /// When the session expires (monotonic).
    pub expires_at: Instant,
    /// Wall-clock creation time (for audit logging only).
    pub created_at_wall: Timestamp,
    /// Number of times this session has been used.
    pub use_count: u64,
    /// Vault identifier this session is bound to.
    pub vault_id: [u8; 16],
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("use_count", &self.use_count)
            .field("vault_id", &hex_encode(&self.vault_id))
            .finish_non_exhaustive()
    }
}

/// Public information about a session (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session identifier.
    pub id: String,
    /// Algorithm used.
    pub algorithm: SessionAlgorithm,
    /// Wall-clock creation time.
    pub created_at: Timestamp,
    /// How many times the session has been used.
    pub use_count: u64,
    /// Vault identifier (hex).
    pub vault_id: String,
    /// Whether the session is still valid.
    pub valid: bool,
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_token_generate_unique() {
        let t1 = SessionToken::generate();
        let t2 = SessionToken::generate();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_session_token_from_bytes_round_trip() {
        let bytes = [42u8; SESSION_TOKEN_SIZE];
        let token = SessionToken::from_bytes(&bytes);
        assert_eq!(token.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_token_constant_time_eq() {
        let bytes = [1u8; SESSION_TOKEN_SIZE];
        let t1 = SessionToken::from_bytes(&bytes);
        let t2 = SessionToken::from_bytes(&bytes);
        assert_eq!(t1, t2);

        let other = [2u8; SESSION_TOKEN_SIZE];
        let t3 = SessionToken::from_bytes(&other);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_session_token_debug_redacted() {
        let token = SessionToken::generate();
        let debug = format!("{token:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains(&format!("{:02x}", token.as_bytes()[0])));
    }

    #[test]
    fn test_session_duration_as_secs() {
        assert_eq!(SessionDuration::OneHour.as_secs(), 3600);
        assert_eq!(SessionDuration::TwentyFourHours.as_secs(), 86_400);
    }

    #[test]
    fn test_session_duration_parse() {
        assert_eq!(
            SessionDuration::from_str_label("1h"),
            Some(SessionDuration::OneHour)
        );
        assert_eq!(
            SessionDuration::from_str_label("24h"),
            Some(SessionDuration::TwentyFourHours)
        );
        assert_eq!(SessionDuration::from_str_label("99h"), None);
    }

    #[test]
    fn test_session_duration_display() {
        assert_eq!(SessionDuration::FourHours.to_string(), "4h");
    }

    #[test]
    fn test_session_algorithm_byte_round_trip() {
        let algo = SessionAlgorithm::XChaCha20Poly1305HkdfSha256;
        assert_eq!(SessionAlgorithm::from_byte(algo.to_byte()), Some(algo));
    }

    #[test]
    fn test_session_algorithm_unknown_byte() {
        assert_eq!(SessionAlgorithm::from_byte(255), None);
    }
}

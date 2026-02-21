//! In-memory session store implementing the `SessionManager` trait.
//!
//! The `SessionStore` holds active sessions in a `HashMap` protected
//! by a `Mutex`. Session tokens are looked up via linear scan with
//! constant-time comparison to prevent timing side-channels.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::crypto::aead::{aead_decrypt, aead_encrypt, generate_nonce, KEY_SIZE, NONCE_SIZE};
use crate::crypto::secret_buf::SecretBuf;
use crate::error::{Error, Result, SessionError};
use crate::session::types::{
    Session, SessionAlgorithm, SessionDuration, SessionInfo, SessionToken, SESSION_TOKEN_SIZE,
};
use crate::traits::session::SessionManager;
use crate::types::Timestamp;

/// Default maximum number of concurrent sessions.
const DEFAULT_MAX_SESSIONS: usize = 3;

/// In-memory session store for the daemon.
///
/// Sessions are stored in mlock'd memory and zeroized on removal.
/// Token lookup uses constant-time comparison. Expiry is based
/// on monotonic `Instant` to prevent wall-clock manipulation.
pub struct SessionStore {
    sessions: Mutex<HashMap<Uuid, Session>>,
    max_sessions: usize,
}

impl SessionStore {
    /// Create a new empty session store with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Create a new session store with a custom maximum session limit.
    #[must_use]
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
        }
    }

    /// Find a session by token using constant-time comparison.
    ///
    /// Returns the session UUID if found, performing comparison against
    /// ALL stored tokens to prevent timing leaks.
    fn find_by_token(sessions: &HashMap<Uuid, Session>, token: &[u8; 32]) -> Option<Uuid> {
        let mut found: Option<Uuid> = None;

        for session in sessions.values() {
            let stored = session.token.as_bytes();
            if stored.len() == SESSION_TOKEN_SIZE {
                let eq: bool = stored.ct_eq(token).into();
                if eq {
                    found = Some(session.id);
                }
            }
        }

        found
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager for SessionStore {
    fn create_session(
        &self,
        kek: &SecretBuf,
        mackey: &SecretBuf,
        vault_id: &[u8; 16],
        duration: SessionDuration,
        idle_timeout: Duration,
        algorithm: SessionAlgorithm,
    ) -> Result<SessionToken> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        // Enforce max sessions limit
        if sessions.len() >= self.max_sessions {
            return Err(Error::Session(SessionError::TooManySessions {
                max: self.max_sessions,
            }));
        }

        // Generate Session Encryption Key (SEK)
        let mut sek = SecretBuf::new(KEY_SIZE);
        rand::rngs::OsRng.fill_bytes(sek.as_mut_slice());

        // Wrap KEK with SEK
        let kek_nonce = generate_nonce();
        let wrapped_kek = aead_encrypt(&sek, &kek_nonce, &[], kek)
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        // Wrap MACKEY with SEK
        let mackey_nonce = generate_nonce();
        let wrapped_mackey = aead_encrypt(&sek, &mackey_nonce, &[], mackey)
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        let now = Instant::now();
        let token = SessionToken::generate();
        let session_id = Uuid::new_v4();

        let session = Session {
            id: session_id,
            token: SessionToken::from_bytes(
                token
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?,
            ),
            wrapped_kek,
            wrapped_mackey,
            kek_nonce: kek_nonce_to_array(kek_nonce),
            mackey_nonce: mackey_nonce_to_array(mackey_nonce),
            sek,
            algorithm,
            created_at: now,
            expires_at: now + duration.as_duration(),
            idle_timeout,
            last_accessed: now,
            created_at_wall: Timestamp::now(),
            use_count: 0,
            vault_id: *vault_id,
        };

        sessions.insert(session_id, session);

        Ok(token)
    }

    fn resume_session(&self, token: &[u8; 32]) -> Result<(SecretBuf, SecretBuf)> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        let session_id = Self::find_by_token(&sessions, token)
            .ok_or(Error::Session(SessionError::InvalidSession))?;

        let session = sessions
            .get_mut(&session_id)
            .ok_or(Error::Session(SessionError::InvalidSession))?;

        let now = Instant::now();

        // Check absolute expiry using monotonic clock
        if now >= session.expires_at {
            sessions.remove(&session_id);
            return Err(Error::Session(SessionError::Expired));
        }

        // Check idle timeout — session expires if unused for too long
        if now.duration_since(session.last_accessed) > session.idle_timeout {
            sessions.remove(&session_id);
            return Err(Error::Session(SessionError::Expired));
        }

        // Unwrap KEK
        let kek_plaintext =
            aead_decrypt(&session.sek, &session.kek_nonce, &[], &session.wrapped_kek)
                .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        // Unwrap MACKEY
        let mackey_plaintext = aead_decrypt(
            &session.sek,
            &session.mackey_nonce,
            &[],
            &session.wrapped_mackey,
        )
        .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        // Reset idle timer on successful use
        session.last_accessed = now;
        session.use_count += 1;

        Ok((
            SecretBuf::from_bytes(&kek_plaintext),
            SecretBuf::from_bytes(&mackey_plaintext),
        ))
    }

    fn destroy_session(&self, token: &[u8; 32]) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        let session_id = Self::find_by_token(&sessions, token)
            .ok_or(Error::Session(SessionError::InvalidSession))?;

        sessions.remove(&session_id);
        Ok(())
    }

    fn session_status(&self, token: &[u8; 32]) -> Result<SessionInfo> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        let session_id = Self::find_by_token(&sessions, token)
            .ok_or(Error::Session(SessionError::InvalidSession))?;

        let session = sessions
            .get(&session_id)
            .ok_or(Error::Session(SessionError::InvalidSession))?;

        let now = Instant::now();
        let absolute_valid = now < session.expires_at;
        let idle_valid = now.duration_since(session.last_accessed) <= session.idle_timeout;
        let valid = absolute_valid && idle_valid;

        Ok(SessionInfo {
            id: session.id.to_string(),
            algorithm: session.algorithm,
            created_at: session.created_at_wall,
            use_count: session.use_count,
            vault_id: hex_encode(&session.vault_id),
            valid,
            idle_timeout_secs: session.idle_timeout.as_secs(),
        })
    }

    fn destroy_all_sessions(&self) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;
        sessions.clear();
        Ok(())
    }

    fn sweep_expired(&self) -> Result<usize> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Session(SessionError::KeyOperationFailed))?;

        let now = Instant::now();
        let before = sessions.len();
        sessions.retain(|_, s| {
            let absolute_valid = now < s.expires_at;
            let idle_valid = now.duration_since(s.last_accessed) <= s.idle_timeout;
            absolute_valid && idle_valid
        });
        Ok(before - sessions.len())
    }
}

/// Convert a `[u8; NONCE_SIZE]` nonce to a fixed-size array.
fn kek_nonce_to_array(nonce: [u8; NONCE_SIZE]) -> [u8; 24] {
    nonce
}

/// Same conversion for mackey nonce.
fn mackey_nonce_to_array(nonce: [u8; NONCE_SIZE]) -> [u8; 24] {
    nonce
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::types::DEFAULT_IDLE_TIMEOUT;

    fn test_kek() -> SecretBuf {
        let mut kek = SecretBuf::new(32);
        rand::rngs::OsRng.fill_bytes(kek.as_mut_slice());
        kek
    }

    fn test_mackey() -> SecretBuf {
        let mut mackey = SecretBuf::new(32);
        rand::rngs::OsRng.fill_bytes(mackey.as_mut_slice());
        mackey
    }

    fn test_vault_id() -> [u8; 16] {
        [0x42; 16]
    }

    #[test]
    fn test_create_session_returns_token() {
        let store = SessionStore::new();
        let token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();
        assert_eq!(token.as_bytes().len(), SESSION_TOKEN_SIZE);
    }

    #[test]
    fn test_resume_session_returns_keys() {
        let store = SessionStore::new();
        let kek = test_kek();
        let mackey = test_mackey();

        let token = store
            .create_session(
                &kek,
                &mackey,
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let token_bytes: [u8; 32] = token.as_bytes().try_into().unwrap();
        let (recovered_kek, recovered_mackey) = store.resume_session(&token_bytes).unwrap();
        assert_eq!(&*recovered_kek, &*kek);
        assert_eq!(&*recovered_mackey, &*mackey);
    }

    #[test]
    fn test_resume_increments_use_count() {
        let store = SessionStore::new();
        let token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let token_bytes: [u8; 32] = token.as_bytes().try_into().unwrap();
        let _ = store.resume_session(&token_bytes).unwrap();
        let _ = store.resume_session(&token_bytes).unwrap();

        let info = store.session_status(&token_bytes).unwrap();
        assert_eq!(info.use_count, 2);
    }

    #[test]
    fn test_wrong_token_rejected() {
        let store = SessionStore::new();
        let _token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let wrong = [0xFFu8; 32];
        let result = store.resume_session(&wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_destroy_session() {
        let store = SessionStore::new();
        let token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let token_bytes: [u8; 32] = token.as_bytes().try_into().unwrap();
        store.destroy_session(&token_bytes).unwrap();

        let result = store.resume_session(&token_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_destroy_all_sessions() {
        let store = SessionStore::new();
        for _ in 0..3 {
            let _ = store
                .create_session(
                    &test_kek(),
                    &test_mackey(),
                    &test_vault_id(),
                    SessionDuration::OneHour,
                    DEFAULT_IDLE_TIMEOUT,
                    SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
                )
                .unwrap();
        }
        store.destroy_all_sessions().unwrap();

        // All tokens should now be invalid
        let result = store.resume_session(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_sessions_enforced() {
        let store = SessionStore::with_max_sessions(2);
        let _ = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();
        let _ = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        // Third should fail
        let result = store.create_session(
            &test_kek(),
            &test_mackey(),
            &test_vault_id(),
            SessionDuration::OneHour,
            DEFAULT_IDLE_TIMEOUT,
            SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
        );
        assert!(matches!(
            result.unwrap_err(),
            Error::Session(SessionError::TooManySessions { max: 2 })
        ));
    }

    #[test]
    fn test_session_token_uniqueness() {
        let store = SessionStore::new();
        let t1 = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();
        let t2 = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();
        assert_ne!(t1.as_bytes(), t2.as_bytes());
    }

    #[test]
    fn test_session_status() {
        let store = SessionStore::new();
        let token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                DEFAULT_IDLE_TIMEOUT,
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let token_bytes: [u8; 32] = token.as_bytes().try_into().unwrap();
        let info = store.session_status(&token_bytes).unwrap();
        assert!(info.valid);
        assert_eq!(info.use_count, 0);
        assert_eq!(info.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT.as_secs());
        assert_eq!(
            info.algorithm,
            SessionAlgorithm::XChaCha20Poly1305HkdfSha256
        );
    }

    #[test]
    fn test_session_idle_timeout_zero_expires_immediately() {
        let store = SessionStore::new();
        let token = store
            .create_session(
                &test_kek(),
                &test_mackey(),
                &test_vault_id(),
                SessionDuration::OneHour,
                Duration::from_secs(0),
                SessionAlgorithm::XChaCha20Poly1305HkdfSha256,
            )
            .unwrap();

        let token_bytes: [u8; 32] = token.as_bytes().try_into().unwrap();
        // With zero idle timeout, any delay causes expiry
        std::thread::sleep(Duration::from_millis(10));
        let result = store.resume_session(&token_bytes);
        assert!(matches!(
            result.unwrap_err(),
            Error::Session(SessionError::Expired)
        ));
    }
}

//! Error types for the Padlock core library.
//!
//! All errors use `thiserror` for ergonomic error handling. Error variants
//! intentionally exclude any secret data to prevent accidental leakage
//! through error messages, logs, or debug output.

use std::io;

/// Top-level error type for all padlock-core operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// A vault operation failed.
    #[error(transparent)]
    Vault(#[from] VaultError),

    /// An entry operation failed.
    #[error(transparent)]
    Entry(#[from] EntryError),

    /// An SSH agent operation failed.
    #[error(transparent)]
    Agent(#[from] AgentError),

    /// A signing operation failed.
    #[error(transparent)]
    Signing(#[from] SigningError),

    /// A session operation failed.
    #[error(transparent)]
    Session(#[from] SessionError),

    /// A generation operation failed.
    #[error(transparent)]
    Generate(#[from] GenerateError),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A configuration error occurred.
    #[error("configuration error: {0}")]
    Config(String),

    /// The requested feature is not supported.
    #[error("not supported: {0}")]
    NotSupported(String),
}

/// Errors from cryptographic operations.
///
/// These errors never contain secret data such as key material,
/// plaintexts, or passphrases.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The provided nonce has an invalid length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        actual: usize,
    },

    /// The provided key has an invalid length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// The provided salt has an invalid length.
    #[error("invalid salt length: expected {expected}, got {actual}")]
    InvalidSaltLength {
        /// Expected salt length in bytes.
        expected: usize,
        /// Actual salt length provided.
        actual: usize,
    },

    /// AEAD authentication failed during decryption.
    #[error("authentication failed: ciphertext may be corrupted or the key is wrong")]
    AuthenticationFailed,

    /// Argon2 key derivation failed.
    #[error("Argon2 key derivation error: {0}")]
    Argon2Error(String),

    /// HKDF key expansion failed.
    #[error("HKDF key expansion error")]
    HkdfError,

    /// Encryption operation failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Memory locking operation failed.
    #[error("memory lock failed: {0}")]
    MemoryLockFailed(String),

    /// The provided data has invalid encoding.
    #[error("invalid encoding: {reason}")]
    InvalidEncoding {
        /// Description of the encoding violation.
        reason: String,
    },
}

/// Errors from vault operations.
///
/// These errors describe vault lifecycle and I/O failures without
/// exposing any secret material.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The vault file was not found at the specified path.
    #[error("vault not found at {path}")]
    NotFound {
        /// The path where the vault was expected.
        path: String,
    },

    /// The vault is currently locked and cannot perform the requested operation.
    #[error("vault is locked")]
    Locked,

    /// The vault file has an invalid format.
    #[error("invalid vault format: {reason}")]
    InvalidFormat {
        /// Description of the format violation.
        reason: String,
    },

    /// The vault data is corrupted.
    #[error("vault data is corrupted")]
    CorruptedData,

    /// The HMAC integrity check failed.
    #[error("vault integrity check failed: HMAC mismatch")]
    HmacMismatch,

    /// The provided passphrase is incorrect.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// The vault is in an invalid state for the requested operation.
    #[error("invalid vault state: {reason}")]
    InvalidState {
        /// Description of why the state is invalid.
        reason: String,
    },

    /// File permission check failed.
    #[error("permission denied: {reason}")]
    PermissionDenied {
        /// Description of the permission failure.
        reason: String,
    },

    /// A vault already exists at the specified path.
    #[error("vault already exists at {path}")]
    AlreadyExists {
        /// The path where the vault already exists.
        path: String,
    },

    /// Atomic write operation failed.
    #[error("atomic write failed: {reason}")]
    AtomicWriteFailed {
        /// Description of the write failure.
        reason: String,
    },

    /// Recovery is not enabled for this vault.
    #[error("recovery is not enabled for this vault")]
    RecoveryNotEnabled,
}

/// Errors from entry operations.
///
/// These errors describe CRUD failures for credential entries.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// The requested entry was not found.
    #[error("entry not found: {id}")]
    NotFound {
        /// The identifier of the missing entry.
        id: String,
    },

    /// An entry with the given name already exists.
    #[error("entry already exists: {name}")]
    AlreadyExists {
        /// The name of the duplicate entry.
        name: String,
    },

    /// Serialization of entry data failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization of entry data failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The entry type is not valid for the requested operation.
    #[error("invalid entry type")]
    InvalidEntryType,
}

/// Errors from SSH agent operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Socket communication error.
    #[error("socket error: {0}")]
    SocketError(String),

    /// SSH agent protocol error.
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// The agent is not running.
    #[error("agent is not running")]
    NotRunning,

    /// The agent has timed out.
    #[error("agent timeout")]
    Timeout,
}

/// Errors from signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Signing operation failed.
    #[error("signing failed: {0}")]
    Failed(String),

    /// The key is not suitable for signing.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Errors from session caching operations.
///
/// These errors describe session lifecycle failures without
/// exposing any secret material such as tokens or keys.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The session token was not found or is invalid.
    #[error("invalid session: token not found")]
    InvalidSession,

    /// The session has expired.
    #[error("session expired")]
    Expired,

    /// Too many concurrent sessions.
    #[error("too many concurrent sessions (max {max})")]
    TooManySessions {
        /// Maximum allowed concurrent sessions.
        max: usize,
    },

    /// The protocol version is not supported.
    #[error("unsupported session protocol version: {version}")]
    UnsupportedVersion {
        /// The unsupported version number.
        version: u8,
    },

    /// The session algorithm is not supported.
    #[error("unsupported session algorithm")]
    UnsupportedAlgorithm,

    /// A key wrap or unwrap operation failed.
    #[error("session key operation failed")]
    KeyOperationFailed,

    /// Transit encryption/decryption failed.
    #[error("session transit encryption error")]
    TransitError,
}

/// Errors from generation operations (passwords, TOTP codes).
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    /// The TOTP secret is not valid base32.
    #[error("invalid TOTP secret: not valid base32")]
    InvalidBase32Secret,

    /// The system clock is unavailable.
    #[error("system clock error")]
    SystemClockError,
}

/// Convenience type alias for Results using the top-level error.
pub type Result<T> = std::result::Result<T, Error>;

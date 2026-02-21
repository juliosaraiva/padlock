//! Entry type definitions for all secret types managed by Padlock.
//!
//! Defines the `Entry` struct and `EntryData` enum covering credentials,
//! SSH keys, TOTP secrets, binary blobs, and netrc entries.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::EntryId;

/// Classification of entry types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryType {
    /// Username/password credential.
    Credential,
    /// SSH private key.
    SSHKey,
    /// Time-based one-time password.
    TOTP,
    /// Arbitrary binary data.
    Binary,
    /// Netrc-format entry.
    Netrc,
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential => write!(f, "credential"),
            Self::SSHKey => write!(f, "ssh-key"),
            Self::TOTP => write!(f, "totp"),
            Self::Binary => write!(f, "binary"),
            Self::Netrc => write!(f, "netrc"),
        }
    }
}

/// SSH key algorithm type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SSHKeyType {
    /// RSA key.
    RSA,
    /// Ed25519 key.
    ED25519,
    /// ECDSA key.
    ECDSA,
}

/// TOTP hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TOTPAlgorithm {
    /// SHA-1 (most common).
    SHA1,
    /// SHA-256.
    SHA256,
    /// SHA-512.
    SHA512,
}

/// Type-specific entry data.
///
/// Each variant contains the fields specific to that secret type.
/// Fields containing sensitive data use `String` which is zeroized
/// when the parent `Entry` is dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum EntryData {
    /// Username/password credential.
    Credential {
        /// Login username.
        username: String,
        /// Login password.
        password: String,
        /// Associated URL.
        #[zeroize(skip)]
        url: Option<String>,
        /// Additional notes.
        notes: Option<String>,
    },
    /// SSH private key.
    SSHKey {
        /// Key algorithm.
        #[zeroize(skip)]
        key_type: SSHKeyType,
        /// PEM-encoded private key.
        private_key: String,
        /// Public key string.
        #[zeroize(skip)]
        public_key: String,
        /// Optional passphrase for the key.
        passphrase: Option<String>,
        /// Key comment.
        #[zeroize(skip)]
        comment: Option<String>,
    },
    /// Time-based one-time password.
    TOTP {
        /// Base32-encoded secret.
        secret: String,
        /// Hash algorithm.
        #[zeroize(skip)]
        algorithm: TOTPAlgorithm,
        /// Number of digits (typically 6 or 8).
        #[zeroize(skip)]
        digits: u32,
        /// Time period in seconds (typically 30).
        #[zeroize(skip)]
        period: u32,
        /// Account name.
        #[zeroize(skip)]
        account_name: String,
        /// Issuer name.
        #[zeroize(skip)]
        issuer: Option<String>,
    },
    /// Arbitrary binary data.
    Binary {
        /// Raw binary content.
        data: Vec<u8>,
        /// MIME content type.
        #[zeroize(skip)]
        content_type: Option<String>,
        /// Original filename.
        #[zeroize(skip)]
        filename: Option<String>,
        /// Description.
        #[zeroize(skip)]
        description: Option<String>,
    },
    /// Netrc-format entry.
    Netrc {
        /// Machine hostname.
        #[zeroize(skip)]
        machine: String,
        /// Login name.
        login: String,
        /// Password.
        password: String,
        /// Optional account.
        #[zeroize(skip)]
        account: Option<String>,
    },
}

impl EntryData {
    /// Get the entry type for this data.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        match self {
            Self::Credential { .. } => EntryType::Credential,
            Self::SSHKey { .. } => EntryType::SSHKey,
            Self::TOTP { .. } => EntryType::TOTP,
            Self::Binary { .. } => EntryType::Binary,
            Self::Netrc { .. } => EntryType::Netrc,
        }
    }
}

/// Additional metadata for an entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryMeta {
    /// Last time this entry was accessed.
    pub last_accessed: Option<i64>,
    /// Number of times this entry has been decrypted.
    pub access_count: u64,
    /// Whether this entry is pinned by the user.
    pub pinned: bool,
}

/// A single vault entry combining metadata with type-specific data.
///
/// The `Entry` struct is the primary unit of data storage in the vault.
/// It contains both the encrypted secret payload and plaintext metadata
/// used for indexing and search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unique entry identifier.
    pub id: EntryId,
    /// Human-readable name.
    pub name: String,
    /// Type-specific secret data.
    pub data: EntryData,
    /// Creation timestamp (Unix seconds).
    pub created_at: i64,
    /// Last modification timestamp (Unix seconds).
    pub modified_at: i64,
    /// Version number (incremented on each modification).
    pub version: u64,
    /// User-assigned tags for categorization.
    pub tags: Vec<String>,
    /// Additional metadata.
    pub meta: EntryMeta,
}

impl Entry {
    /// Create a new entry with the given name and data.
    #[must_use]
    pub fn new(name: String, data: EntryData) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: EntryId::new(),
            name,
            data,
            created_at: now,
            modified_at: now,
            version: 1,
            tags: Vec::new(),
            meta: EntryMeta::default(),
        }
    }

    /// Get the entry type.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        self.data.entry_type()
    }

    /// Increment the version and update the modification timestamp.
    pub fn bump_version(&mut self) {
        self.version += 1;
        self.modified_at = chrono::Utc::now().timestamp();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_credential() -> Entry {
        Entry::new(
            "github".to_string(),
            EntryData::Credential {
                username: "user@example.com".to_string(),
                password: "s3cret!".to_string(),
                url: Some("https://github.com".to_string()),
                notes: None,
            },
        )
    }

    fn sample_ssh_key() -> Entry {
        Entry::new(
            "deploy-key".to_string(),
            EntryData::SSHKey {
                key_type: SSHKeyType::ED25519,
                private_key:
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
                        .to_string(),
                public_key: "ssh-ed25519 AAAA... user@host".to_string(),
                passphrase: None,
                comment: Some("deploy key".to_string()),
            },
        )
    }

    fn sample_totp() -> Entry {
        Entry::new(
            "aws-mfa".to_string(),
            EntryData::TOTP {
                secret: "JBSWY3DPEHPK3PXP".to_string(),
                algorithm: TOTPAlgorithm::SHA1,
                digits: 6,
                period: 30,
                account_name: "user@aws".to_string(),
                issuer: Some("AWS".to_string()),
            },
        )
    }

    #[test]
    fn test_entry_type_credential() {
        let entry = sample_credential();
        assert_eq!(entry.entry_type(), EntryType::Credential);
    }

    #[test]
    fn test_entry_type_ssh_key() {
        let entry = sample_ssh_key();
        assert_eq!(entry.entry_type(), EntryType::SSHKey);
    }

    #[test]
    fn test_entry_type_totp() {
        let entry = sample_totp();
        assert_eq!(entry.entry_type(), EntryType::TOTP);
    }

    #[test]
    fn test_entry_new_sets_version_one() {
        let entry = sample_credential();
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn test_entry_bump_version() {
        let mut entry = sample_credential();
        entry.bump_version();
        assert_eq!(entry.version, 2);
    }

    #[test]
    fn test_entry_id_is_unique() {
        let e1 = sample_credential();
        let e2 = sample_credential();
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn test_entry_type_display() {
        assert_eq!(EntryType::Credential.to_string(), "credential");
        assert_eq!(EntryType::SSHKey.to_string(), "ssh-key");
        assert_eq!(EntryType::TOTP.to_string(), "totp");
        assert_eq!(EntryType::Binary.to_string(), "binary");
        assert_eq!(EntryType::Netrc.to_string(), "netrc");
    }
}

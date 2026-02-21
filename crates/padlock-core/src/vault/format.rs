//! Binary vault file format parsing and serialization.
//!
//! Handles the vault header (1024 bytes), vault index (MessagePack),
//! and entry metadata structures. All multi-byte integers use
//! little-endian byte order.
//!
//! # Vault File Structure
//!
//! ```text
//! [Header (1024 bytes)] [Index (variable)] [Entries (variable)] [HMAC (32 bytes)]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{Error, VaultError};

/// Magic bytes at the start of every vault file.
pub const MAGIC: &[u8; 8] = b"PADLOCK\0";

/// Current vault format version.
pub const VERSION: u8 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 1024;

/// HMAC size appended at the end of the vault file.
pub const VAULT_HMAC_SIZE: usize = 32;

/// Vault file header (fixed 1024 bytes).
///
/// Contains metadata about the vault including the Argon2 salt,
/// KDF parameters, entry counts, and section lengths. All multi-byte
/// integers are stored in little-endian byte order.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Magic bytes: "PADLOCK\0".
    pub magic: [u8; 8],
    /// Protocol version (currently 1).
    pub version: u8,
    /// Flags (bit 0: encrypted).
    pub flags: u8,
    /// Argon2id salt for KDF (16 bytes).
    pub argon2_salt: [u8; 16],
    /// Vault UUID (16 bytes).
    pub vault_uuid: [u8; 16],
    /// Creation timestamp (Unix seconds).
    pub created_timestamp: u64,
    /// Last modification timestamp (Unix seconds).
    pub modified_timestamp: u64,
    /// Number of active (non-deleted) entries.
    pub entry_count: u32,
    /// Number of logically deleted entries.
    pub deleted_entry_count: u32,
    /// Length of the vault index section in bytes.
    pub vault_index_length: u32,
    /// Total length of the entries blob in bytes.
    pub entries_blob_length: u32,
    /// Argon2id memory cost in KiB (0 = use caller-provided fallback).
    pub argon2_memory_kib: u32,
    /// Argon2id time cost / iterations (0 = use caller-provided fallback).
    pub argon2_time_cost: u32,
    /// Argon2id parallelism / threads (0 = use caller-provided fallback).
    pub argon2_parallelism: u32,
    /// Recovery HKDF salt (16 bytes, all zeros if recovery not enabled).
    pub recovery_salt: [u8; 16],
    /// Recovery XChaCha20-Poly1305 nonce (24 bytes).
    pub recovery_nonce: [u8; 24],
    /// Recovery blob: KEK||MACKEY encrypted under recovery wrapping key (80 bytes).
    pub recovery_blob: [u8; 80],
}

impl VaultHeader {
    /// Create a new vault header with the given parameters.
    ///
    /// KDF parameters are stored in the header so the vault is self-describing
    /// and can always be opened with the correct derivation settings.
    #[must_use]
    pub fn new(
        argon2_salt: [u8; 16],
        vault_uuid: [u8; 16],
        now: u64,
        argon2_memory_kib: u32,
        argon2_time_cost: u32,
        argon2_parallelism: u32,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            flags: 0x01, // encrypted
            argon2_salt,
            vault_uuid,
            created_timestamp: now,
            modified_timestamp: now,
            entry_count: 0,
            deleted_entry_count: 0,
            vault_index_length: 0,
            entries_blob_length: 0,
            argon2_memory_kib,
            argon2_time_cost,
            argon2_parallelism,
            recovery_salt: [0u8; 16],
            recovery_nonce: [0u8; 24],
            recovery_blob: [0u8; 80],
        }
    }

    /// Validate that the magic bytes are correct.
    #[must_use]
    pub fn is_magic_valid(&self) -> bool {
        self.magic == *MAGIC
    }

    /// Validate that the version is supported.
    #[must_use]
    pub fn is_version_valid(&self) -> bool {
        self.version == VERSION
    }

    /// Check whether recovery is enabled (flags bit 1).
    #[must_use]
    pub fn recovery_enabled(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Set or clear the recovery enabled flag (bit 1).
    pub fn set_recovery_enabled(&mut self, enabled: bool) {
        if enabled {
            self.flags |= 0x02;
        } else {
            self.flags &= !0x02;
        }
    }
}

/// Serialize a vault header to exactly 1024 bytes.
///
/// # Layout (little-endian)
///
/// ```text
/// Offset  Size  Field
/// 0       8     MAGIC
/// 8       1     VERSION
/// 9       1     FLAGS
/// 10      2     RESERVED1
/// 12      16    ARGON2_SALT
/// 28      16    VAULT_UUID
/// 44      8     CREATED_TIMESTAMP
/// 52      8     MODIFIED_TIMESTAMP
/// 60      4     ENTRY_COUNT
/// 64      4     DELETED_ENTRY_COUNT
/// 68      4     VAULT_INDEX_LENGTH
/// 72      4     ENTRIES_BLOB_LENGTH
/// 76      4     ARGON2_MEMORY_KIB (0 = use fallback)
/// 80      4     ARGON2_TIME_COST  (0 = use fallback)
/// 84      4     ARGON2_PARALLELISM (0 = use fallback)
/// 88      16    RECOVERY_SALT (zeros if recovery disabled)
/// 104     24    RECOVERY_NONCE
/// 128     80    RECOVERY_BLOB (KEK||MACKEY encrypted, + 16 auth tag)
/// 208     816   RESERVED (zeros)
/// ```
#[must_use]
pub fn serialize_header(header: &VaultHeader) -> [u8; HEADER_SIZE] {
    let mut buf = [0u8; HEADER_SIZE];

    buf[0..8].copy_from_slice(&header.magic);
    buf[8] = header.version;
    buf[9] = header.flags;
    // bytes 10-11: reserved (already zero)
    buf[12..28].copy_from_slice(&header.argon2_salt);
    buf[28..44].copy_from_slice(&header.vault_uuid);
    buf[44..52].copy_from_slice(&header.created_timestamp.to_le_bytes());
    buf[52..60].copy_from_slice(&header.modified_timestamp.to_le_bytes());
    buf[60..64].copy_from_slice(&header.entry_count.to_le_bytes());
    buf[64..68].copy_from_slice(&header.deleted_entry_count.to_le_bytes());
    buf[68..72].copy_from_slice(&header.vault_index_length.to_le_bytes());
    buf[72..76].copy_from_slice(&header.entries_blob_length.to_le_bytes());
    buf[76..80].copy_from_slice(&header.argon2_memory_kib.to_le_bytes());
    buf[80..84].copy_from_slice(&header.argon2_time_cost.to_le_bytes());
    buf[84..88].copy_from_slice(&header.argon2_parallelism.to_le_bytes());
    buf[88..104].copy_from_slice(&header.recovery_salt);
    buf[104..128].copy_from_slice(&header.recovery_nonce);
    buf[128..208].copy_from_slice(&header.recovery_blob);
    // bytes 208-1023: reserved (already zero)

    buf
}

/// Parse a vault header from a byte slice.
///
/// The input must be at least 1024 bytes.
///
/// # Errors
///
/// Returns `VaultError::InvalidFormat` if the data is too short,
/// the magic bytes are wrong, or the version is unsupported.
pub fn parse_header(data: &[u8]) -> crate::error::Result<VaultHeader> {
    if data.len() < HEADER_SIZE {
        return Err(Error::Vault(VaultError::InvalidFormat {
            reason: format!(
                "header too short: expected {} bytes, got {}",
                HEADER_SIZE,
                data.len()
            ),
        }));
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&data[0..8]);

    let version = data[8];
    let flags = data[9];

    let mut argon2_salt = [0u8; 16];
    argon2_salt.copy_from_slice(&data[12..28]);

    let mut vault_uuid = [0u8; 16];
    vault_uuid.copy_from_slice(&data[28..44]);

    let created_timestamp = u64::from_le_bytes(data[44..52].try_into().unwrap_or([0u8; 8]));
    let modified_timestamp = u64::from_le_bytes(data[52..60].try_into().unwrap_or([0u8; 8]));
    let entry_count = u32::from_le_bytes(data[60..64].try_into().unwrap_or([0u8; 4]));
    let deleted_entry_count = u32::from_le_bytes(data[64..68].try_into().unwrap_or([0u8; 4]));
    let vault_index_length = u32::from_le_bytes(data[68..72].try_into().unwrap_or([0u8; 4]));
    let entries_blob_length = u32::from_le_bytes(data[72..76].try_into().unwrap_or([0u8; 4]));
    let argon2_memory_kib = u32::from_le_bytes(data[76..80].try_into().unwrap_or([0u8; 4]));
    let argon2_time_cost = u32::from_le_bytes(data[80..84].try_into().unwrap_or([0u8; 4]));
    let argon2_parallelism = u32::from_le_bytes(data[84..88].try_into().unwrap_or([0u8; 4]));

    let mut recovery_salt = [0u8; 16];
    recovery_salt.copy_from_slice(&data[88..104]);

    let mut recovery_nonce = [0u8; 24];
    recovery_nonce.copy_from_slice(&data[104..128]);

    let mut recovery_blob = [0u8; 80];
    recovery_blob.copy_from_slice(&data[128..208]);

    let header = VaultHeader {
        magic,
        version,
        flags,
        argon2_salt,
        vault_uuid,
        created_timestamp,
        modified_timestamp,
        entry_count,
        deleted_entry_count,
        vault_index_length,
        entries_blob_length,
        argon2_memory_kib,
        argon2_time_cost,
        argon2_parallelism,
        recovery_salt,
        recovery_nonce,
        recovery_blob,
    };

    if !header.is_magic_valid() {
        return Err(Error::Vault(VaultError::InvalidFormat {
            reason: "invalid magic bytes".to_string(),
        }));
    }

    if !header.is_version_valid() {
        return Err(Error::Vault(VaultError::InvalidFormat {
            reason: format!("unsupported version: {}", header.version),
        }));
    }

    Ok(header)
}

/// Metadata for a single entry in the vault index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Entry UUID (16 bytes).
    pub uuid: [u8; 16],
    /// Byte offset of this entry in the entries blob.
    pub entry_offset: u64,
    /// Length of this entry's data in bytes.
    pub entry_length: u32,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last modification timestamp (Unix seconds).
    pub modified_at: u64,
    /// Whether this entry has been logically deleted.
    pub deleted: bool,
    /// Entry title/name (for index lookups without decryption).
    pub title: String,
    /// Denormalized tags for index-level search without decryption.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Vault index mapping entry UUIDs to their metadata.
///
/// The index is serialized as MessagePack and stored between the
/// header and the entries blob in the vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultIndex {
    /// Map from entry UUID to entry metadata.
    pub entries: HashMap<[u8; 16], EntryMetadata>,
    /// Reverse index from lowercase tag to entry UUIDs.
    /// Enables O(1) tag lookup instead of O(n) full-decrypt scan.
    #[serde(default)]
    pub tag_index: HashMap<String, Vec<[u8; 16]>>,
}

impl VaultIndex {
    /// Create a new empty vault index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            tag_index: HashMap::new(),
        }
    }

    /// Add an entry's tags to the tag index.
    ///
    /// Duplicate UUIDs for the same tag are silently ignored, so calling this
    /// method multiple times with the same `uuid` / `tags` combination is
    /// idempotent and `search_by_tag` will never return duplicate entries.
    pub fn add_tags(&mut self, uuid: [u8; 16], tags: &[String]) {
        for tag in tags {
            let key = tag.to_lowercase();
            let uuids = self.tag_index.entry(key).or_default();
            if !uuids.contains(&uuid) {
                uuids.push(uuid);
            }
        }
    }

    /// Remove an entry's tags from the tag index.
    pub fn remove_tags(&mut self, uuid: &[u8; 16], tags: &[String]) {
        for tag in tags {
            let key = tag.to_lowercase();
            if let Some(uuids) = self.tag_index.get_mut(&key) {
                uuids.retain(|u| u != uuid);
                if uuids.is_empty() {
                    self.tag_index.remove(&key);
                }
            }
        }
    }

    /// Get the number of active (non-deleted) entries.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.entries.values().filter(|e| !e.deleted).count()
    }

    /// Get the number of deleted entries.
    #[must_use]
    pub fn deleted_count(&self) -> usize {
        self.entries.values().filter(|e| e.deleted).count()
    }
}

impl Default for VaultIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize a vault index to MessagePack bytes.
///
/// # Errors
///
/// Returns `VaultError::InvalidFormat` if serialization fails.
pub fn serialize_index(index: &VaultIndex) -> crate::error::Result<Vec<u8>> {
    rmp_serde::to_vec(index).map_err(|e| {
        Error::Vault(VaultError::InvalidFormat {
            reason: format!("index serialization failed: {e}"),
        })
    })
}

/// Deserialize a vault index from MessagePack bytes.
///
/// # Errors
///
/// Returns `VaultError::InvalidFormat` if deserialization fails.
pub fn deserialize_index(data: &[u8]) -> crate::error::Result<VaultIndex> {
    rmp_serde::from_slice(data).map_err(|e| {
        Error::Vault(VaultError::InvalidFormat {
            reason: format!("index deserialization failed: {e}"),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> VaultHeader {
        VaultHeader::new([0xAA; 16], [0xBB; 16], 1_700_000_000, 262_144, 3, 4)
    }

    #[test]
    fn test_header_serialize_deserialize_round_trip() {
        let header = test_header();
        let bytes = serialize_header(&header);
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.magic, header.magic);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.argon2_salt, header.argon2_salt);
        assert_eq!(parsed.vault_uuid, header.vault_uuid);
        assert_eq!(parsed.created_timestamp, header.created_timestamp);
        assert_eq!(parsed.modified_timestamp, header.modified_timestamp);
        assert_eq!(parsed.entry_count, header.entry_count);
        assert_eq!(parsed.deleted_entry_count, header.deleted_entry_count);
        assert_eq!(parsed.argon2_memory_kib, header.argon2_memory_kib);
        assert_eq!(parsed.argon2_time_cost, header.argon2_time_cost);
        assert_eq!(parsed.argon2_parallelism, header.argon2_parallelism);
    }

    #[test]
    fn test_header_is_exactly_1024_bytes() {
        let header = test_header();
        let bytes = serialize_header(&header);
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn test_header_magic_at_offset_zero() {
        let header = test_header();
        let bytes = serialize_header(&header);
        assert_eq!(&bytes[0..8], MAGIC);
    }

    #[test]
    fn test_header_invalid_magic_rejected() {
        let mut bytes = serialize_header(&test_header());
        bytes[0] = 0xFF; // Corrupt magic
        let result = parse_header(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_invalid_version_rejected() {
        let mut header = test_header();
        header.version = 99;
        // Manually construct bytes with bad version
        let mut bytes = serialize_header(&header);
        bytes[8] = 99;
        // Magic is correct but version should fail
        // Need to re-set magic since serialize uses header.magic
        bytes[0..8].copy_from_slice(MAGIC);
        let result = parse_header(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_too_short_rejected() {
        let result = parse_header(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_with_entry_counts() {
        let mut header = test_header();
        header.entry_count = 42;
        header.deleted_entry_count = 5;
        header.vault_index_length = 1234;
        header.entries_blob_length = 56789;
        let bytes = serialize_header(&header);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.entry_count, 42);
        assert_eq!(parsed.deleted_entry_count, 5);
        assert_eq!(parsed.vault_index_length, 1234);
        assert_eq!(parsed.entries_blob_length, 56789);
    }

    #[test]
    fn test_header_kdf_params_round_trip() {
        let header = VaultHeader::new([0xCC; 16], [0xDD; 16], 1_700_000_000, 262_144, 3, 4);
        let bytes = serialize_header(&header);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.argon2_memory_kib, 262_144);
        assert_eq!(parsed.argon2_time_cost, 3);
        assert_eq!(parsed.argon2_parallelism, 4);
    }

    #[test]
    fn test_header_kdf_params_zero_for_legacy_vaults() {
        // Simulate a legacy vault with zeros at offsets 76-87
        let header = VaultHeader::new([0xCC; 16], [0xDD; 16], 1_700_000_000, 0, 0, 0);
        let bytes = serialize_header(&header);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.argon2_memory_kib, 0);
        assert_eq!(parsed.argon2_time_cost, 0);
        assert_eq!(parsed.argon2_parallelism, 0);
    }

    #[test]
    fn test_index_empty_round_trip() {
        let index = VaultIndex::new();
        let bytes = serialize_index(&index).unwrap();
        let deserialized = deserialize_index(&bytes).unwrap();
        assert_eq!(deserialized.entries.len(), 0);
    }

    #[test]
    fn test_index_with_entries_round_trip() {
        let mut index = VaultIndex::new();
        let uuid = [0x11; 16];
        index.entries.insert(
            uuid,
            EntryMetadata {
                uuid,
                entry_offset: 0,
                entry_length: 100,
                created_at: 1_700_000_000,
                modified_at: 1_700_000_001,
                deleted: false,
                title: "test-entry".to_string(),
                tags: vec![],
            },
        );
        let bytes = serialize_index(&index).unwrap();
        let deserialized = deserialize_index(&bytes).unwrap();
        assert_eq!(deserialized.entries.len(), 1);
        let entry = deserialized.entries.get(&uuid).unwrap();
        assert_eq!(entry.title, "test-entry");
        assert_eq!(entry.entry_length, 100);
    }

    #[test]
    fn test_index_active_and_deleted_counts() {
        let mut index = VaultIndex::new();
        index.entries.insert(
            [1; 16],
            EntryMetadata {
                uuid: [1; 16],
                entry_offset: 0,
                entry_length: 50,
                created_at: 0,
                modified_at: 0,
                deleted: false,
                title: "active".to_string(),
                tags: vec![],
            },
        );
        index.entries.insert(
            [2; 16],
            EntryMetadata {
                uuid: [2; 16],
                entry_offset: 50,
                entry_length: 50,
                created_at: 0,
                modified_at: 0,
                deleted: true,
                title: "deleted".to_string(),
                tags: vec![],
            },
        );
        assert_eq!(index.active_count(), 1);
        assert_eq!(index.deleted_count(), 1);
    }

    #[test]
    fn test_header_magic_valid() {
        let header = test_header();
        assert!(header.is_magic_valid());
    }

    #[test]
    fn test_header_version_valid() {
        let header = test_header();
        assert!(header.is_version_valid());
    }

    #[test]
    fn test_header_recovery_fields_round_trip() {
        let mut header = test_header();
        header.recovery_salt = [0x11; 16];
        header.recovery_nonce = [0x22; 24];
        header.recovery_blob = [0x33; 80];
        header.set_recovery_enabled(true);

        let bytes = serialize_header(&header);
        let parsed = parse_header(&bytes).unwrap();

        assert_eq!(parsed.recovery_salt, [0x11; 16]);
        assert_eq!(parsed.recovery_nonce, [0x22; 24]);
        assert_eq!(parsed.recovery_blob, [0x33; 80]);
        assert!(parsed.recovery_enabled());
    }

    #[test]
    fn test_header_recovery_disabled_by_default() {
        let header = test_header();
        assert!(!header.recovery_enabled());
        assert_eq!(header.recovery_salt, [0u8; 16]);
        assert_eq!(header.recovery_nonce, [0u8; 24]);
        assert_eq!(header.recovery_blob, [0u8; 80]);
    }

    #[test]
    fn test_header_backward_compat_zeros_means_no_recovery() {
        // A vault with zeros at offsets 88-207 should report recovery disabled
        let header = test_header();
        let bytes = serialize_header(&header);
        let parsed = parse_header(&bytes).unwrap();
        assert!(!parsed.recovery_enabled());
    }

    #[test]
    fn test_add_tags_no_duplicates_when_called_twice() {
        let mut index = VaultIndex::new();
        let uuid = [0xAA; 16];
        let tags = vec!["rust".to_string(), "security".to_string()];
        index.add_tags(uuid, &tags);
        // Calling a second time with the same uuid/tags must not produce duplicates.
        index.add_tags(uuid, &tags);
        for tag in &tags {
            let uuids = index.tag_index.get(tag).unwrap();
            assert_eq!(uuids.len(), 1, "tag '{tag}' should contain exactly one UUID");
        }
    }

    #[test]
    fn test_add_tags_deduplicates_within_entry_tags() {
        let mut index = VaultIndex::new();
        let uuid = [0xBB; 16];
        // Entry whose tag list already contains a duplicate.
        let tags = vec!["rust".to_string(), "rust".to_string()];
        index.add_tags(uuid, &tags);
        let uuids = index.tag_index.get("rust").unwrap();
        assert_eq!(uuids.len(), 1, "duplicate tag in input must not produce duplicate UUID");
    }

    #[test]
    fn test_add_tags_different_uuids_same_tag() {
        let mut index = VaultIndex::new();
        let uuid1 = [0x01; 16];
        let uuid2 = [0x02; 16];
        let tags = vec!["rust".to_string()];
        index.add_tags(uuid1, &tags);
        index.add_tags(uuid2, &tags);
        let uuids = index.tag_index.get("rust").unwrap();
        assert_eq!(uuids.len(), 2, "two distinct UUIDs for the same tag should both be present");
    }

    #[test]
    fn test_header_recovery_flag_set_clear() {
        let mut header = test_header();
        assert!(!header.recovery_enabled());

        header.set_recovery_enabled(true);
        assert!(header.recovery_enabled());
        // Encrypted flag (bit 0) should still be set
        assert_eq!(header.flags & 0x01, 0x01);

        header.set_recovery_enabled(false);
        assert!(!header.recovery_enabled());
        assert_eq!(header.flags & 0x01, 0x01);
    }
}

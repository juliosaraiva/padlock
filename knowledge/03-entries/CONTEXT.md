# Entry Management Context — Padlock Entries Module

## Overview

The entries module provides CRUD (Create, Read, Update, Delete) operations for all secret types managed by Padlock. Entries are the fundamental unit of data storage in the vault, where each entry represents a single credential, SSH key, certificate, or other secret material.

## Entry Types

All entries are classified into six types via the `EntryType` enum:

```rust
pub enum EntryType {
    Credential,   // Username/password pairs with optional metadata
    SSHKey,       // SSH private keys with optional passphrase
    Certificate,  // X.509 certificates and keys
    TOTP,         // Time-based one-time passwords
    Binary,       // Arbitrary binary data blobs
    Netrc,        // .netrc format entries for curl/wget compatibility
}
```

Each type has specialized fields in the `EntryData` enum while maintaining a common interface.

## EntryData Enum

The complete `EntryData` enum encompasses all field variants across all secret types:

```rust
pub enum EntryData {
    Credential {
        username: String,
        password: ZeroizedString,  // Must derive Zeroize + ZeroizeOnDrop
        url: Option<String>,
        notes: Option<ZeroizedString>,
        tags: Vec<String>,
        custom_fields: Vec<(String, ZeroizedString)>,
        expires_at: Option<i64>,  // Unix timestamp, optional expiration
    },
    SSHKey {
        key_type: SSHKeyType,  // RSA, ED25519, ECDSA, etc.
        private_key: ZeroizedString,  // PEM format
        public_key: String,
        passphrase: Option<ZeroizedString>,
        comment: Option<String>,
        added_at: i64,
    },
    Certificate {
        certificate: String,  // PEM-encoded X.509
        private_key: Option<ZeroizedString>,
        chain: Vec<String>,  // Intermediate/root certificates
        common_name: String,
        not_before: i64,  // Unix timestamp
        not_after: i64,   // Unix timestamp
        subject_alt_names: Vec<String>,
    },
    TOTP {
        secret: ZeroizedString,  // Base32-encoded secret
        algorithm: TOTPAlgorithm,  // SHA1, SHA256, SHA512
        digits: u32,  // 6, 8, typically
        period: u32,  // Seconds, typically 30
        account_name: String,
        issuer: Option<String>,
    },
    Binary {
        data: ZeroizedVec<u8>,  // Raw binary blob
        content_type: Option<String>,  // MIME type
        filename: Option<String>,
        description: Option<ZeroizedString>,
    },
    Netrc {
        machine: String,
        login: String,
        password: ZeroizedString,
        account: Option<String>,
        macdef: Option<Vec<String>>,  // Macro definitions
    },
}

pub enum SSHKeyType {
    RSA,
    ED25519,
    ECDSA,
    DSA,
}

pub enum TOTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}
```

Each `EntryData` variant contains only the fields relevant to that secret type. Fields containing passwords, keys, or other sensitive material must be wrapped in `ZeroizedString` or `ZeroizedVec<T>`.

## Common Entry Metadata

All entries share common metadata regardless of type:

```rust
pub struct Entry {
    pub id: EntryId,                 // UUID v4
    pub entry_data: EntryData,       // Type-specific payload
    pub name: String,                // Human-readable name (encrypted in storage)
    pub created_at: i64,             // Unix timestamp
    pub modified_at: i64,            // Unix timestamp
    pub version: u64,                // Incremented on every modification
    pub tags: Vec<String>,           // Optional categorization
    pub metadata: EntryMetadata,     // See below
}

pub struct EntryMetadata {
    pub last_accessed: Option<i64>,  // Track read access
    pub access_count: u64,           // Number of times decrypted
    pub pinned: bool,                // User-pinned important entries
    pub color: Option<String>,       // UI hint (hex color code)
}
```

## Serialization with MessagePack

Entries are serialized using MessagePack via the `rmp-serde` crate. All types must derive both `Serialize` and `Deserialize`:

```rust
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    // fields...
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizedString(String);

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizedVec<T>(Vec<T>);
```

MessagePack is chosen for:
- Compact binary format (smaller encrypted payload)
- Speed (faster serialization than JSON)
- Deterministic encoding (important for HMAC of serialized data)
- Language agnostic (supports future client libraries)

## Zeroize Integration

All secret fields use zeroized types to ensure in-memory secrets are wiped on drop:

- `ZeroizedString`: A String wrapper that zeros memory on drop
- `ZeroizedVec<u8>`: A Vec wrapper that zeros memory on drop
- All types containing secrets must derive `Zeroize` and `ZeroizeOnDrop`
- Sensitive fields: passwords, private keys, secrets, PII in custom fields, passphrases

Example:

```rust
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizedString {
    #[serde(rename = "data")]
    data: String,
}

impl Drop for ZeroizedString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
```

When an `Entry` is dropped or moved out of scope, all contained zeroized fields automatically wipe their memory.

## Entry Index

The vault maintains an encrypted index as a compact array of index entries. Rather than decrypting all entries to perform lookups, the index allows O(1) access:

```rust
pub struct IndexEntry {
    pub id: EntryId,              // UUID of the entry
    pub offset: u64,              // Byte offset in the entries file
    pub length: u64,              // Byte length of encrypted entry
    pub entry_type: EntryType,    // Type discriminant (enables filtering)
    pub name_hash: [u8; 32],      // HMAC-SHA256 of plaintext name
}

pub struct VaultIndex {
    pub entries: Vec<IndexEntry>,
    pub created_at: i64,
    pub last_modified: i64,
}
```

The index is encrypted as a single unit (separate from entry data) and stored in the vault metadata section. Index updates are atomic: the entire index is re-encrypted on any change.

## Name Hash Lookup

To search for entries by name without decrypting all data, the index uses HMAC-based name hashing:

```rust
fn compute_name_hash(kek: &[u8], name: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(kek)
        .expect("HMAC can take key of any size");
    mac.update(name.as_bytes());
    let result = mac.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(result.as_bytes());
    hash
}
```

Search by name:
1. Compute HMAC(KEK, search_term)
2. Compare against name_hash in index entries
3. Retrieve matching entries by offset/length
4. Decrypt and return full entries

This avoids decrypting the full index but reveals entry count and timing of searches (acceptable threat model).

## Entry Versioning

Every entry maintains a version counter that increments with each modification:

```rust
pub struct Entry {
    pub version: u64,  // Starts at 1, increments on every write
    // ...
}
```

Operations that increment version:
- Modify entry_data (any field change)
- Modify name, tags, or metadata
- Explicitly trigger a modification (even if no fields change)

Version is used for:
- Conflict detection in multi-device sync
- History chain integrity verification
- Cache invalidation in CLI tools
- Optimistic locking in concurrent access

## Entry History

Optionally, entries can maintain a history of previous versions. This is opt-in per entry:

```rust
pub struct HistoryEntry {
    pub version: u64,              // Version number of this snapshot
    pub snapshot: Vec<u8>,         // Encrypted serialized EntryData
    pub modified_at: i64,
    pub change_summary: Option<String>,  // Optional: "password changed", "URL updated"
}

pub struct EntryHistory {
    pub enabled: bool,             // Opt-in flag
    pub entries: VecDeque<HistoryEntry>,  // FIFO queue
    pub max_depth: usize,          // Hard limit (5 by default)
}
```

History constraints:
- Maximum depth of 5 previous versions per entry (oldest dropped when exceeded)
- Each history entry is individually encrypted with DEK
- History is only decrypted when explicitly requested
- Compact storage: serialized as MessagePack array of snapshots
- Rollback to previous version creates new version, doesn't revert version counter

History use cases:
- Password reuse detection (ensure new password differs from last N versions)
- Audit trail (who changed what, when)
- Accidental modification recovery
- Forensics and compliance

## Module Structure

The entries module is organized as:

```
entries/
├── mod.rs              # Public API, re-exports
├── types.rs            # EntryType, EntryData, Entry structs
├── crud.rs             # Create, Read, Update, Delete operations
├── search.rs           # Name/tag/type filtering, name hash lookup
├── history.rs          # History snapshots, rollback, cleanup
└── serialize.rs        # MessagePack serialization, zeroize integration
```

### mod.rs
Public API surface:
- Exports all types
- Provides high-level `EntryStore` trait
- Re-exports common functions

### types.rs
Type definitions:
- `Entry`, `EntryData`, `EntryType`, `EntryMetadata`
- `ZeroizedString`, `ZeroizedVec<T>` wrappers
- Trait impls: `Clone`, `Eq`, `Hash` (careful: cloning creates secrets)
- Validation logic: `Entry::validate()` checks for required fields

### crud.rs
Storage operations:
- `fn create_entry(vault: &mut Vault, entry_data: EntryData, name: String) -> Result<Entry>`
- `fn read_entry(vault: &Vault, id: EntryId) -> Result<Entry>`
- `fn update_entry(vault: &mut Vault, id: EntryId, entry_data: EntryData) -> Result<Entry>`
- `fn delete_entry(vault: &mut Vault, id: EntryId) -> Result<()>`
- Internals: disk I/O, index updates, version increments

### search.rs
Query operations:
- `fn search_by_name(vault: &Vault, name: &str) -> Result<Vec<Entry>>`
- `fn search_by_tag(vault: &Vault, tag: &str) -> Result<Vec<Entry>>`
- `fn search_by_type(vault: &Vault, entry_type: EntryType) -> Result<Vec<Entry>>`
- `fn list_all(vault: &Vault) -> Result<Vec<Entry>>`
- Name hash lookup internals

### history.rs
Version tracking:
- `fn enable_history(vault: &mut Vault, id: EntryId) -> Result<()>`
- `fn get_history(vault: &Vault, id: EntryId) -> Result<Vec<HistoryEntry>>`
- `fn rollback_to_version(vault: &mut Vault, id: EntryId, version: u64) -> Result<()>`
- Automatic cleanup when history exceeds max_depth

### serialize.rs
Encoding/decoding:
- `fn serialize_entry(entry: &Entry) -> Result<Vec<u8>>`
- `fn deserialize_entry(bytes: &[u8]) -> Result<Entry>`
- MessagePack round-trip integration
- Zeroize integration for temporary buffers

## Dependencies

**On crypto module:**
- DEK (Data Encryption Key) derivation
- Encryption/decryption of entry payloads
- HMAC operations for name hash
- Key stretching for KEK (Key Encryption Key)

**On vault module:**
- Vault structure and metadata storage
- Storage backend abstraction (file I/O)
- Lock/unlock state management
- Index persistence

**On external crates:**
- `rmp-serde`: MessagePack serialization
- `zeroize`: Memory wiping
- `uuid`: Entry IDs (UUIDs)
- `serde`: Serialization traits
- `sha2`, `hmac`: Name hash computation

## Testing Strategy

### CRUD Round-Trips
For each `EntryType` variant:
- Create entry with all fields populated
- Serialize to MessagePack
- Deserialize back
- Assert all fields match original
- Verify zeroized fields are wiped after drop

Example test structure:
```rust
#[test]
fn test_credential_roundtrip() {
    let entry = Entry {
        entry_data: EntryData::Credential { /* ... */ },
        // ...
    };
    let serialized = serialize_entry(&entry).unwrap();
    let deserialized = deserialize_entry(&serialized).unwrap();
    assert_eq!(entry, deserialized);
}
```

### Search Accuracy
- Verify name_hash collisions are negligible (> 10k entries)
- Test case-sensitive and case-insensitive search behavior
- Confirm tag search returns all tagged entries
- Validate type filtering returns only matching types
- Test partial name matches (prefix/contains logic)

### History Depth Limits
- Create entry with history enabled
- Perform 10 modifications
- Verify history contains exactly 5 most recent versions
- Confirm oldest version is dropped
- Test rollback to all reachable versions

### MessagePack Fuzzing
- Fuzz serialize/deserialize with random EntryData
- Corrupt serialized bytes and verify deserialization fails gracefully
- Test malformed MessagePack streams
- Verify size estimates (serialized size matches actual)

### Zeroize Verification
- Create entries with secrets
- Track memory patterns before/after drop
- Use `volatile_zeroize` checks to confirm memory is actually cleared
- Test with both stack and heap-allocated secrets

### Edge Cases
- Empty strings, None values in optional fields
- Maximum field sizes (entry names, notes, custom fields)
- Very long tag lists
- Concurrent modification detection via version counter
- Invalid UTF-8 handling in names

### Integration Tests
- Create, read, update, delete in sequence
- Verify index consistency after operations
- Test search after bulk create/delete
- Validate version numbers increment correctly
- Confirm entry deletion removes index entry

## Performance Considerations

- Index lookup: O(n) linear scan of index entries (typically < 10K entries)
- Name hash lookup: O(1) hash table possible future optimization
- Serialization: < 5ms for typical entries
- Decrypt-on-read pattern: entries only decrypted when accessed
- Copy-on-write for history: snapshots are full MessagePack copies
- Zeroize overhead: minimal (atomic memory ops, no performance cost)

## Security Considerations

- All secret fields use zeroized types (no plaintext in memory after drop)
- Name hashes prevent plaintext name leakage in index
- Entry IDs are UUIDs (not sequential, prevents enumeration)
- Modified timestamps could leak update patterns (acceptable)
- Version counter allows conflict detection but reveals modification frequency
- History snapshots are separately encrypted (no plaintext concatenation)
- No compression (would leak entropy via size patterns)

## Future Extensions

Possible enhancements:
- Deduplicated history snapshots (store diffs instead of full copies)
- Pluggable serialization backends (JSON, CBOR)
- Entry encryption with per-entry DEKs (stronger isolation)
- Searchable encryption for name lookups (advanced, cryptographic)
- Hardware key integration (Yubikey, TPM)

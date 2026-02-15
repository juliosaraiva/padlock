# Padlock Vault File Format and Storage Context

## Purpose

The vault module is responsible for reading and writing the encrypted vault file, managing vault lifecycle (Created, Locked, Unlocked states), and supporting all vault operations. It provides the interface between high-level credential management and the low-level encrypted storage format.

### Vault Operations Supported
- **Init**: Create a new vault file
- **Open/Unlock**: Decrypt vault with passphrase
- **Lock**: Clear in-memory decrypted state (vault file unchanged on disk)
- **Read Entry**: Retrieve a single credential entry
- **Write Entry**: Add or update a credential entry
- **Passphrase Change**: Re-derive keys and re-encrypt all entries with new passphrase
- **Delete Entry**: Mark entry as deleted (logical; physical deletion in compaction)
- **Integrity Check**: Verify HMAC over entire vault

## Binary Vault File Format Specification

The vault file is binary with the following structure. All multi-byte integers are **little-endian** unless noted.

### Overall Structure

```
┌─────────────────────────────────────────────────────────────┐
│ VAULT HEADER (fixed 1024 bytes)                             │
├─────────────────────────────────────────────────────────────┤
│ VAULT INDEX (variable length, prefixed with 4-byte length)  │
├─────────────────────────────────────────────────────────────┤
│ ENTRIES BLOB (variable length, contains encrypted entries)  │
├─────────────────────────────────────────────────────────────┤
│ VAULT HMAC (32 bytes, covers header + index + entries)      │
└─────────────────────────────────────────────────────────────┘
```

### Vault Header (Bytes 0–1023)

All header fields are in **little-endian** byte order.

```
Offset  Size  Field Name              Description
────────────────────────────────────────────────────────────────
0       8     MAGIC                   "PADLOCK\x00" (8 bytes)
8       1     VERSION                 Protocol version (1)
9       1     FLAGS                   Bit 0: encrypted (1=yes)
10      2     RESERVED1               (must be 0x0000)
12      16    ARGON2_SALT             Salt for KDF (16 bytes)
28      4     VAULT_UUID_HIGH         UInt32 (high 32 bits of vault ID)
32      4     VAULT_UUID_LOW          UInt32 (low 32 bits of vault ID)
36      8     CREATED_TIMESTAMP       Unix timestamp (seconds), 8 bytes
44      8     MODIFIED_TIMESTAMP      Unix timestamp (seconds), 8 bytes
52      4     ENTRY_COUNT             Number of active entries
56      4     DELETED_ENTRY_COUNT     Number of deleted/tombstone entries
60      4     VAULT_INDEX_LENGTH      Length of vault index section (bytes)
64      4     ENTRIES_BLOB_LENGTH     Total length of entries blob (bytes)
68      4     RESERVED2               (must be 0x00000000)
72      (up to 952 bytes) RESERVED3   Reserved for future use (zeros)
1024    (end of header)
```

### Vault Index (Variable Length)

The vault index is a MessagePack-serialized map from entry UUID to entry metadata.

**Format**:
- Prefixed with a 4-byte little-endian length field
- Followed by MessagePack binary data
- Serialized Rust structure:
  ```rust
  pub struct VaultIndex {
      entries: HashMap<[u8; 16], EntryMetadata>,
  }

  pub struct EntryMetadata {
      uuid: [u8; 16],
      filename_hash: [u8; 32],      // SHA-256 of entry ID (for file naming)
      entry_offset: u64,             // Offset in entries blob
      entry_length: u32,             // Length of entry data
      created_at: u64,               // Unix timestamp
      modified_at: u64,              // Unix timestamp
      deleted: bool,                 // Logical deletion flag
  }
  ```
- MessagePack encodes this as a compact binary map
- On deserialization, expect exactly `ENTRY_COUNT + DELETED_ENTRY_COUNT` entries in the map

### Entries Blob (Variable Length)

Contains encrypted entry data concatenated together. Each entry is:

```
┌──────────────────────────────────────────┐
│ Entry Data (variable length)             │
│                                          │
│ ┌──────────────────────────────────────┐ │
│ │ Wrapped DEK (48 bytes)               │ │
│ │ = XChaCha20-Poly1305(KEK, n, DEK)   │ │
│ ├──────────────────────────────────────┤ │
│ │ Nonce for DEK wrapping (24 bytes)   │ │
│ ├──────────────────────────────────────┤ │
│ │ Ciphertext (variable length)         │ │
│ │ = XChaCha20-Poly1305(DEK, n, entry) │ │
│ │   where entry is MessagePack        │ │
│ │   serialized EncryptedEntry struct   │ │
│ └──────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

**Entry Field Breakdown**:

```
Offset  Size    Field Name              Description
──────────────────────────────────────────────────────
0       48      WRAPPED_DEK             Encrypted DEK (XChaCha20-Poly1305 ciphertext)
48      24      NONCE_DEK_WRAP          Nonce used to wrap the DEK
72      var     CIPHERTEXT              Encrypted MessagePack entry data
(end)   (var)   (end of entry)
```

**EncryptedEntry Structure** (serialized as MessagePack before encryption):

```rust
pub struct EncryptedEntry {
    pub uuid: [u8; 16],
    pub title: String,
    pub username: String,
    pub password: String,          // SecureString in code; plain in MessagePack
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub created_at: u64,           // Unix timestamp
    pub modified_at: u64,          // Unix timestamp
}
```

### Vault HMAC (Last 32 Bytes)

The vault HMAC is **appended at the end** of the file (after all entries).

```
Offset              Size  Field Name      Description
─────────────────────────────────────────────────────────
(end - 32)          32    VAULT_HMAC      HMAC-SHA-256 over [header + index + entries]
```

**HMAC Computation**:
```
MACKEY = derive_mackey(PDK)
data_to_mac = header_bytes (1024) || index_length (4) || index_data || entries_blob
vault_hmac = HMAC-SHA-256(MACKEY, data_to_mac)
```

- HMAC is computed using MACKEY (derived from PDK)
- HMAC covers header + index + entries (all authenticated material)
- HMAC is verified on vault open before allowing any operations
- HMAC is recomputed and written on every vault write operation

### Example Byte Layout (Simplified)

```
[MAGIC (8)] [VERSION (1)] [FLAGS (1)] [...] [ARGON2_SALT (16)] [...] [ENTRY_COUNT (4)] [INDEX_LENGTH (4)] [ENTRIES_BLOB_LENGTH (4)] [...padding...]
[INDEX_LENGTH (4)] [MSGPACK_INDEX (variable)]
[WRAPPED_DEK_1 (48)] [NONCE_1 (24)] [CIPHERTEXT_1 (variable)]
[WRAPPED_DEK_2 (48)] [NONCE_2 (24)] [CIPHERTEXT_2 (variable)]
...
[VAULT_HMAC (32)]
```

## Vault Lifecycle States

The vault in-memory state machine has three states:

### 1. Created (Locked)
- Vault file exists on disk
- Passphrase-derived keys are NOT loaded into memory
- Cannot read/write entries
- Transition: unlock() → Unlocked

### 2. Unlocked
- Vault file exists on disk
- In-memory decrypted entry cache is populated
- PDK, KEK, MACKEY loaded into memory (SecretBuf)
- Can read/write entries
- Transition: lock() → Locked; close() → (file closed, state destroyed)

### 3. Deleted/Closed
- Vault is no longer accessible
- All in-memory keys are zeroized
- Transition: (terminal state)

### State Diagram

```
         ┌─────────────────┐
         │ Created (Locked)│
         └────────┬────────┘
                  │ unlock(passphrase)
                  │ [derive PDK, KEK, MACKEY]
                  │ [verify HMAC, decrypt entries]
                  ▼
         ┌─────────────────┐
         │   Unlocked      │
         │ (in-memory keys)│
         └────────┬────────┘
                  │
       ┌──────────┴──────────┐
       │ lock()              │ close()
       │ [zeroize keys]      │ [cleanup]
       ▼                     ▼
  Created (Locked)      Closed (destroyed)
```

## Vault Operations

### 1. Init: Create New Vault

**Input**:
- `passphrase: &str` (user-provided)
- `vault_path: &Path` (file system location)

**Process**:
1. Generate random Argon2 salt (16 bytes)
2. Generate random vault UUID (16 bytes)
3. Derive PDK from passphrase + salt using Argon2id
4. Derive KEK and MACKEY from PDK using HKDF
5. Create empty vault index (MessagePack-serialized, empty map)
6. Create empty entries blob
7. Assemble vault header with metadata
8. Compute HMAC over header + index + entries
9. Write vault file atomically (see atomic write pattern below)
10. Return Vault object in Locked state

**File Permissions**:
- Directory (vault parent): `0o700` (rwx------)
- Vault file: `0o600` (rw-------)

### 2. Open/Unlock: Decrypt Vault

**Input**:
- `vault_path: &Path`
- `passphrase: &str`

**Process**:
1. Read vault file from disk
2. Parse header; extract Argon2 salt
3. Derive PDK from passphrase + salt (takes ~2–3 seconds)
4. Derive KEK and MACKEY from PDK
5. Read vault index (MessagePack-serialized)
6. Decrypt all entry data:
   - For each entry: unwrap DEK using KEK, decrypt ciphertext using DEK
   - Deserialize MessagePack to EncryptedEntry
   - Populate in-memory entry cache (HashMap<UUID, EncryptedEntry>)
7. Verify vault HMAC (compute HMAC over header + index + entries, compare with stored HMAC)
8. If HMAC fails: return error (possible corruption or tampering)
9. Return Vault object in Unlocked state

**Timing**:
- Argon2id: ~2–3 seconds (intentional for security)
- Decryption: ~10–100 ms (depends on vault size)
- Total unlock time: ~2–3 seconds per vault

### 3. Lock: Clear In-Memory Keys

**Input**: None (operates on self)

**Process**:
1. Zeroize PDK, KEK, MACKEY from memory (SecretBuf drop)
2. Clear in-memory entry cache (all decrypted entries)
3. Transition state from Unlocked → Locked
4. Vault file on disk remains unchanged

**Purpose**: Allows user to lock vault without closing file handle; re-unlock with same passphrase later without re-reading disk.

### 4. Read Entry

**Input**:
- `entry_uuid: &[u8; 16]`

**Process**:
1. Assert vault is Unlocked
2. Look up entry_uuid in in-memory cache
3. Return cloned EncryptedEntry or error if not found
4. No disk I/O (already decrypted in memory)

**Time**: < 1 ms

### 5. Write Entry (Create or Update)

**Input**:
- `entry: EncryptedEntry`

**Process**:
1. Assert vault is Unlocked
2. Check if entry UUID already exists
3. If exists: update entry in cache and vault index metadata
4. If new: insert entry, update entry count
5. Serialize entry to MessagePack
6. Generate random DEK
7. Generate random nonce (24 bytes) for DEK wrapping
8. Wrap DEK using KEK
9. Encrypt serialized entry using DEK (XChaCha20-Poly1305)
10. Append wrapped_dek || nonce || ciphertext to entries blob
11. Update vault index with entry metadata
12. Recompute vault HMAC
13. Write vault file atomically
14. Return success

**Time**: ~10–50 ms per entry (includes disk I/O and encryption)

### 6. Passphrase Change

**Input**:
- `old_passphrase: &str`
- `new_passphrase: &str`

**Process**:
1. Verify old passphrase by deriving PDK with old passphrase + stored salt
2. If verification fails: return error
3. Generate new Argon2 salt
4. Derive new PDK from new passphrase + new salt
5. Derive new KEK and MACKEY from new PDK
6. **Re-encrypt all entries**:
   - For each entry in cache: generate new random DEK, wrap with new KEK, encrypt with new DEK
   - Rebuild entries blob
7. Update vault header with new salt and timestamp
8. Recompute vault HMAC with new MACKEY
9. Write vault file atomically
10. Keep vault Unlocked with new keys
11. Old keys (old PDK, KEK, MACKEY) are zeroized

**Time**: ~2–3 seconds (dominated by Argon2id for new salt) + encryption time

### 7. Delete Entry (Logical Deletion)

**Input**:
- `entry_uuid: &[u8; 16]`

**Process**:
1. Assert vault is Unlocked
2. Look up entry_uuid in vault index
3. Set `deleted` flag to true in entry metadata
4. Remove entry from in-memory cache
5. Increment deleted_entry_count in header
6. Decrement entry_count (or leave separate counts)
7. Remove ciphertext from entries blob (logical; rebuild required)
8. Recompute vault HMAC
9. Write vault file atomically
10. Return success

**Note**: Physical deletion requires vault compaction (future operation).

### 8. Integrity Check (Verify HMAC)

**Input**: None (operates on file)

**Process**:
1. Read vault file
2. Extract stored HMAC (last 32 bytes)
3. Compute HMAC over header + index + entries
4. Compare using constant-time comparison
5. Return result

**Used during**:
- Vault open (mandatory before unlocking)
- After every write operation (before closing file)
- Optional user-triggered integrity verification

## Atomic File Write Pattern

All vault writes use an atomic file update pattern to ensure crash safety:

### Pattern: `tmp → fsync → rename backup → rename new → fsync dir`

```
1. Write to temporary file (vault.tmp)
   └─ Write all data: header + index + entries + hmac
   └─ fsync(tmp_fd) — ensure data on disk

2. Preserve existing backup
   └─ rename(vault, vault.backup)   [or skip if no existing vault]
   └─ fsync(dir)

3. Activate new vault
   └─ rename(vault.tmp, vault)
   └─ fsync(dir)

4. Cleanup (optional)
   └─ Delete vault.backup if not needed
```

### Why This Works

- **tmp → fsync**: Ensures tmp file is fully written to disk before renaming
- **rename backup**: Keeps a backup in case new write is corrupted
- **rename new**: Atomic on most filesystems (inode swap); old file still readable if new is incomplete
- **fsync dir**: Ensures directory metadata is on disk (required on some filesystems like ext4)

### Error Handling

- **Write fails**: tmp file left on disk (safe; next write overwrites)
- **Fsync fails**: Return error; keep vault unlocked for retry
- **Rename fails**: Return error; tmp file may exist (safe for retry)
- **Power loss during rename**: One of old or new file will be valid; no mixed state

## File Permissions

All vault-related files must have restrictive permissions:

```
Directory containing vault: 0o700 (rwx------)
Vault file:                 0o600 (rw-------)
Backup file:                0o600 (rw-------)
Temp file:                  0o600 (rw-------)
```

**Enforcement**:
- Set via `std::fs::Permissions::set_mode()` (Unix)
- Verify on every read (warn if permissions are too open)

## Module Structure

```
src/vault/
├── mod.rs                 # Public module interface, Vault struct, lifecycle
├── format.rs              # Binary format parsing, header/index/entries
├── lifecycle.rs           # State machine, init/open/lock/close
├── storage.rs             # File I/O, read_vault_file, write_vault_file
├── atomic.rs              # Atomic write pattern, fsync, rename
└── entries.rs             # Entry encryption/decryption, caching
```

### Module Responsibilities

#### `vault/mod.rs`
- Public `Vault` struct representing vault state
- Methods: `init()`, `open()`, `lock()`, `close()`, `read_entry()`, `write_entry()`, `delete_entry()`, `change_passphrase()`
- Vault state enum: Created, Unlocked, Deleted
- Re-exports key types

#### `vault/format.rs`
- `VaultHeader` struct with all fields
- `VaultIndex` struct (HashMap-based)
- `EntryMetadata` struct
- `EncryptedEntry` struct
- Parse/serialize functions:
  - `parse_header(bytes: &[u8]) -> Result<VaultHeader>`
  - `serialize_header(header: &VaultHeader) -> Vec<u8>` (exactly 1024 bytes)
  - `parse_index(bytes: &[u8]) -> Result<VaultIndex>` (MessagePack deserialization)
  - `serialize_index(index: &VaultIndex) -> Vec<u8>` (MessagePack serialization)
- Validation functions:
  - `validate_magic(header: &VaultHeader) -> bool`
  - `validate_version(header: &VaultHeader) -> bool`

#### `vault/lifecycle.rs`
- State machine logic
- `Vault::init(passphrase, path) -> Result<Vault>` (creates new vault)
- `Vault::open(passphrase, path) -> Result<Vault>` (opens existing vault)
- `Vault::lock(&mut self) -> Result<()>` (clear keys, transition to Locked)
- `Vault::close(&mut self) -> Result<()>` (cleanup)
- State assertions: `assert_unlocked()`, etc.

#### `vault/storage.rs`
- `read_vault_file(path: &Path) -> Result<Vec<u8>>`
- `write_vault_file(path: &Path, data: &[u8]) -> Result<()>`
- File I/O with permission checks
- Verify permissions after read (warn if too open)

#### `vault/atomic.rs`
- `atomic_write(vault_path: &Path, data: &[u8]) -> Result<()>`
  - Implements tmp → fsync → rename backup → rename new → fsync dir pattern
- Helper functions:
  - `fsync_dir(path: &Path) -> Result<()>`
  - `rename_with_backup(old: &Path, new: &Path) -> Result<()>`

#### `vault/entries.rs`
- `encrypt_entry(entry: &EncryptedEntry, dek: &SecretBuf) -> Result<Vec<u8>>`
  - Serialize to MessagePack, encrypt with XChaCha20-Poly1305
  - Return: wrapped_dek || nonce || ciphertext
- `decrypt_entry(data: &[u8], kek: &SecretBuf) -> Result<EncryptedEntry>`
  - Parse wrapped_dek and nonce, unwrap DEK, decrypt ciphertext
  - Deserialize MessagePack to EncryptedEntry

## Module Dependencies

```
vault/
  ├── depends on: crypto/ (aead, kdf, hkdf, hmac)
  ├── depends on: std (fs, io, path)
  ├── depends on: uuid (entry IDs)
  └── depends on: rmp-serde (MessagePack serialization)
```

## Required Crates

- **`rmp-serde`**: MessagePack serialization (vault index and entries)
- **`uuid`**: UUID v4 generation for vault IDs and entry IDs
- **`serde`**: Serialization framework (used by rmp-serde)
- **`std::fs`**: File I/O (built-in, no crate needed)
- **`std::path`**: Path handling (built-in)
- **Crates from crypto module**: Re-imported as needed

## Testing Strategy

### 1. Vault Corruption Detection

**Test**: Vault file integrity validation

- Create vault with known entries
- Flip a single bit in the vault file (anywhere in header/index/entries)
- Attempt to open vault
- Verify HMAC verification fails
- Ensure no partial decryption or data leakage

### 2. Atomic Write Crash Recovery

**Test**: Simulate crash during write; verify recovery

- Open vault, write an entry
- Simulate crash: kill process mid-write (or use mock for testing)
- Restart; verify vault is in a consistent state (old or new version, not mixed)
- Verify backup file exists if needed
- Verify temp files are cleaned up on next write

### 3. Passphrase Change

**Test**: Change vault passphrase

- Create vault with passphrase "old"
- Write entries
- Change passphrase to "new"
- Lock and unlock vault with "new" passphrase
- Verify entries are intact
- Verify old passphrase no longer works
- Verify all entries were re-encrypted (DEKs are new)

### 4. Wrong Passphrase Rejection

**Test**: Reject incorrect passphrase

- Create vault with passphrase "correct"
- Attempt to open with passphrase "wrong"
- Verify HMAC verification fails (or Argon2 derives wrong PDK)
- Ensure no plaintext leakage
- Ensure vault file is unchanged

### 5. Entry Read/Write Round-Trip

**Test**: Write and read entries

- Create vault
- Write 10 entries with various data (unicode, special chars, long passwords)
- Read each entry back
- Verify data matches exactly
- Verify UUIDs are assigned correctly

### 6. Entry Delete and Restore

**Test**: Logical deletion

- Create vault, write entries
- Delete entry (set deleted flag)
- Verify entry no longer appears in read_entry()
- Verify entry_count decremented
- Verify deleted_entry_count incremented

### 7. Vault Index Serialization

**Test**: MessagePack round-trip

- Create VaultIndex with known entries
- Serialize to MessagePack
- Deserialize
- Verify all entries and metadata are intact

### 8. Header Format Validation

**Test**: Header parsing and serialization

- Create VaultHeader with all fields
- Serialize to 1024-byte header
- Verify magic bytes at offset 0
- Verify salt at offset 12–27
- Verify entry counts at correct offsets
- Deserialize and compare fields

### 9. File Permissions Enforcement

**Test**: Permissions on created vault file

- Create vault
- Verify vault file has mode 0o600
- Verify vault directory has mode 0o700
- Read vault and verify file permissions are not modified

### 10. Large Vault Handling

**Test**: Vault with many entries

- Create vault
- Write 1000 entries (total size ~10 MiB)
- Close and reopen vault
- Verify all entries are intact
- Measure performance (should be < 30 seconds to unlock and verify HMAC)

### 11. Vault Index Consistency

**Test**: Index and entries blob are in sync

- Create vault, write entries
- Manually verify entry_count matches entries in entries blob
- Verify every entry in index has corresponding entry in blob
- Verify no orphaned entries (in blob but not in index)

## Security Invariants (MUST HOLD)

1. **No plaintext entries on disk**
   - All entries are encrypted with XChaCha20-Poly1305 (authenticated)
   - Entry ciphertext is AEADencrypted; no partial decryption possible

2. **Vault HMAC is mandatory for integrity**
   - HMAC covers all authenticated material (header + index + entries)
   - HMAC verification is constant-time
   - No operation succeeds if HMAC fails

3. **Atomic file writes prevent partial writes**
   - tmp → fsync → rename ensures all-or-nothing semantics
   - Crash during write leaves vault in known state (old or new, not mixed)

4. **Passphrase is never stored**
   - Only salt (public) and derived keys (derived on demand) are stored
   - Passphrase is immediately zeroized after KDF

5. **In-memory decrypted entries are cleared on lock**
   - lock() zeroizes all keys and entry cache
   - No plaintext entries remain in RAM after lock

6. **Entry IDs (UUIDs) are cryptographically random**
   - No predictable entry IDs
   - Prevents enumeration attacks

7. **DEKs are independent and random**
   - Each entry has a fresh random DEK
   - Compromise of one entry's plaintext does not compromise others' DEKs

8. **File permissions prevent unauthorized access**
   - Vault files are readable only by owner (0o600)
   - Enforced on vault creation and verified on read

9. **Nonce uniqueness for entry encryption**
   - Each entry encryption uses a unique random 24-byte nonce
   - Stored alongside ciphertext (not secret)

10. **Metadata is immutable except for deletion**
    - Entry creation/modification timestamps are written once
    - Deleted flag is the only mutable metadata
    - (Future: audit log for detailed history)

## Error Handling

All vault operations return `Result<T, VaultError>`:

```rust
#[derive(Debug)]
pub enum VaultError {
    FileNotFound,
    InvalidFormat,
    CorruptedData,
    HmacMismatch,
    EncryptionFailed(CryptoError),
    SerializationFailed,
    DeserializationFailed,
    WrongPassphrase,
    IoError(io::Error),
    InvalidState,        // e.g., read_entry on Locked vault
    PermissionDenied,
}
```

- Errors are descriptive but do not leak sensitive data
- No panics in vault code (except for invariant violations)

## Performance Targets

- **Vault creation**: ~3 seconds (Argon2id)
- **Vault unlock**: ~3 seconds (Argon2id)
- **Lock**: < 1 ms (just clear keys)
- **Read entry**: < 1 ms (in-memory lookup)
- **Write entry**: ~10–50 ms (includes encryption and disk I/O)
- **Passphrase change**: ~3 seconds + re-encryption time (~100 ms per entry)
- **HMAC verification**: ~10–100 ms (depends on vault size)

## References & Standards

- **MessagePack**: Official spec (msgpack.org)
- **Atomic file operations**: Linux kernel documentation on rename(2), fsync(2)
- **File permissions**: POSIX 1003.1 (chmod semantics)
- **XChaCha20-Poly1305**: RFC 8439 (ChaCha20 extended to 192-bit nonce)

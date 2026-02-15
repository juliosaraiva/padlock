# Padlock Sync Protocol Context

## Status

**NOT IN MVP.** This context document describes the design for cross-device synchronization. Implementation is POST-MVP, but the architecture is documented here to guide future development and ensure the core vault design can support sync without major refactoring.

## Purpose

Enable secure synchronization of encrypted credentials across multiple user devices without trusting the synchronization backend. The sync layer must:

- Provide end-to-end encryption for all synchronized data
- Never expose plaintext or encryption keys to sync backends
- Maintain data consistency across devices with conflict resolution
- Operate offline with eventual consistency
- Minimize metadata leakage (device information, entry count, access patterns, timing)
- Support efficient incremental sync with minimal bandwidth
- Allow users to pair new devices via simple out-of-band verification

## Design Goals

1. **End-to-End Encryption (E2E)**: All data encrypted before leaving device; backend stores only ciphertext
2. **Server-Untrusted**: Backend cannot see device identities, entry keys, or metadata; suitable for untrusted cloud storage
3. **Conflict Resolution**: Automatic resolution with user notification and override options
4. **Bandwidth Efficient**: Incremental sync, compression, and optional payload padding for privacy
5. **Offline Capable**: Full read/write access offline; sync on reconnect with automatic conflict resolution
6. **Minimal Metadata Leakage**: Opaque file names, padded payloads, coarse timestamps

## Device Pairing Protocol

### SPAKE2 Out-of-Band Verification

New devices pair with existing devices using SPAKE2 (Simple Password Authenticated Key Exchange) with a 6-digit numeric code displayed on the initiating device:

- **Code Generation**: 6-digit random code (1,000,000 possibilities; collision probability negligible over typical user session)
- **Code Lifetime**: 5 minutes; expiration enforced by both devices
- **Code Transport**: User verbally communicates or visually transfers code (out-of-band, not transmitted digitally)
- **One-Time Use**: Code invalidated after successful pairing; replaying does not re-pair devices

### Pairing Flow

```
Device A (existing)                 Device B (new)
      |                                 |
      | Generate 6-digit code C         |
      | Derive SPAKE2 context           |
      | Display code to user            |
      |                                 |
      |  User enters code C             |
      |  Derive SPAKE2 context          |
      |  Compute shared_secret via      |
      |  SPAKE2(password=C)             |
      |                                 |
      | Derive shared_secret via        |
      | SPAKE2(password=C)              |
      |                                 |
      |------ Exchange identity_key ----|
      |------ Exchange wrapped_kek -----|
      |                                 |
      | Verify signatures               |
      | Derive device session keys      |
      |                                 |
      |------ Sync pull ------->|       |
      |<------ Sync push -------|       |
```

**Pairing Steps:**

1. **Device A (Initiator):**
   - Generate 6-digit code C (displayed to user)
   - Generate ephemeral SPAKE2 context with password=C
   - Wait for pairing request from Device B

2. **Device B (New Device):**
   - User enters code C (received from Device A)
   - Generate ephemeral SPAKE2 context with password=C
   - Compute SPAKE2 shared_secret
   - Generate new Ed25519 identity keypair (device_id_public, device_id_secret)
   - Derive device-specific AES-256-GCM key from shared_secret
   - Encrypt device_id_secret with derived key → wrapped_device_secret
   - Send (device_id_public, wrapped_device_secret) to Device A

3. **Device A (Verifier):**
   - Receive pairing request
   - Compute SPAKE2 shared_secret with code C
   - Decrypt received wrapped_device_secret
   - Verify Device B's identity_key signature with ECDH key agreement
   - Derive shared Master Encryption Key (MEK) for sync operations
   - Encrypt MEK with Device B's identity_key → wrapped_kek
   - Send wrapped_kek to Device B

4. **Device B (Complete):**
   - Receive and decrypt wrapped_kek
   - Verify Device A's signature
   - Store Device A's identity_key and MEK
   - Begin sync operations

## Sync Wire Protocol

### Message Structure

All sync messages use a framed protocol with the following structure:

```rust
struct SyncMessage {
    // Metadata (unencrypted, visible to backend)
    version: u32,                  // Protocol version (currently 1)
    sender_device_id: [u8; 32],   // Ed25519 public key of sender
    sequence_number: u64,          // Monotonically increasing per device
    timestamp_coarse: u32,         // Unix timestamp rounded to 1-hour buckets

    // Encrypted payload (opaque to backend)
    encrypted_payload: Vec<u8>,   // AES-256-GCM(payload, nonce=timestamp_coarse||seq)
    payload_size_padded: u16,     // Padded to 1KiB blocks for privacy

    // Proof of authenticity
    signature: [u8; 64],          // Ed25519(sender_device_id_secret, message_hash)
}
```

**Encryption Details:**
- **Cipher**: AES-256-GCM (authenticated encryption)
- **Nonce**: Derived from timestamp_coarse (u32) || sequence_number (u64)
- **Key**: Device-specific sync key derived from MEK
- **Authentication**: Ed25519 signature over entire message structure
- **Padding**: Payload padded to nearest 1KiB block to obfuscate entry count and operation sizes

### Payload Operations

Encrypted payloads contain a list of operations:

```rust
enum Operation {
    UpsertEntry {
        entry_id: [u8; 32],           // SHA-256 hash of encrypted entry
        encrypted_entry: Vec<u8>,     // Full encrypted entry data
        version: LamportTimestamp,    // Lamport clock value
        device_id: [u8; 32],          // Device that performed operation
    },
    DeleteEntry {
        entry_id: [u8; 32],
        version: LamportTimestamp,
        tombstone_time: u64,          // Coarse deletion timestamp (1-hour bucket)
    },
    UpdateMetadata {
        metadata_key: String,
        metadata_value: Vec<u8>,
        version: LamportTimestamp,
    },
}
```

## Conflict Resolution

### Vector Clocks

Each entry maintains a vector clock tracking causal relationships:

```rust
struct VectorClock {
    // Per-device Lamport timestamp
    clocks: HashMap<[u8; 32], u64>,  // device_id -> lamport_timestamp
}
```

### Conflict Detection

Conflicts occur when two or more devices concurrently modify the same entry (causally unrelated):

```rust
fn detect_conflict(clock_a: &VectorClock, clock_b: &VectorClock) -> bool {
    // Neither clock dominates the other
    !dominates(clock_a, clock_b) && !dominates(clock_b, clock_a)
}
```

### Default Resolution Strategy

**Last-Write-Wins (LWW) with Notification:**
- Device that modified entry most recently (by Lamport timestamp) wins
- If timestamps are equal, device_id lexicographically sorts (stable, deterministic)
- User receives notification that conflict occurred; manual override available
- Resolved entry synced back to all devices

**Alternative Strategies (configurable per user):**
- **Manual Resolution**: Conflict pauses sync; user must choose winning version
- **Keep Local**: Local device's version always wins
- **Keep Remote**: Remote device's version always wins
- **Merge Strategy**: Application-level merge (for structured data types)

### Merging Example

For password entries with TOTP:
- Conflict between Device A (password + TOTP code) and Device B (password only)
- Default strategy: LWW uses Device A's version (more recent edit)
- Alternative: Merge strategy combines both password and TOTP

## Sync Backends

### Backend Trait

```rust
trait SyncBackend: Send + Sync {
    async fn upload(&self, message: SyncMessage) -> Result<()>;
    async fn download_since(&self, device_id: &[u8; 32], seq: u64) -> Result<Vec<SyncMessage>>;
    async fn list_devices(&self) -> Result<Vec<DeviceInfo>>;
}
```

### Supported Backends

#### v1: File-Based (Local/Network)

- **Use Case**: Single machine, NAS, network mount
- **Storage**: Flat directory with files named `device-{device_id_hex}/{seq}.msg`
- **Properties**: No central server, suitable for LAN or direct attachment
- **Limitations**: Requires shared filesystem or manual export/import

```
sync-storage/
├── device-abc123.../
│   ├── 0.msg
│   ├── 1.msg
│   └── 2.msg
└── device-def456.../
    ├── 0.msg
    └── 1.msg
```

#### Future: Cloud Storage Backend

- **Target**: AWS S3, Azure Blob, Google Cloud Storage, Backblaze B2
- **Encryption**: Data encrypted client-side before upload
- **Auth**: SigV4 (AWS) or equivalent; no plaintext credentials stored
- **Bandwidth**: Resume support for large payloads
- **Deletion**: Automatic cleanup of old messages per retention policy

#### Future: Relay Server Backend

- **Target**: Self-hosted Padlock sync relay or managed service
- **Protocol**: WebSocket with TLS 1.3
- **Server Responsibilities**: Route messages, enforce rate limits, garbage collect old messages
- **Server Limitations**: Cannot decrypt payloads, cannot see device identities (only public keys)
- **Redundancy**: Support multiple relay servers with automatic failover

## Metadata Leakage Minimization

### Threat Model

Adversary with access to sync backend can observe:
- Device identities (Ed25519 public keys used as device_id)
- Message timing and frequency
- Approximate entry count (via payload size)
- Message sequence numbers and order

### Mitigations

1. **Opaque File Names**: File names derived from sequence number only; backend cannot map to entry IDs
2. **Payload Padding**: All payloads padded to 1KiB blocks; entry count unknown
3. **Coarse Timestamps**: Timestamps rounded to 1-hour buckets; precise access time hidden
4. **Device ID Rotation** (future): Rotate device_id public key periodically with signature chain
5. **Decoy Operations** (future): Inject dummy sync operations at configurable rate

### Non-Targets

The following are NOT protected and visible to backend:
- Device pairing events (timing, order)
- Total message count
- Sync frequency and duration
- Device count and which devices are paired
- Whether specific entries exist (inferrable from padded payload size range)

## Module Structure

```
src/sync/
├── mod.rs                    # Public API, SyncManager
├── pairing.rs               # SPAKE2 pairing flow, device enrollment
├── protocol.rs              # SyncMessage, Operation, wire format
├── conflict.rs              # VectorClock, conflict detection, resolution
├── clock.rs                 # Lamport timestamp implementation
├── backends/
│   ├── mod.rs               # SyncBackend trait
│   └── file.rs              # File-based backend (v1)
└── tests/
    ├── pairing_tests.rs
    ├── protocol_tests.rs
    └── conflict_tests.rs
```

### Public API

```rust
// Manager
pub struct SyncManager {
    backend: Box<dyn SyncBackend>,
    local_device_id: [u8; 32],
    vault: Arc<Vault>,
}

impl SyncManager {
    pub async fn initiate_pairing(&self, code_lifetime_secs: u64) -> Result<PairingSession>;
    pub async fn complete_pairing(&self, pairing_data: PairingData) -> Result<()>;
    pub async fn sync_pull(&self) -> Result<SyncStats>;
    pub async fn sync_push(&self) -> Result<SyncStats>;
    pub async fn sync_bidirectional(&self) -> Result<SyncStats>;
    pub async fn resolve_conflict(&self, entry_id: &[u8; 32], resolution: ResolutionStrategy) -> Result<()>;
}

pub struct SyncStats {
    pub messages_received: usize,
    pub messages_sent: usize,
    pub conflicts_detected: usize,
    pub conflicts_resolved: usize,
}
```

## Dependencies

### Required Crates

```toml
[dependencies]
spake2 = "0.4"
x25519-dalek = "2.0"
ed25519-dalek = "2.1"
aes-gcm = "0.10"
```

### Internal Dependencies

- **crypto** module: Key derivation, encryption, signing
- **vault** module: Entry storage, metadata management
- **entries** module: Entry structure definitions
- **storage** module: StorageBackend trait for persistent state

## Design Rationale

### Why SPAKE2 + 6-Digit Code?

- SPAKE2 protects against offline dictionary attacks
- 6-digit code memorable for users, low cognitive load
- Out-of-band code transport prevents MITM on digital channels
- Time limit (5 minutes) reduces code guessing window
- Single-use prevents replay

### Why Lamport Timestamps + Vector Clocks?

- Lamport clocks are lightweight and deterministic
- Vector clocks enable causal ordering detection
- No synchronized global time required
- LWW resolution is simple and fast; users rarely encounter conflicts in practice

### Why 1KiB Padding Blocks?

- Balances privacy (difficult to infer exact entry count) with bandwidth
- 1KiB blocks are natural boundary for most entry sizes
- Configurable padding level for users with different privacy/bandwidth tradeoffs

### Why Coarse Timestamps?

- Prevents adversary from inferring exact access times
- 1-hour granularity sufficient for eventual consistency semantics
- Reduces timestamp entropy and fingerprinting surface

## Future Enhancements

1. **Device ID Rotation**: Rotate public keys with signature-chain continuity to prevent device tracking
2. **Bandwidth Optimization**: Delta-sync for large entries; store diffs instead of full updates
3. **Sync Scheduling**: Automatic background sync with user-configurable policies
4. **Selective Sync**: Sync specific folders/tags, not entire vault
5. **Peer-to-Peer Sync**: Direct device-to-device sync without backend (e.g., Bluetooth, LAN)
6. **Decoy Traffic**: Inject dummy operations to obscure access patterns
7. **Compressed Sync**: gzip payloads before encryption for bandwidth savings
8. **Rate Limiting**: User-configurable sync limits (bytes/second, messages/minute)

## Testing Strategy

- **Unit Tests**: SPAKE2 pairing, vector clock operations, conflict detection
- **Integration Tests**: Full sync flows with mock backend
- **Stress Tests**: High entry counts, large payloads, many devices
- **Network Tests**: Latency, packet loss, intermittent connectivity
- **Privacy Tests**: Ensure no metadata leaks in wire protocol

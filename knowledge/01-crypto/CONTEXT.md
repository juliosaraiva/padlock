# Padlock Cryptographic Engine Context

## Purpose

The cryptographic engine implements all encryption, decryption, key derivation, HMAC operations, and secure memory management for the Padlock credential manager. It provides a cryptographically sound foundation that other modules depend upon. This module is responsible for:

- Vault data encryption/decryption
- Passphrase-based key derivation
- Key hierarchy management
- Authenticated encryption (AEAD)
- Integrity verification via HMAC
- Secure secret storage and memory management

## Algorithm Choices with Parameters

### AEAD: XChaCha20-Poly1305

- **Algorithm**: XChaCha20-Poly1305 (IETF variant)
- **Key size**: 256 bits (32 bytes)
- **Nonce size**: 192 bits (24 bytes) — enables safer random nonce generation
- **Authentication tag size**: 128 bits (16 bytes)
- **Use case**: Vault data encryption, encrypted entry storage
- **Rationale**: ChaCha20 is a modern stream cipher resistant to timing attacks; Poly1305 provides authentication; XChaCha20 extends nonce space for safety with random nonces

### KDF: Argon2id

- **Algorithm**: Argon2id (IANA identifier: $argon2id$)
- **Memory cost (m)**: 1 GiB (1,048,576 KiB)
- **Time cost (t)**: 2 iterations
- **Parallelism (p)**: 4 threads
- **Salt length**: 16 bytes (128 bits), randomly generated per vault
- **Output length**: 32 bytes (for PDK)
- **Use case**: Deriving Primary Derivation Key (PDK) from user passphrase
- **Rationale**: Memory-hard algorithm resists GPU/ASIC attacks; Argon2id balances parallelism and sequential cost; parameters tuned for ~2–3 second derivation on modern hardware

### HKDF: HKDF-SHA-256

- **Algorithm**: HKDF (RFC 5869) with SHA-256
- **Hash function**: SHA-256
- **Use case**: Deriving sub-keys from PDK (KEK and other keys)
- **Info strings**:
  - Vault KEK: `"padlock-vault-kek"` (16 bytes)
  - Vault mackey: `"padlock-vault-mackey"` (20 bytes)
- **Salt**: 0 bytes (implicit, as per RFC 5869 for single-recipient scenarios)
- **Output lengths**: 32 bytes each (256-bit keys)
- **Rationale**: Industry-standard key expansion; deterministic output from PDK; includes context info strings to prevent key confusion

### HMAC: HMAC-SHA-256

- **Algorithm**: HMAC-SHA-256 (RFC 2104)
- **Key size**: 256 bits (32 bytes)
- **Output size**: 256 bits (32 bytes)
- **Use case**: Vault file integrity verification and vault metadata authentication
- **Rationale**: Provides authentication without confidentiality; detects tampering; fast and well-analyzed

## Key Hierarchy Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User Passphrase                           │
│                  (variable length, UTF-8)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Argon2id (1GiB, t=2, p=4, 16-byte salt)
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              PDK (Primary Derivation Key)                    │
│               256 bits, deterministic from                   │
│          passphrase + vault-specific Argon2id salt           │
└──────────────────────┬──────────────────────────────────────┘
                       │
           ┌───────────┴───────────┐
           │                       │
           │ HKDF (info=           │ HKDF (info=
           │ "padlock-            │ "padlock-
           │  vault-kek")          │  vault-mackey")
           │                       │
┌──────────▼────────────┐  ┌──────▼──────────────┐
│  KEK (Key Encrypt     │  │  MACKEY (HMAC Key)  │
│  Key) 256 bits        │  │  256 bits           │
│  Used to wrap DEKs    │  │  Used for vault     │
└──────────┬────────────┘  │  integrity check    │
           │               └─────────────────────┘
           │
           │ For each entry: KEK encrypts
           │ a random DEK (not HKDF-derived)
           │
┌──────────▼──────────────┐
│ DEK (Data Encrypt Key)  │
│ 256 bits per entry,     │
│ randomly generated,      │
│ wrapped by KEK          │
└─────────────────────────┘
```

### Key Hierarchy Semantics

1. **PDK (Primary Derivation Key)**
   - Derived from passphrase + Argon2id (vault-specific salt)
   - Deterministic and reproducible from the same passphrase + salt
   - Stored nowhere; reconstructed on vault unlock
   - Serves as the root of all other keys

2. **KEK (Key Encryption Key)**
   - Derived from PDK via HKDF-SHA-256 (info: "padlock-vault-kek")
   - Used exclusively to wrap/unwrap Data Encryption Keys (DEKs)
   - One KEK per vault
   - Deterministic from PDK

3. **MACKEY (HMAC Key)**
   - Derived from PDK via HKDF-SHA-256 (info: "padlock-vault-mackey")
   - Used to compute HMAC over vault metadata and all entries
   - One MACKEY per vault
   - Deterministic from PDK

4. **DEK (Data Encryption Key)**
   - A random 256-bit key, generated fresh for each vault entry
   - Wrapped (encrypted) by the KEK using XChaCha20-Poly1305
   - Stored alongside encrypted data in vault (wrapped DEK + ciphertext)
   - **NOT derived via HKDF** — purely random
   - Different DEK per entry ensures compromise of one entry does not compromise others

## DEK Strategy: Random Wrapped Keys (Not HKDF-Derived)

**Decision**: Each entry's Data Encryption Key is randomly generated and then wrapped by the KEK.

**Rationale**:
- Provides independence: compromise of one entry's plaintext does not enable key recovery for other entries (DEKs are independent random values)
- Allows per-entry key rotation without changing KEK
- Simplifies key management in a multi-entry vault
- Stored format: `[wrapped_dek (48 bytes) || ciphertext (variable)]`
  - `wrapped_dek` = XChaCha20-Poly1305(KEK, random_nonce_24b, DEK_32b)
  - Unwrap to recover DEK, then decrypt ciphertext with DEK

## Required Crates

### Core Cryptography
- **`chacha20poly1305`**: AEAD cipher (XChaCha20-Poly1305)
- **`argon2`**: Password hashing (Argon2id)
- **`hkdf`**: Key derivation (HKDF-SHA-256)
- **`sha2`**: SHA-256 hashing (used by HKDF and HMAC)
- **`hmac`**: HMAC-SHA-256

### Secure Memory & Randomness
- **`zeroize`**: Zeroize secrets on drop
- **`secrecy`**: Type-level secret markers and types
- **`memsec`**: Platform-specific memory locking (mlock on Unix)
- **`subtle`**: Constant-time comparison
- **`rand`**: CSPRNG for nonce/key generation
- **`getrandom`**: OS random source (used by rand)

### Dependency Management
All crates must be pinned to specific versions in `Cargo.toml` with security audits checked.

## SecretBuf Implementation Requirements

A custom `SecretBuf` type wraps sensitive data with the following guarantees:

### Properties
1. **Memory locking**: Allocated via `memsec::mlock` on Unix; prevents OS swapping
2. **Guard pages**: Before and after the buffer (where available) to catch buffer overflows
3. **Automatic zeroization**: Implements `Drop` that zeroizes contents before deallocation
4. **No Debug output**: Custom Debug impl that prints `"***SecretBuf***"` instead of contents
5. **No Display impl**: Prevents accidental string conversion
6. **Immutable borrowing**: Provides `&[u8]` access via `Deref`; no mutable borrowing (enforces immutability during use)
7. **Clone not available**: SecretBuf does not impl Clone to prevent accidental copies
8. **Drop guarantees**: Uses explicit `drop()` in critical paths to zeroize early

### Interface
```rust
pub struct SecretBuf {
    // Platform-specific mlock'd allocation
}

impl SecretBuf {
    pub fn new(size: usize) -> Self; // Allocate locked buffer
    pub fn from_bytes(data: &[u8]) -> Self; // Allocate and copy
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}

impl Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8]; // Immutable access only
}

impl Drop for SecretBuf {
    fn drop(&mut self); // Zeroize on drop
}

impl Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "***SecretBuf***")
    }
}
```

## Module Structure

```
src/crypto/
├── mod.rs                 # Public module interface, re-exports
├── aead.rs               # XChaCha20-Poly1305 encrypt/decrypt
├── kdf.rs                # Argon2id passphrase KDF, PDK derivation
├── hkdf_keys.rs          # HKDF-SHA-256 subkey derivation (KEK, MACKEY)
├── hmac.rs               # HMAC-SHA-256 vault integrity
├── secret_buf.rs         # SecretBuf implementation (locked memory, zeroize)
└── memory.rs             # Memory safety utilities (clear, compare_ct)
```

### Module Responsibilities

#### `crypto/mod.rs`
- Public module interface
- Re-exports key types and functions
- High-level validation functions (e.g., validate nonce size)

#### `crypto/aead.rs`
- `encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>`
  - Returns ciphertext with Poly1305 tag appended
  - Nonce MUST be 24 bytes; panics otherwise
  - Key MUST be 32 bytes
- `decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>`
  - Validates tag; returns error on authentication failure
  - Returns plaintext without tag

#### `crypto/kdf.rs`
- `derive_pdk(passphrase: &str, salt: &[u8]) -> Result<SecretBuf>`
  - Uses Argon2id with parameters (m=1GiB, t=2, p=4)
  - Validates salt length (16 bytes)
  - Returns 32-byte PDK in SecretBuf
- `generate_argon2_salt() -> [u8; 16]`
  - Uses `rand::OsRng` for CSPRNG

#### `crypto/hkdf_keys.rs`
- `derive_kek(pdk: &SecretBuf) -> SecretBuf`
  - HKDF-SHA-256 with info="padlock-vault-kek"
  - Returns 32-byte KEK
- `derive_mackey(pdk: &SecretBuf) -> SecretBuf`
  - HKDF-SHA-256 with info="padlock-vault-mackey"
  - Returns 32-byte MACKEY
- `expand_key(key: &SecretBuf, info: &[u8], len: usize) -> Result<SecretBuf>`
  - Generic HKDF expansion; used internally

#### `crypto/hmac.rs`
- `compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32]`
  - HMAC-SHA-256
  - Returns 32-byte tag
- `verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()>`
  - Constant-time comparison using `subtle::ConstantTimeComparison`
  - Returns error on mismatch

#### `crypto/secret_buf.rs`
- Complete SecretBuf implementation with mlock, guard pages, zeroize
- Memory-safe string handling for passphrases

#### `crypto/memory.rs`
- `clear_memory(buf: &mut [u8])`
  - Wrapper around volatile writes to prevent compiler optimization
- `secure_compare(a: &[u8], b: &[u8]) -> bool`
  - Constant-time comparison for integrity checks

## Public API Sketch

```rust
// Key types
pub struct SecretBuf { /* ... */ }
pub struct EncryptedVault { /* ... */ }

// AEAD
pub fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>>;

pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>>;

// KDF
pub fn derive_pdk(passphrase: &str, salt: &[u8]) -> Result<SecretBuf>;
pub fn generate_argon2_salt() -> [u8; 16];

// HKDF subkeys
pub fn derive_kek(pdk: &SecretBuf) -> SecretBuf;
pub fn derive_mackey(pdk: &SecretBuf) -> SecretBuf;

// HMAC
pub fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32];
pub fn verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()>;

// Random nonce generation
pub fn generate_nonce_24b() -> [u8; 24];

// DEK wrapping (higher-level)
pub fn wrap_dek(kek: &SecretBuf) -> (Vec<u8>, SecretBuf);
// Returns (wrapped_dek, plaintext_dek)

pub fn unwrap_dek(kek: &SecretBuf, wrapped_dek: &[u8]) -> Result<SecretBuf>;
// Decrypts wrapped_dek to recover plaintext DEK
```

## Testing Strategy

### 1. Round-Trip Property Tests
- Encrypt plaintext → decrypt ciphertext; verify plaintext recovered
- Test across various plaintext sizes (0 bytes, 1 byte, 1000 bytes, 1 MiB)
- Test AAD variations (empty AAD, non-empty AAD)
- Test nonce uniqueness: generate 100k nonces, verify all unique

### 2. Wrong-Key Rejection
- Encrypt with key K1
- Attempt decrypt with key K2 (K1 ≠ K2)
- Verify authentication failure (tag rejection)
- Verify no plaintext leakage

### 3. Nonce Uniqueness Statistical Test
- Generate 1M random nonces using `generate_nonce_24b()`
- Run collision detection (birthday bound check)
- Verify statistical properties (entropy tests optional but desirable)

### 4. Memory Zeroing Verification
- SecretBuf drops contents: write SecretBuf with known pattern, drop it, verify memory location is zeroed
- Uses `memsec` APIs to inspect memory (Unix only; graceful skip on other platforms)
- PDK SecretBuf: after unlock completion, verify PDK bytes are overwritten

### 5. KDF Parameter Verification
- Argon2id(passphrase="test", salt1) produces consistent output across runs
- Different salts produce different PDKs
- Wrong passphrase produces wrong PDK

### 6. HKDF Determinism
- HKDF(PDK, info="padlock-vault-kek") always produces same KEK for same PDK
- Different info strings produce different keys

### 7. HMAC Integrity
- Compute HMAC over data
- Flip a single bit in data
- Verify HMAC fails
- Verify constant-time comparison (via timing analysis or by structure)

### 8. Nonce Derivation Edge Cases
- 0-byte nonce: fails validation
- 24-byte nonce: accepted
- 25-byte nonce: fails validation
- Verify panics or errors are appropriate

## Security Invariants (MUST HOLD)

1. **No plaintext key material in logs or error messages**
   - All key types implement custom Display/Debug that hide contents
   - Error types never include SecretBuf or key data

2. **Constant-time comparison for authentication**
   - All HMAC comparisons use `subtle` or custom constant-time impl
   - Tag validation is constant-time

3. **Passphrase never stored in plaintext**
   - Passphrases are immediately converted to SecretBuf
   - SecretBuf is zeroized on drop
   - No string copies or intermediate buffers

4. **PDK never exported from crypto module**
   - PDK is internal; only KEK and MACKEY are derived and returned
   - PDK is zeroized immediately after key derivation

5. **DEK random generation uses OS entropy**
   - `generate_nonce_24b()` and DEK wrapping use `rand::OsRng`
   - No hardcoded seeds; no weak RNGs

6. **Nonce uniqueness for same key**
   - Each XChaCha20-Poly1305 operation uses a unique 24-byte nonce
   - Random nonce generation ensures uniqueness with overwhelming probability (2^-96)

7. **No key reuse across different purposes**
   - KEK derived with specific HKDF info string
   - MACKEY derived with different info string
   - No shared keys across encryption/authentication

8. **Memory allocation is mlock'd**
   - All SecretBuf allocations are locked in RAM
   - No swapping to disk for sensitive data
   - Verified in unit tests (Unix platforms)

9. **Zeroization happens before deallocation**
   - Drop impl zeroizes entire buffer with volatile writes
   - No compiler optimizations remove the zeroization

10. **Authentication tag validation prevents forgery**
    - Every ciphertext includes Poly1305 tag
    - Verification is mandatory; no option to skip
    - Wrong key → tag verification failure → decryption fails (no partial decryption)

## Error Handling

All cryptographic operations return `Result<T, CryptoError>`:

```rust
#[derive(Debug)]
pub enum CryptoError {
    InvalidNonceLength,
    InvalidKeyLength,
    InvalidSaltLength,
    AuthenticationFailed,
    Argon2Error(String),
    HkdfError,
    InvalidAeadOutput,
}
```

- Errors are descriptive but do not leak key material
- No panics in cryptographic code (except for severe invariant violations)

## Performance Considerations

- Argon2id KDF: ~2–3 seconds per unlock (intentionally slow for passphrase hardening)
- XChaCha20-Poly1305: ~1–10 μs per 1 KiB (fast for normal usage)
- HMAC-SHA-256: < 1 μs per 1 KiB (very fast)
- Memory allocation (mlock): ~10 ms per 1 GiB (amortized, only during KDF)

## References & Standards

- **XChaCha20-Poly1305**: RFC 8439 (ChaCha20) extended to 192-bit nonce (IETF draft)
- **Argon2id**: RFC 9106, OWASP Password Storage Cheat Sheet
- **HKDF**: RFC 5869 (HMAC-based Extract-and-Expand Key Derivation Function)
- **HMAC**: RFC 2104
- **Constant-Time Comparison**: DJB's timing-safe comparison principles

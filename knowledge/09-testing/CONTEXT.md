# Testing Strategy Context

## Goal
Achieve **95%+ code coverage** with comprehensive scenario coverage across all modules, ensuring reliability and security of the encrypted credential manager.

## DDD Testing Approach

The Padlock project uses Domain-Driven Design testing principles, organizing tests by layer:

- **Unit Tests**: Domain logic and entity behavior (in-module)
- **Integration Tests**: Cross-module workflows (vault lifecycle, CRUD operations)
- **CLI Tests**: Full CLI invocation with real subprocess calls
- **Property Tests**: Crypto operations and serialization guarantees
- **Fuzzing**: Parser robustness (vault format, SSH agent messages, MessagePack)
- **Mutation Testing**: Test suite quality verification

## Test Levels

### 1. Unit Tests

**Location**: `#[cfg(test)] mod tests` within each module
**Purpose**: Verify domain logic and private functions

**Convention**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_<function>_<scenario>_<expected>() {
        // Arrange
        let input = setup();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

**Coverage**:
- Happy path execution
- Error cases and invariant violations
- Boundary conditions
- State transitions
- Private helper functions (encrypt/decrypt, hashing, validation)

**Example** (from `padlock-core/src/crypto.rs`):
```rust
#[test]
fn test_encrypt_entry_valid_key_succeeds() { }

#[test]
fn test_encrypt_entry_empty_plaintext_succeeds() { }

#[test]
fn test_decrypt_entry_wrong_key_fails() { }

#[test]
fn test_decrypt_entry_corrupted_ciphertext_fails() { }
```

### 2. Integration Tests

**Location**: `crates/padlock-core/tests/`
**Purpose**: Verify workflows across module boundaries

**Test Categories**:

#### A. Vault Lifecycle
- Create vault with master passphrase
- Open vault (correct passphrase)
- Open vault (wrong passphrase → error)
- Modify vault and save
- Load vault from disk
- Change master passphrase
- Export/import vaults

**File**: `tests/vault_lifecycle.rs`

#### B. Entry CRUD Operations
- Create entry (with all field types)
- Read entry (decrypts correctly)
- Update entry (modifies plaintext, re-encrypts)
- Delete entry (removed from vault)
- List entries (without decryption)
- Search entries (by tag, type)

**File**: `tests/entry_operations.rs`

#### C. Crypto Round-Trips
- Encrypt entry → decrypt entry → matches original
- Multiple entries with same passphrase
- Large entry (10MB plaintext)
- Special characters (unicode, control chars)
- Binary data (SSH keys, certificates)

**File**: `tests/crypto_round_trip.rs`

#### D. Filesystem Operations
- Vault file creation (permissions 0o600)
- Socket creation (permissions 0o700)
- Lock file handling (concurrent access)
- Atomic writes (no partial files on crash)
- Backup file creation (rotation)

**File**: `tests/filesystem_ops.rs`

#### E. SSH Agent Protocol
- Conformance to RFC draft (list keys, sign request)
- Concurrent agent connections
- Large key lists (1000+ entries)
- Malformed message handling

**File**: `tests/agent_protocol.rs`

**Test Naming**:
```
test_<module>_<function>_<scenario>_<expected>

Examples:
test_vault_open_correct_passphrase_succeeds
test_entry_crud_create_and_read_matches_original
test_crypto_aead_corrupted_ciphertext_fails
```

### 3. CLI Tests

**Framework**: `assert_cmd` + `predicates` crates
**Location**: `crates/padlock-cli/tests/`
**Purpose**: Verify full CLI invocation, exit codes, output

**Test Structure**:
```rust
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_cli_create_vault_succeeds() {
    let temp = TempDir::new().unwrap();
    let vault_path = temp.path().join("test.vault");

    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("create")
       .arg(&vault_path)
       .arg("--passphrase")
       .arg("test-passphrase");

    cmd.assert().success();
    assert!(vault_path.exists());
}

#[test]
fn test_cli_add_entry_invalid_json_fails() {
    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("add")
       .arg("--vault")
       .arg("test.vault")
       .arg("--data")
       .arg("{invalid json}");

    cmd.assert()
       .failure()
       .stderr(predicate::str::contains("JSON"));
}
```

**Coverage**:
- Create/open/save vault operations
- Add/update/delete entries
- List/search entries
- Export/import data
- Passphrase change
- Error messages (no secret leakage)
- Exit codes (0 = success, 1 = error, 2 = invalid args)

### 4. Property Tests

**Framework**: `proptest`
**Location**: Within module `#[cfg(test)]` or dedicated `tests/` files
**Purpose**: Verify invariants hold across arbitrary inputs

**Common Properties**:

#### A. Crypto Properties
```rust
proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip(plaintext in ".*") {
        let key = generate_test_key();
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn prop_different_nonces_different_ciphertexts(
        plaintext in ".*",
        nonce1 in any::<[u8; 12]>(),
        nonce2 in any::<[u8; 12]>()
    ) {
        prop_assume!(nonce1 != nonce2);
        let key = generate_test_key();
        let c1 = encrypt_with_nonce(&plaintext, &key, &nonce1).unwrap();
        let c2 = encrypt_with_nonce(&plaintext, &key, &nonce2).unwrap();
        prop_assert_ne!(c1, c2);
    }
}
```

#### B. Serialization Properties
```rust
proptest! {
    #[test]
    fn prop_entry_serialize_deserialize(entry in arbitrary_entry()) {
        let serialized = serde_json::to_vec(&entry).unwrap();
        let deserialized: Entry = serde_json::from_slice(&serialized).unwrap();
        prop_assert_eq!(entry, deserialized);
    }
}
```

#### C. Parsing Properties
```rust
proptest! {
    #[test]
    fn prop_vault_header_parse_roundtrip(
        version in 0..=255u8,
        flags in 0..=255u8
    ) {
        let header = VaultHeader::new(version, flags);
        let bytes = header.to_bytes();
        let parsed = VaultHeader::from_bytes(&bytes).unwrap();
        prop_assert_eq!(header, parsed);
    }
}
```

**Strategy**:
- Generate arbitrary but valid inputs
- Verify cryptographic properties (determinism, uniqueness, invertibility)
- Test boundary conditions systematically
- Run 1000+ iterations per property (configurable)

### 5. Fuzzing

**Framework**: `cargo-fuzz` with libFuzzer
**Location**: `crates/padlock-core/fuzz/`
**Purpose**: Discover crash and correctness bugs in parsers

**Fuzz Targets**:

#### A. Vault Format Parser
**File**: `fuzz/fuzz_targets/vault_parser.rs`
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use padlock_core::vault::Vault;

fuzz_target!(|data: &[u8]| {
    // Should not panic on any input
    let _ = Vault::from_bytes(data);
});
```

#### B. SSH Agent Protocol Parser
**File**: `fuzz/fuzz_targets/agent_protocol.rs`
```rust
fuzz_target!(|data: &[u8]| {
    let _ = AgentMessage::parse(data);
});
```

#### C. MessagePack Decoder
**File**: `fuzz/fuzz_targets/msgpack_decoder.rs`
```rust
fuzz_target!(|data: &[u8]| {
    let _ = rmp_serde::from_slice::<Entry>(data);
});
```

**Execution**:
```bash
# Run single target for 10 minutes
cargo fuzz run vault_parser -- -max_len=16384 -timeout=10

# Run all fuzz targets
for target in fuzz/fuzz_targets/*.rs; do
    cargo fuzz run $(basename "$target" .rs) -- -max_len=16384
done
```

**Corpus Management**:
- Store interesting inputs in `fuzz/corpus/<target>/`
- Commit to Git for regression detection
- Minimize crash cases with `cargo fuzz cmin`

### 6. Mutation Testing

**Framework**: `cargo-mutants`
**Location**: Repository-wide
**Purpose**: Verify test suite catches real bugs

**Execution**:
```bash
# Run mutation testing (generates 100+ mutants by default)
cargo mutants --timeout 30

# Check which mutations survived (tests didn't catch)
cargo mutants --timeout 30 | grep "survived"

# Generate HTML report
cargo mutants --timeout 30 --output html-report
```

**Target**: <1% mutation survival rate (i.e., 99%+ of mutations killed)

**Mutant Types Detected**:
- Remove assertion (should fail test)
- Flip boolean condition (test catches logic error)
- Replace operator (+/-, &/|) (arithmetic/logic error)
- Delete statement (missing operation)
- Change constant value (boundary error)

## Test Naming Convention

```
test_<module>_<function>_<scenario>_<expected>
```

**Examples**:
- `test_crypto_encrypt_empty_plaintext_succeeds`
- `test_vault_open_wrong_passphrase_fails`
- `test_agent_list_keys_large_list_succeeds`
- `test_entry_crud_create_with_unicode_tags_succeeds`
- `test_cli_add_entry_invalid_json_stderr_has_location`

## Test Utilities Crate

**Crate**: `crates/padlock-test-utils/`

**Purpose**: Reusable test helpers and fixtures

**Exports**:

### A. Vault Builders
```rust
pub struct TestVaultBuilder {
    entries: Vec<TestEntry>,
    passphrase: String,
}

impl TestVaultBuilder {
    pub fn new() -> Self { }
    pub fn with_entry(mut self, name: &str, value: &str) -> Self { }
    pub fn with_password_entry(mut self, username: &str, password: &str) -> Self { }
    pub fn with_ssh_entry(mut self, key_name: &str, private_key: &[u8]) -> Self { }
    pub fn with_passphrase(mut self, passphrase: &str) -> Self { }
    pub fn build(self) -> Vault { }
    pub fn save(self, path: &Path) -> Vault { }
}
```

**Usage**:
```rust
let vault = TestVaultBuilder::new()
    .with_password_entry("admin", "secret123")
    .with_passphrase("test-pass")
    .build();
```

### B. Key Generators
```rust
pub fn generate_test_master_key() -> MasterKey { }
pub fn generate_test_rsa_keypair() -> (String, String) { }
pub fn generate_test_ed25519_keypair() -> (String, String) { }
pub fn test_encryption_key() -> EncryptionKey { }
pub fn test_hmac_key() -> HmacKey { }
```

### C. Temporary Directories
```rust
pub fn temp_vault_dir() -> TempDir { }
pub fn temp_vault_path() -> PathBuf { }
pub fn with_test_vault<F>(f: F)
where F: FnOnce(PathBuf) { }
```

### D. Assertions
```rust
pub fn assert_vault_integrity(vault: &Vault) -> Result<()> { }
pub fn assert_entry_decrypts(entry: &Entry, key: &MasterKey) { }
pub fn assert_no_plaintext_in_memory(data: &[u8]) { }
pub fn assert_file_permissions(path: &Path, expected: u32) { }
```

**Location in Cargo.toml**:
```toml
[dev-dependencies]
padlock-test-utils = { path = "../padlock-test-utils" }
```

## Coverage Reporting

**Tool**: `cargo-llvm-cov`
**Language**: Rust LLVM coverage

**Installation**:
```bash
cargo install cargo-llvm-cov
```

**Generate Coverage**:
```bash
# Create HTML report
cargo llvm-cov --workspace --html

# Show in terminal
cargo llvm-cov --workspace

# Generate with specific test filter
cargo llvm-cov --package padlock-core --lib test_vault
```

**Target**:
- Overall: ≥95% line coverage
- Crypto modules: 100% coverage (no untested paths)
- CLI: ≥90% coverage (some error paths hard to trigger)
- Exception: Platform-specific code (conditional compilation)

**Report Location**: `target/llvm-cov/html/index.html`

**CI Integration**:
- Generate on every PR
- Fail if coverage drops below 95%
- Comment on PR with coverage delta

## Security-Specific Tests

Referenced from SYSTEM_DESIGN.md §11.3

### 1. Crypto Round-Trip Test Suite

**File**: `padlock-core/tests/security_crypto.rs`

```rust
#[test]
fn test_security_crypto_all_entry_types_roundtrip() {
    // Test password, SSH key, API token, certificate entries
}

#[test]
fn test_security_crypto_unicode_plaintext_survives_roundtrip() {
    let plaintext = "密码 🔐 p@ssw0rd\n\0";
    // Verify binary safety
}

#[test]
fn test_security_crypto_10mb_entry_roundtrip() {
    // Large entry handling
}
```

### 2. Wrong Passphrase Rejection

**File**: `padlock-core/tests/security_auth.rs`

```rust
#[test]
fn test_security_wrong_passphrase_rejected() {
    let vault = create_test_vault("correct-pass");
    assert!(vault.open("wrong-pass").is_err());
}

#[test]
fn test_security_passphrase_timing_constant() {
    // Measure time to reject various wrong passphrases
    // Ensure no timing leakage
}
```

### 3. Vault Corruption Detection

**File**: `padlock-core/tests/security_integrity.rs`

```rust
#[test]
fn test_security_vault_corruption_single_byte_flip_detected() {
    let vault_bytes = vault.to_bytes();
    for byte_idx in 0..vault_bytes.len() {
        let mut corrupted = vault_bytes.clone();
        corrupted[byte_idx] ^= 0xFF; // Flip all bits

        let result = Vault::from_bytes(&corrupted);
        assert!(result.is_err(), "Corruption at byte {} not detected", byte_idx);
    }
}

#[test]
fn test_security_vault_corruption_hmac_fails() {
    // Verify HMAC-SHA256 catches tampering
}
```

### 4. Entry Tampering Detection (AEAD Tag)

**File**: `padlock-core/tests/security_aead.rs`

```rust
#[test]
fn test_security_entry_tampering_aead_tag_fails() {
    let vault = create_test_vault_with_entry("password", "secret123");
    let entry = vault.entries[0].clone();

    // Flip a bit in the ciphertext
    let mut corrupted = entry.ciphertext.clone();
    corrupted[100] ^= 0x01;

    let result = decrypt(&corrupted, &entry.nonce, &key);
    assert!(result.is_err(), "AEAD tag did not catch tampering");
}
```

### 5. Nonce Uniqueness

**File**: `padlock-core/tests/security_nonce.rs`

```rust
#[test]
fn test_security_nonce_uniqueness_1m_encryptions() {
    let key = generate_test_key();
    let mut nonces = HashSet::new();

    for i in 0..1_000_000 {
        let plaintext = format!("entry_{}", i);
        let (ciphertext, nonce) = encrypt(&plaintext, &key).unwrap();

        assert!(
            nonces.insert(nonce.clone()),
            "Nonce collision detected at iteration {}",
            i
        );
    }
}
```

### 6. Memory Zeroing Verification

**File**: `padlock-core/tests/security_memory.rs`

```rust
#[test]
fn test_security_memory_plaintext_zeroed_after_decrypt() {
    // Use miri or direct memory inspection to verify
    // zeroize::Zeroize implementation
}

#[test]
fn test_security_memory_master_key_never_printed() {
    // Verify Debug/Display implementations don't leak key
}
```

### 7. SSH Agent Protocol Conformance

**File**: `padlock-core/tests/security_agent.rs`

```rust
#[test]
fn test_security_agent_list_keys_conforms_to_spec() {
    // Match RFC draft-miller-ssh-agent-00
}

#[test]
fn test_security_agent_sign_request_signature_valid() {
    // Verify SSH signature on arbitrary data
}

#[test]
fn test_security_agent_malformed_message_rejected() {
    // Invalid message format doesn't crash agent
}
```

### 8. Concurrent Agent Access

**File**: `padlock-core/tests/security_concurrency.rs`

```rust
#[test]
fn test_security_agent_concurrent_connections() {
    // Spawn 100 concurrent agent clients
    // Verify all requests succeed without corruption
}

#[test]
fn test_security_vault_concurrent_reads_same_key() {
    // Multiple threads read same entry
    // Verify decryptions match
}
```

### 9. Atomic Write Recovery

**File**: `padlock-core/tests/security_atomicity.rs`

```rust
#[test]
fn test_security_atomic_write_kill_during_write_no_corruption() {
    // Spawn process writing vault
    // Kill at random point during write
    // Verify vault either fully updated or reverted
}
```

### 10. Passphrase Change Integrity

**File**: `padlock-core/tests/security_passphrase.rs`

```rust
#[test]
fn test_security_passphrase_change_all_entries_readable() {
    let vault = create_test_vault("old-pass");
    vault.add_entry(create_test_entry("secret"));

    vault.change_passphrase("old-pass", "new-pass").unwrap();

    let reopened = Vault::open(&vault_path, "new-pass").unwrap();
    assert_eq!(reopened.entries[0].decrypt("new-pass"), "secret");
}

#[test]
fn test_security_passphrase_change_old_passphrase_fails() {
    vault.change_passphrase("old", "new").unwrap();
    assert!(Vault::open(&path, "old").is_err());
}
```

## Test Dependencies

**In `Cargo.toml`**:

```toml
[dev-dependencies]
# CLI testing
assert_cmd = "2.0"
predicates = "3.0"

# Property testing
proptest = "1.0"

# Test utilities
tempfile = "3.0"
rand = "0.8"

# Crypto testing
zeroize = { version = "1.0", features = ["derive"] }
hex = "0.4"

# Test utils crate
padlock-test-utils = { path = "../padlock-test-utils" }

# Coverage (local only)
[profile.coverage]
inherits = "dev"
```

**Fuzzing** (in `Cargo.toml`):
```toml
[dev-dependencies]
libfuzzer-sys = "0.4"
```

**Mutation Testing**:
```bash
cargo install cargo-mutants
```

## Running Tests

**All tests**:
```bash
cargo test --workspace
```

**Specific level**:
```bash
cargo test --lib                    # Unit tests only
cargo test --test '*'               # Integration tests
cargo test --package padlock-cli    # CLI tests
```

**With output**:
```bash
cargo test -- --nocapture          # Print stdout/stderr
cargo test -- --test-threads=1    # Sequential (easier debugging)
```

**Coverage report**:
```bash
cargo llvm-cov --workspace --html
open target/llvm-cov/html/index.html
```

**Fuzzing**:
```bash
cargo fuzz run vault_parser -- -max_len=16384
```

**Mutation testing**:
```bash
cargo mutants --timeout 30
open html-report/index.html
```

## Test Quality Gates

All tests must pass with:
1. `cargo test --all-features`
2. `cargo test --no-default-features`
3. Coverage ≥95%
4. Mutation survival <1%
5. Zero clippy warnings
6. All fuzz targets complete without crashes

These tests form the foundation of security verification for Padlock.

# Padlock Project Context

**Version:** 1.0
**Last Updated:** 2026-02-07
**Audience:** Implementation teams, code reviewers, future maintainers

This document provides architectural and organizational context for the Padlock credential manager project. It covers workspace structure, coding conventions, dependency management, module organization, error handling patterns, and how we use traits for domain-driven design.

---

## Cargo Workspace Layout

Padlock is organized as a Cargo workspace with three crates:

```
padlock/
├── Cargo.toml                          # Workspace root (defines members and settings)
├── crates/
│   ├── padlock-core/
│   │   ├── Cargo.toml                  # Core library (no_std compatible, pure Rust)
│   │   ├── src/
│   │   │   ├── lib.rs                  # Library root; public module tree
│   │   │   ├── crypto/
│   │   │   ├── vault/
│   │   │   ├── entries/
│   │   │   ├── ssh_agent/
│   │   │   ├── signing/
│   │   │   ├── sync/
│   │   │   ├── audit/
│   │   │   ├── generate/
│   │   │   ├── traits/
│   │   │   ├── types/
│   │   │   └── error.rs                # Error types (thiserror)
│   │   └── tests/                      # Integration tests
│   │
│   ├── padlock-cli/
│   │   ├── Cargo.toml                  # CLI binary crate
│   │   ├── src/
│   │   │   ├── main.rs                 # CLI entry point
│   │   │   ├── commands/               # Command implementations
│   │   │   ├── ui/                     # User interaction (prompts, formatting)
│   │   │   ├── config/                 # CLI-specific config
│   │   │   └── error.rs                # Error types (anyhow)
│   │   └── tests/                      # CLI integration tests
│   │
│   └── padlock-test-utils/
│       ├── Cargo.toml                  # Test utilities library
│       ├── src/
│       │   ├── lib.rs
│       │   ├── fixtures.rs             # Test data generators
│       │   ├── vault.rs                # Mock/test vault setup
│       │   └── mocks.rs                # Mock implementations of traits
│       └── tests/
│
├── docs/                                # Documentation
│   ├── MVP_SCOPE.md                    # Feature scope and design decisions
│   ├── ARCHITECTURE.md                 # High-level architecture
│   ├── THREAT_MODEL.md                 # Security threat model
│   └── ...
│
├── knowledge/                           # Knowledge base for Claude Code
│   ├── 00-project/
│   │   └── CONTEXT.md                  # This file
│   ├── 01-crypto/
│   │   └── CRYPTO_DECISIONS.md         # Cryptographic algorithm choices
│   ├── 02-vault/
│   │   ├── VAULT_FORMAT.md             # On-disk vault file format
│   │   └── VAULT_OPERATIONS.md         # Vault lifecycle semantics
│   ├── 03-ssh-agent/
│   │   └── SSH_AGENT_PROTOCOL.md       # SSH agent implementation notes
│   └── ...
│
└── scripts/                             # Build and deployment scripts
    ├── ci.sh
    ├── test.sh
    └── ...
```

### Why This Structure?

1. **padlock-core:** Pure Rust, dependency-minimal library. Implements all cryptographic operations, vault logic, and trait abstractions. No platform-specific code here (abstracted via traits).

2. **padlock-cli:** Binary crate that uses padlock-core. Contains all CLI logic, user interaction, and error handling for CLI-specific scenarios. Depends on padlock-core + anyhow for error handling.

3. **padlock-test-utils:** Shared test utilities and fixtures. Prevents duplication across padlock-core and padlock-cli tests. Uses padlock-core as dependency.

---

## Naming Conventions

### Module Names
- Use **snake_case** for all module names (Rust convention).
- Module name reflects the primary responsibility.
- Examples:
  - `crypto` — Cryptographic operations (AES-GCM, Argon2, random generation).
  - `vault` — Vault initialization, unlock, lock, storage operations.
  - `entries` — Credential entry management (CRUD).
  - `ssh_agent` — SSH agent protocol implementation.
  - `signing` — Git SSH signing, signature generation.
  - `audit` — Audit event logging.
  - `generate` — Password/token generation.
  - `traits` — Domain-driven design trait definitions.
  - `types` — Domain types (Credential, VaultKey, etc.).
  - `error` — Error type definitions.

### Type Names
- Use **PascalCase** for all public types (Rust convention).
- Be explicit about the type's role. Examples:
  - `Vault` — The main vault object.
  - `Credential` — A single credential entry.
  - `CredentialKind` — Enum of credential types (SSH key, password, TOTP secret, etc.).
  - `AuditEvent` — A single audit log event.
  - `VaultKey` — The derived encryption key for vault data.
  - `StorageBackend` — Trait for vault storage.
  - `PlatformKeyring` — Trait for OS-level keyring integration.
  - `UserConfirmation` — Trait for user interaction/prompts.
  - `SyncTransport` — Trait for sync protocol (deferred, but defined early).

### Function/Method Names
- Use **snake_case** for function and method names.
- Verb-first for actions. Examples:
  - `create_credential()` — Create a new credential.
  - `unlock_vault()` — Unlock the vault with a master password.
  - `derive_key()` — Derive encryption key from password.
  - `sign_commitment()` — Create a signature over a commitment.
  - `generate_totp()` — Generate a TOTP code.

### Test Names
- All test functions are in a `tests` submodule in each file (or `tests/` directory at crate level).
- Test function names follow pattern: `test_<what>_<scenario>_<expectation>`.
- Examples:
  - `test_vault_unlock_with_correct_password_succeeds()`
  - `test_derive_key_from_weak_password_still_produces_valid_key()`
  - `test_ssh_agent_signature_matches_openssl_verification()`
  - `test_audit_log_contains_all_operations()`

### Configuration Constants
- Use **SCREAMING_SNAKE_CASE** for constants (especially in config modules).
- Examples:
  - `ARGON2_TIME_COST = 2`
  - `ARGON2_MEMORY_MB = 65536`
  - `VAULT_LOCK_TIMEOUT_SECS = 3600`
  - `MAX_PASSWORD_LENGTH = 4096`

---

## Dependency Management

### Version Pinning Strategy

**Rule:** All `padlock-core` dependencies must be pinned to a specific version in `Cargo.toml`. No wildcard versions like `^1.0` or `*`.

**Rationale:**
- Security-critical library; supply chain attacks are real.
- Pinned versions allow auditing and freezing of dependency set.
- Wildcard versions can introduce unvetted patches.

**Example:**
```toml
[dependencies]
argon2 = "=0.5.2"           # Exact version, not ^0.5
aes-gcm = "=0.10.3"         # Exact version
zeroize = "=1.6.1"          # Exact version
thiserror = "=1.0.50"       # Exact version
```

### Dependency Vetted Set
- All dependencies for `padlock-core` must be approved via `cargo-vet`.
- Process:
  1. Add dependency to `Cargo.toml`.
  2. Run `cargo vet` to verify the crate has been vetted by the community.
  3. If not vetted, review the crate code manually or defer to v1.1.
  4. Document the vetting decision in `SECURITY_AUDIT.md`.

### Dependency Deny
- Use `cargo-deny` to prevent known-vulnerable dependencies.
- Configuration file: `deny.toml` at workspace root.
- All CI builds run `cargo deny check` before compilation.
- Example violations:
  - Crates with known CVEs.
  - Crates with RUSTSEC advisories.
  - Crates with GPL/copyleft licenses (if project is not compatible).

### Feature Flags
- `padlock-core` should be built with **minimal default features**.
- Feature matrix (defined in `padlock-core/Cargo.toml`):
  - `default = []` — Minimal, no experimental features.
  - `async` — Async/await support (for future sync module).
  - `std` — Standard library (enabled by default; can be disabled for embedded/no_std).
  - `unstable-crypto` — Experimental/post-quantum crypto (disabled by default).
  - `test-utils` — Internal testing utilities (dev-only).

- CLI crate enables features as needed: `padlock-core = { path = "../padlock-core", features = ["std"] }`.

---

## Feature Flags Strategy

### Core Architecture
- **`std` (default):** Uses Rust std library. Enabled for all platforms.
- **`async` (optional):** Provides async/await APIs for sync module. Not enabled in MVP (sync is deferred).
- **`test-utils` (dev-only):** Provides mock implementations and test fixtures. Only available in test/bench targets.

### How to Add a New Feature
1. Define in `Cargo.toml` under `[features]`.
2. Use `#[cfg(feature = "...")]` to conditionally compile code.
3. Ensure tests cover both feature-enabled and feature-disabled paths.
4. Document the feature's purpose in `ARCHITECTURE.md`.

### Example: Adding `async` Feature
```toml
# In padlock-core/Cargo.toml
[features]
default = []
std = []
async = ["tokio"]

[dependencies]
tokio = { version = "=1.35.0", optional = true }
```

```rust
// In padlock-core/src/sync/transport.rs
#[cfg(feature = "async")]
pub async fn sync_with_remote() -> Result<()> { ... }

#[cfg(not(feature = "async"))]
pub fn sync_with_remote() -> Result<()> {
    Err(Error::FeatureDisabled("async sync"))
}
```

---

## Module Structure for padlock-core

### `crypto/` Module
**Purpose:** Cryptographic operations (encryption, key derivation, random generation, hashing).

**Key Exports:**
- `derive_vault_key()` — Derive encryption key from master password (Argon2id).
- `encrypt_credential()` — Encrypt credential using AES-256-GCM.
- `decrypt_credential()` — Decrypt credential.
- `generate_secure_random()` — Generate cryptographically secure random bytes.
- `hash_password()` — Hash password for verification.

**Dependencies:** `argon2`, `aes-gcm`, `rand`, `sha2`, `zeroize`.

**No Public Dependencies on:** Anything platform-specific or network-related.

### `vault/` Module
**Purpose:** Vault lifecycle (initialization, locking, unlocking, storage interaction).

**Key Exports:**
- `Vault` — Main vault struct. Represents an unlocked vault in memory.
- `VaultConfig` — Configuration for vault (name, path, keyring backend, etc.).
- `VaultBuilder` — Builder for constructing a vault.
- `init_vault()` — Create a new vault.
- `unlock_vault()` — Unlock an existing vault with master password.
- `lock_vault()` — Lock the vault (clear in-memory secrets).

**Traits Used:**
- `StorageBackend` — Trait for reading/writing vault files. Implemented for local filesystem; can be mocked for tests.
- `PlatformKeyring` — Trait for OS-level keyring (defer to v1.1; MVP has no-op impl).

**Internal State:**
- In-memory decrypted credentials (cleared on lock).
- Derived encryption key (cleared on lock).
- Metadata (vault ID, creation time, last unlock time).

### `entries/` Module
**Purpose:** Credential CRUD operations (create, read, update, delete).

**Key Exports:**
- `Credential` — Struct representing a single credential (ID, kind, metadata, encrypted data).
- `CredentialKind` — Enum: `SshKey`, `Password`, `TotpSecret`, `ApiKey`, `Custom`.
- `CredentialMetadata` — Timestamps, tags, notes.
- `create_credential()` — Create new credential in vault.
- `read_credential()` — Load credential from vault.
- `update_credential()` — Update credential data and metadata.
- `delete_credential()` — Remove credential from vault.
- `list_credentials()` — List all credentials (names and kinds only, not decrypted data).

**Error Handling:**
- Returns `Result<T, Error>` (using `thiserror`).
- Specific error variants: `CredentialNotFound`, `InvalidCredentialKind`, `AlreadyExists`.

### `ssh_agent/` Module
**Purpose:** SSH agent protocol implementation (RFC 4251). Allow SSH clients to use vault keys.

**Key Exports:**
- `SshAgentServer` — Listens on Unix socket, handles SSH agent protocol.
- `SshAgentProtocol` — Low-level protocol serialization/deserialization.
- `SshPublicKey` — Extracted public key from private key.
- `ssh_sign_request()` — Handle SSH signature request (from agent client).
- `ssh_list_identities()` — Enumerate keys available in vault.

**Protocol Details:**
- Listens on `~/.padlock/agent.sock` (Unix socket, not networked).
- Implements subset of SSH agent protocol: key listing, signing, identity removal.
- Does NOT implement key addition (vault is the source of truth, not the agent).

**Security:**
- Socket is protected with filesystem permissions (0600).
- All signature requests are logged in audit log.
- Time-based timeout for agent socket (if unlocked vault idle for N seconds, socket closes).

### `signing/` Module
**Purpose:** Git SSH signing and signature generation.

**Key Exports:**
- `sign_git_commit()` — Create OpenSSH signature over Git commit.
- `sign_data()` — Create OpenSSH signature over arbitrary data.
- `verify_signature()` — Verify an OpenSSH signature (for testing).
- `SshSignatureFormat` — Encapsulates OpenSSH signature format (algorithm, signature bytes).

**Integration with Git:**
- Designed to be used with Git's `gpg.ssh.program` config.
- Takes commit bytes as stdin, outputs signature as stdout.

**Signature Format:**
- Uses OpenSSH signature format (RFC 8332-like), not raw SSH agent protocol.
- Includes algorithm OID (e.g., "ssh-rsa-sha2-256"), signature bytes, namespace.

### `sync/` Module
**Purpose:** Vault synchronization (DEFERRED to v1.1; not in MVP scope).

**Placeholders:**
- `SyncTransport` trait — Abstract over sync transport (will be implemented for cloud provider, P2P, etc.).
- `sync_vault()` function signature (not implemented; raises "Not implemented" error).
- `ConflictResolver` trait — How to handle sync conflicts (placeholder).

**Future Design:**
- Sync should use end-to-end encryption (vault key remains on local machine).
- Consider time-based vector clocks or operational transformation for conflict resolution.
- Placeholder code allows architecture to be reviewed before implementation.

### `audit/` Module
**Purpose:** Audit event logging (all vault operations logged for compliance and forensics).

**Key Exports:**
- `AuditEvent` — Struct representing a single audit event (timestamp, user, action, resource, result).
- `AuditLog` — Manages writing events to log file (JSON Lines format).
- `AuditAction` — Enum: `VaultInit`, `VaultUnlock`, `VaultLock`, `CredentialCreate`, `CredentialRead`, `CredentialUpdate`, `CredentialDelete`, `SshSign`, `SshListKeys`, etc.
- `log_event()` — Write an audit event.
- `read_audit_log()` — Read and parse audit log file.

**Audit Log Format:**
- JSON Lines (one JSON object per line).
- Schema: `{ "timestamp": "2026-02-07T...", "user": "...", "action": "...", "resource": { ... }, "result": "success" | "failure", "error": "..." }`.
- Log file: `~/.padlock/audit.log` (path configurable).
- Log file is always writable, even when vault is locked.

**Logging Guarantees:**
- Every operation is logged (success and failure).
- Logs are durable (flushed to disk).
- No sensitive data in logs (only resource IDs/names, not secrets).

### `generate/` Module
**Purpose:** Credential generation (passwords, TOTP secrets, SSH keys).

**Key Exports:**
- `generate_password()` — Generate a strong random password.
- `PasswordPolicy` — Struct defining password requirements (length, character classes, forbidden patterns).
- `generate_totp_secret()` — Generate a random TOTP secret (base32-encoded).
- `generate_ssh_key_pair()` — Generate a new Ed25519 SSH key pair (or RSA for legacy systems).

**Sensible Defaults:**
- Password: 32 characters, alphanumeric + symbols.
- TOTP secret: 32 bytes (standard for TOTP).
- SSH key: Ed25519 (modern, small, secure); fallback to RSA 4096 if client requires.

### `traits/` Module
**Purpose:** Domain-driven design (DDD) traits. Abstract over external systems to keep core logic testable and platform-agnostic.

**Key Trait Definitions:**

#### `StorageBackend`
```rust
pub trait StorageBackend: Send + Sync {
    fn write_credential(&self, id: &str, encrypted_data: &[u8]) -> Result<()>;
    fn read_credential(&self, id: &str) -> Result<Vec<u8>>;
    fn delete_credential(&self, id: &str) -> Result<()>;
    fn list_credential_ids(&self) -> Result<Vec<String>>;
    fn write_vault_config(&self, config_data: &[u8]) -> Result<()>;
    fn read_vault_config(&self) -> Result<Vec<u8>>;
}
```
- Implementations: `FilesystemBackend` (prod), `InMemoryBackend` (tests).
- Injected into `Vault` at construction.

#### `PlatformKeyring`
```rust
pub trait PlatformKeyring: Send + Sync {
    fn get_key(&self, identifier: &str) -> Result<Vec<u8>>;
    fn set_key(&self, identifier: &str, key: &[u8]) -> Result<()>;
    fn delete_key(&self, identifier: &str) -> Result<()>;
    fn is_available(&self) -> bool;
}
```
- Implementations: `NoOpKeyring` (MVP), `MacOSKeychain` (v1.1), `LinuxSecretService` (v1.1).
- Allows vault to optionally store encryption keys in OS keyring (deferred).

#### `UserConfirmation`
```rust
pub trait UserConfirmation: Send + Sync {
    fn prompt_password(&self, prompt: &str) -> Result<String>;
    fn prompt_yes_no(&self, prompt: &str) -> Result<bool>;
    fn show_message(&self, message: &str) -> Result<()>;
}
```
- Implementations: `InteractivePrompt` (CLI), `NonInteractivePrompt` (scripting/automation).
- Allows vault to request user interaction without knowing about CLI.

#### `SyncTransport`
```rust
pub trait SyncTransport: Send + Sync {
    fn pull(&self) -> Result<Vec<u8>>;
    fn push(&self, data: &[u8]) -> Result<()>;
    fn get_remote_version(&self) -> Result<u64>;
}
```
- Placeholder for future sync implementation.
- Implementations will be added in v1.1.

### `types/` Module
**Purpose:** Core domain types (used across multiple modules).

**Key Exports:**
- `Credential` — Main credential struct.
- `CredentialKind` — Enum of credential types.
- `CredentialMetadata` — Timestamps, tags, notes.
- `VaultId` — UUID for vault instance.
- `VaultKey` — The derived encryption key (securely zeroized on drop).
- `AuditEvent` — Audit log entry.
- `SshPublicKey` — Public key extracted from private key.
- `TotpConfig` — TOTP parameters (secret, algorithm, time step, digits).

**Invariants:**
- All types implement `Debug` only when `#[cfg(test)]` (prevents accidental logging of secrets).
- All types that contain secrets implement `Zeroize` (via `zeroize` crate).
- All types are serializable (via `serde`; used for JSON audit logs and encrypted storage).

### `error.rs` Module
**Purpose:** Error types for padlock-core (using `thiserror`).

**Error Enum:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vault not found at {path}")]
    VaultNotFound { path: String },

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Credential not found: {id}")]
    CredentialNotFound { id: String },

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid SSH key format: {0}")]
    InvalidSshKey(String),

    #[error("Audit log error: {0}")]
    AuditError(String),

    // ... more variants
}
```

**Error Handling Rules:**
- All fallible operations return `Result<T, Error>`.
- Errors are specific (not generic "Error" strings).
- CLI layer (padlock-cli) converts `Error` to `anyhow::Error` for display.

---

## Error Handling Patterns

### In padlock-core (Library)
- **Use `thiserror`** for error types.
- Define a single `Error` enum in `error.rs`.
- All public functions return `Result<T, Error>`.
- Errors are variants of the enum (specific, not strings).

**Example:**
```rust
// In padlock-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vault locked")]
    VaultLocked,

    #[error("Invalid password")]
    InvalidPassword,
}

// In padlock-core/src/vault/mod.rs
pub fn unlock_vault(password: &str) -> Result<Vault, Error> {
    // ...
    if password_incorrect {
        return Err(Error::InvalidPassword);
    }
    // ...
}
```

### In padlock-cli (Binary)
- **Use `anyhow`** for error handling.
- Convert padlock-core errors to anyhow errors using `?` operator.
- Add context where helpful using `.context()`.

**Example:**
```rust
// In padlock-cli/src/commands/unlock.rs
pub fn cmd_unlock(password: &str) -> anyhow::Result<()> {
    let vault = padlock_core::unlock_vault(password)
        .context("Failed to unlock vault")?;

    println!("Vault unlocked!");
    Ok(())
}
```

### In Tests
- Use `assert!`, `assert_eq!`, `expect()` for simple cases.
- Use `Result<T, Box<dyn std::error::Error>>` return type for integration tests.
- Provide clear failure messages.

**Example:**
```rust
#[test]
fn test_unlock_vault_with_invalid_password() {
    let vault = init_test_vault("correct_password").expect("setup");
    let result = unlock_vault(&vault, "wrong_password");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPassword));
}
```

---

## How Traits Are Used for DDD Abstraction

### Domain-Driven Design (DDD) Principles
1. **Ubiquitous Language:** Types and functions use domain terminology (e.g., `Vault`, `Credential`, `SshKey`).
2. **Bounded Context:** padlock-core is a single bounded context; traits define boundaries with external systems.
3. **Dependency Inversion:** Core logic depends on abstractions (traits), not concrete implementations.

### Concrete Pattern: Storage Abstraction

**Problem:** Vault needs to persist credentials to disk, but core logic shouldn't know about filesystems, APIs, or database schemas.

**Solution:** `StorageBackend` trait abstracts storage.

```rust
// In padlock-core/src/traits/storage.rs
pub trait StorageBackend: Send + Sync {
    fn write_credential(&self, id: &str, encrypted_data: &[u8]) -> Result<()>;
    fn read_credential(&self, id: &str) -> Result<Vec<u8>>;
    fn list_credential_ids(&self) -> Result<Vec<String>>;
}

// Production implementation (in padlock-core/src/vault/filesystem.rs)
pub struct FilesystemBackend {
    vault_dir: PathBuf,
}

impl StorageBackend for FilesystemBackend {
    fn write_credential(&self, id: &str, data: &[u8]) -> Result<()> {
        let path = self.vault_dir.join(format!("{}.enc", id));
        std::fs::write(&path, data)?;
        Ok(())
    }
    // ...
}

// Test implementation (in padlock-test-utils/src/mocks.rs)
pub struct InMemoryBackend {
    credentials: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl StorageBackend for InMemoryBackend {
    fn write_credential(&self, id: &str, data: &[u8]) -> Result<()> {
        self.credentials.lock().unwrap().insert(id.to_string(), data.to_vec());
        Ok(())
    }
    // ...
}

// Usage in Vault struct
pub struct Vault {
    storage: Box<dyn StorageBackend>,
    // ...
}

impl Vault {
    pub fn new(storage: Box<dyn StorageBackend>) -> Self {
        Vault { storage, ... }
    }

    pub fn create_credential(&mut self, credential: Credential) -> Result<()> {
        let encrypted = self.encrypt_credential(&credential)?;
        self.storage.write_credential(&credential.id, &encrypted)?;
        Ok(())
    }
}
```

**Benefits:**
- Core vault logic is independent of filesystem, database, cloud storage, etc.
- Tests inject `InMemoryBackend` for speed and isolation.
- Production uses `FilesystemBackend`.
- Future: Can add `CloudStorageBackend` without changing vault logic.

### Concrete Pattern: User Interaction Abstraction

**Problem:** Vault needs to ask user for password, confirmations, or display messages, but core logic shouldn't know about CLI, GUI, TUI, etc.

**Solution:** `UserConfirmation` trait abstracts user interaction.

```rust
// In padlock-core/src/traits/user.rs
pub trait UserConfirmation: Send + Sync {
    fn prompt_password(&self, prompt: &str) -> Result<String>;
    fn prompt_yes_no(&self, prompt: &str) -> Result<bool>;
}

// CLI implementation
pub struct CliPrompt;

impl UserConfirmation for CliPrompt {
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        eprint!("{}", prompt);
        // Read password from stdin without echo
        let password = rpasswor::read_password()?;
        Ok(password)
    }

    fn prompt_yes_no(&self, prompt: &str) -> Result<bool> {
        eprint!("{} (y/n): ", prompt);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(input.trim().eq_ignore_ascii_case("y"))
    }
}

// Non-interactive implementation (for scripting)
pub struct NonInteractivePrompt {
    password: String,
}

impl UserConfirmation for NonInteractivePrompt {
    fn prompt_password(&self, _prompt: &str) -> Result<String> {
        Ok(self.password.clone())
    }

    fn prompt_yes_no(&self, _prompt: &str) -> Result<bool> {
        Err(Error::NonInteractiveMode.into())
    }
}

// Usage in vault initialization
pub fn init_vault(
    name: &str,
    storage: Box<dyn StorageBackend>,
    user: Arc<dyn UserConfirmation>,
) -> Result<Vault> {
    let password = user.prompt_password("Master password: ")?;
    // ... rest of init logic
}
```

**Benefits:**
- Core logic doesn't depend on CLI or any UI framework.
- Same vault code works with interactive CLI, non-interactive scripts, TUI, or future GUI.
- Tests can provide mock implementations that return fixed passwords.

### Concrete Pattern: Platform Keyring Abstraction

**Problem:** v1.1 will integrate with OS keyrings (macOS Keychain, Linux Secret Service), but core logic shouldn't have platform-specific code.

**Solution:** `PlatformKeyring` trait abstracts keyring.

```rust
// In padlock-core/src/traits/keyring.rs
pub trait PlatformKeyring: Send + Sync {
    fn get_key(&self, identifier: &str) -> Result<Vec<u8>>;
    fn set_key(&self, identifier: &str, key: &[u8]) -> Result<()>;
    fn is_available(&self) -> bool;
}

// MVP implementation (no-op)
pub struct NoOpKeyring;

impl PlatformKeyring for NoOpKeyring {
    fn get_key(&self, _identifier: &str) -> Result<Vec<u8>> {
        Err(Error::NotSupported("Keyring not available in MVP").into())
    }

    fn set_key(&self, _identifier: &str, _key: &[u8]) -> Result<()> {
        Ok(()) // Silent no-op
    }

    fn is_available(&self) -> bool { false }
}

// Future implementation (v1.1)
#[cfg(target_os = "macos")]
pub struct MacOSKeychain;

#[cfg(target_os = "macos")]
impl PlatformKeyring for MacOSKeychain {
    fn get_key(&self, identifier: &str) -> Result<Vec<u8>> {
        // Call macOS Keychain API
        // ...
    }
    // ...
}
```

**Benefits:**
- MVP ships with no-op keyring (fast, no external dependencies).
- v1.1 can add platform-specific implementations without changing core vault logic.
- Tests use NoOpKeyring.
- Production selects implementation at startup based on OS.

---

## Testing Strategy

### Unit Tests (in each module)
- Test individual functions in isolation.
- Use mock implementations of traits.
- Located in `tests` submodule within each file.

**Example:**
```rust
// In padlock-core/src/crypto/mod.rs
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = "test_password";
        let salt = [0u8; 16];

        let key1 = derive_vault_key(password, &salt).expect("key1");
        let key2 = derive_vault_key(password, &salt).expect("key2");

        assert_eq!(key1, key2, "Derivation must be deterministic");
    }
}
```

### Integration Tests (in `tests/` directory)
- Test complete workflows (e.g., init vault, create credential, unlock, read).
- Use `padlock-test-utils` for fixtures.
- Located in `crates/padlock-core/tests/` and `crates/padlock-cli/tests/`.

**Example:**
```rust
// In padlock-core/tests/vault_workflow.rs
#[test]
fn test_init_unlock_create_read_workflow() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = FilesystemBackend::new(temp_dir.path());

    // Initialize
    let vault = Vault::init(
        Box::new(storage),
        Arc::new(TestPrompt::new("password123")),
    ).expect("init");

    // Create credential
    let cred = Credential::new_password("my_api_key", "secret123");
    vault.create_credential(cred).expect("create");

    // Lock
    vault.lock();

    // Unlock
    let vault = Vault::unlock(Box::new(storage), Arc::new(TestPrompt::new("password123")))
        .expect("unlock");

    // Read
    let cred = vault.read_credential("my_api_key").expect("read");
    assert_eq!(cred.secret(), "secret123");
}
```

### Property-Based Tests (future)
- Use `proptest` to verify invariants hold for random inputs.
- Examples: encryption/decryption round-trip, TOTP generation consistency.

---

## Code Organization Guidelines

### File Layout Within a Module
```rust
// At the top of each module file:

// 1. Module documentation (what does this module do?)
//! This module handles vault initialization and locking.
//!
//! # Examples
//!
//! ```
//! # use padlock_core::vault::*;
//! let vault = init_vault("my_vault", password)?;
//! ```

// 2. Imports (grouped: std, external crates, internal)
use std::path::PathBuf;
use thiserror::Error;

use crate::crypto::*;
use crate::traits::*;

// 3. Public types and constants
/// The main vault struct.
pub struct Vault {
    // ...
}

pub const DEFAULT_VAULT_NAME: &str = "default";

// 4. Public functions and impl blocks
impl Vault {
    pub fn new() -> Self { ... }
}

pub fn init_vault() -> Result<Vault> { ... }

// 5. Private helper functions
fn validate_vault_path(path: &Path) -> Result<()> { ... }

// 6. Tests at the bottom
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_init() { ... }
}
```

### Comments and Documentation
- Every public type, function, and trait must have a doc comment (`///`).
- Doc comments explain the "why", not just the "what".
- Include examples in doc comments for complex types.

**Example:**
```rust
/// Unlock a vault with a master password.
///
/// This function derives the encryption key from the master password using Argon2id,
/// then decrypts all credential metadata from storage. The vault is kept in memory
/// until `lock()` is called.
///
/// # Arguments
///
/// * `storage` - Where to load the vault from
/// * `password` - The master password (will be zeroized after use)
///
/// # Errors
///
/// Returns `Error::InvalidPassword` if the password is incorrect.
///
/// # Example
///
/// ```
/// # use padlock_core::vault::*;
/// let vault = unlock_vault(storage, "my_password")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn unlock_vault(
    storage: Box<dyn StorageBackend>,
    password: &str,
) -> Result<Vault> {
    // ...
}
```

---

## Summary: How It All Fits Together

1. **Crate Structure:** Three crates (`padlock-core`, `padlock-cli`, `padlock-test-utils`) with clear responsibilities.

2. **Module Organization:** Each domain concern (crypto, vault, entries, SSH, signing, audit, generation) is a module with public exports and private helpers.

3. **Types and Traits:** Domain types (`Vault`, `Credential`, etc.) + traits for abstraction (`StorageBackend`, `UserConfirmation`, `PlatformKeyring`).

4. **Error Handling:** Core uses `thiserror` for specific errors; CLI uses `anyhow` for context and display.

5. **Testing:** Unit tests per module, integration tests in `tests/` directory, shared fixtures in `padlock-test-utils`.

6. **Dependencies:** Pinned versions, vetted, minimal, security-focused.

7. **Features:** Minimal defaults; optional features (`async`, `test-utils`) for future capabilities.

**When implementing a new feature:**
1. Add a new module under `padlock-core/src/` (or extend existing).
2. Define public types and traits in that module.
3. Implement core logic (private functions/impl blocks).
4. Write unit tests in the module.
5. Write integration tests in `tests/`.
6. Export from `lib.rs`.
7. Document with doc comments and examples.
8. Update this context file if you're introducing new conventions or patterns.


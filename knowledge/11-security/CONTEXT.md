# Security Checklist Context

## Overview

Padlock is an encrypted credential manager handling sensitive data (passwords, SSH keys, API tokens, certificates). Security is non-negotiable. This document provides a comprehensive audit checklist covering all 49 security items referenced in SYSTEM_DESIGN.md §11.

**Organization**: 11 categories, each with specific verifiable checks and corresponding code locations.

---

## Category 1: Cryptography (8 items)

### 1.1 AES-256-GCM Implementation

**Check**: All vault entries use AES-256-GCM (AEAD) encryption.

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs`
- [ ] `encrypt()` uses `aead::AesGcm::<aes::Aes256>::new(key)`
- [ ] Test: `test_security_crypto_all_entry_types_roundtrip`
- [ ] Test: `test_security_crypto_aead_tag_verification_fails`

**Rationale**: AES-256-GCM provides:
- 256-bit symmetric encryption (resistant to quantum attacks with key distribution)
- Authenticated encryption (AEAD catches tampering)
- Nonce-based (not ECB which is insecure)

**Phase**: Core (0)

---

### 1.2 HMAC-SHA256 for Vault Integrity

**Check**: Vault file includes HMAC-SHA256 of ciphertext + metadata.

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs`
- [ ] `VaultHeader` includes 32-byte HMAC field
- [ ] `save()` computes HMAC before writing
- [ ] `open()` verifies HMAC on load (fails if mismatch)
- [ ] Test: `test_security_vault_corruption_single_byte_flip_detected`

**Rationale**: HMAC detects vault file tampering (any byte flip detected).

**Phase**: Core (0)

---

### 1.3 Argon2id Key Derivation

**Check**: Master passphrase → encryption key via Argon2id (memory-hard).

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs::derive_key()`
- [ ] Uses `argon2::Argon2::new()` with ID variant
- [ ] Memory: 256 MB (configurable)
- [ ] Time: 3 iterations (configurable)
- [ ] Parallelism: 4 threads (configurable)
- [ ] Salt: 32 random bytes (stored in vault header)
- [ ] Test: `test_security_wrong_passphrase_rejected`

**Rationale**: Argon2id resists GPU/ASIC brute-force attacks by using RAM.

**Phase**: Core (0)

---

### 1.4 Nonce Generation (Randomness)

**Check**: Each encryption uses a unique, random 12-byte nonce.

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs::generate_nonce()`
- [ ] Uses `rand::thread_rng()` or `OsRng` (OS entropy)
- [ ] Nonce is 12 bytes (96 bits)
- [ ] No nonce reuse with same key
- [ ] Test: `test_security_nonce_uniqueness_1m_encryptions`
- [ ] Test: `proptest: prop_different_nonces_different_ciphertexts`

**Rationale**: Nonce uniqueness guarantees AES-GCM security. Reusing nonce = key compromise.

**Phase**: Core (0)

---

### 1.5 Random Number Generation (Entropy)

**Check**: All randomness uses cryptographically-secure RNG.

**Verification**:
- Code location: Search for `rand::` usage
- [ ] Uses `rand::rngs::OsRng` or `thread_rng()`
- [ ] No weak RNG (e.g., `std::rand`, `rand::ThreadRng` before seeding)
- [ ] Nonce: RNG ≥256 bits entropy
- [ ] Salt: RNG ≥256 bits entropy
- [ ] Test: `test_security_nonce_uniqueness_1m_encryptions`

**Rationale**: Weak RNG breaks all cryptography.

**Phase**: Core (0)

---

### 1.6 Passphrase Hashing (Timing)

**Check**: Passphrase comparison is constant-time.

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs::verify_passphrase()`
- [ ] Uses `constant_time_eq()` or constant-time comparison
- [ ] No early-return on first byte mismatch
- [ ] Test: `test_security_passphrase_timing_constant`
- [ ] Verify: Benchmark 1000 wrong passphrases, check uniform timing

**Rationale**: Timing attack could leak passphrase length or prefix.

**Phase**: Core (0)

---

### 1.7 Key Rotation (Master Passphrase Change)

**Check**: Changing master passphrase re-encrypts all entries.

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs::change_passphrase()`
- [ ] Old passphrase verifies current HMAC
- [ ] Decrypt all entries with old key
- [ ] Re-encrypt entries with new key
- [ ] Generate new salt
- [ ] Verify no plaintext on disk
- [ ] Test: `test_security_passphrase_change_all_entries_readable`
- [ ] Test: `test_security_passphrase_change_old_passphrase_fails`

**Rationale**: Users should be able to change passphrase securely.

**Phase**: MVP (1)

---

### 1.8 Secure Deletion (Zeroize)

**Check**: All secrets zeroed from memory after use.

**Verification**:
- Code location: Search for `zeroize::Zeroize` or `.zeroize()`
- [ ] Master key: Zeroized after derive, not cloned
- [ ] Plaintext: Zeroized after return to caller
- [ ] Intermediate buffers: Zeroized (XOR with 0)
- [ ] Test: `test_security_memory_zeroing_verification`
- [ ] Verify: No sensitive data in debug/display output

**Rationale**: Plaintext in memory can be read via cold-boot or core dumps.

**Phase**: Core (0)

---

## Category 2: Threat Model (6 items)

### 2.1 Adversary Classes & Mitigations

**Threat Model**: 6 adversary classes

```
┌──────────────────────────────────────────────────────────────┐
│ Adversary Class      │ Capability           │ Mitigation      │
├──────────────────────────────────────────────────────────────┤
│ 1. Passive Attacker  │ Observes ciphertext  │ Encryption      │
│    (eavesdropper)    │ on disk/network      │ w/ AEAD         │
├──────────────────────────────────────────────────────────────┤
│ 2. Active Attacker   │ Modifies vault file  │ HMAC-SHA256     │
│    (tamperer)        │ or agents messages   │ + AEAD tags     │
├──────────────────────────────────────────────────────────────┤
│ 3. Insider          │ Local file access    │ File perms      │
│    (local user)     │ to /home/<user>      │ (0o600, 0o700)  │
├──────────────────────────────────────────────────────────────┤
│ 4. Malware          │ Injects into agent   │ Unix socket      │
│    (code injection)  │ process              │ permissions      │
│                     │ Reads memory         │ Memory zeroize   │
├──────────────────────────────────────────────────────────────┤
│ 5. Brute Force      │ Guesses passphrase   │ Argon2id KDF     │
│    (password cracking)│ offline on disk copy│ (memory-hard)    │
├──────────────────────────────────────────────────────────────┤
│ 6. Side-Channel     │ Timing attacks       │ Const-time comps │
│    (timing leak)     │ Cache/thermal        │ (primary defense)│
│                     │ correlation          │ (mitigated)      │
└──────────────────────────────────────────────────────────────┘
```

**Verification**:
- [ ] Document threat model in THREAT_MODEL.md
- [ ] For each adversary class: code location implementing mitigation
- [ ] Test coverage for each mitigation

**Phase**: Core (0)

---

### 2.2 Assets Under Protection

**Table**: Identify what data is protected and where

```
Asset                  Location              Threat                Protection
─────────────────────────────────────────────────────────────────────────────
Passwords              Vault file            Passive eavesdropping  AES-256-GCM
SSH private keys       Vault file            File tampering         HMAC-SHA256
API tokens             Vault file            Insider access         File perms 0o600
Master passphrase      RAM (derivation)      Core dump              Zeroize + mlock
Session token          Agent socket          Local malware          Unix socket 0o700
Nonce                  Vault file            IV reuse               Randomness
Salt (Argon2)          Vault file (public)   Offline brute force     Memory-hard KDF
```

**Verification**:
- [ ] All assets have identified threats
- [ ] All threats have mitigations
- [ ] Code implements each mitigation

**Phase**: Core (0)

---

### 2.3 Attack Surface

**Code locations to secure**:

1. **Vault file parsing** → Fuzzing required
2. **SSH agent protocol** → Conformance testing required
3. **Master key derivation** → Constant-time required
4. **File I/O** → Atomic writes required

**Verification**:
- [ ] Fuzz vault parser for 10+ minutes without crashes
- [ ] Fuzz SSH agent protocol for 10+ minutes without crashes
- [ ] Security tests pass for all 4 surfaces

**Phase**: Core (0)

---

### 2.4 Defense in Depth

**Multiple layers of defense**:

```
Layer 1: Encryption      - AES-256-GCM (active attacker can't read)
Layer 2: Authentication  - HMAC-SHA256 (active attacker can't modify)
Layer 3: Access Control  - File permissions (insider can't access)
Layer 4: Memory Safety   - Zeroize (malware can't read from memory)
Layer 5: Key Derivation  - Argon2id (brute force attacker slowed)
```

**Verification**:
- [ ] Disable each layer, verify remaining layers still functional
- [ ] No single point of failure

**Phase**: Core (0)

---

### 2.5 Fail-Safe Defaults

**Check**: Security-critical defaults are conservative.

**Verification**:
- Code location: `crates/padlock-core/src/config.rs`
- [ ] Argon2id memory: 256 MB (high, slow)
- [ ] Timeout: Require passphrase entry on every open
- [ ] File permissions: 0o600 (user-only) on creation
- [ ] Socket permissions: 0o700 (user-only) on creation
- [ ] No plaintext fallback

**Rationale**: Users shouldn't have to opt-in to security.

**Phase**: Core (0)

---

### 2.6 Threat Monitoring & Incident Response

**Check**: Logging and alerting for security events.

**Verification**:
- Code location: `crates/padlock-core/src/logging.rs`
- [ ] Log wrong passphrase attempts (rate limit)
- [ ] Log file permission errors
- [ ] Log HMAC verification failures
- [ ] No secret data in logs
- [ ] Logs are optional (can be disabled)

**Phase**: MVP (1)

---

## Category 3: Data Protection (7 items)

### 3.1 Vault File Encryption

**Check**: Entire vault encrypted on disk (no plaintext).

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs::save()`
- [ ] Entries encrypted before writing
- [ ] Metadata encrypted (tags, types)
- [ ] Only salt and HMAC unencrypted
- [ ] Test: `test_security_crypto_vault_file_no_plaintext`
- [ ] Hex dump vault file: no readable text

**Rationale**: Disk exposure should not leak secrets.

**Phase**: Core (0)

---

### 3.2 Entry Encryption (AEAD)

**Check**: Each entry's ciphertext + nonce + AEAD tag integrity.

**Verification**:
- Code location: `crates/padlock-core/src/entry.rs`
- [ ] Entry struct: `ciphertext`, `nonce`, `tag` fields
- [ ] Decrypt: AEAD tag verified before decryption
- [ ] No plaintext returned if tag fails
- [ ] Test: `test_security_entry_tampering_aead_tag_fails`

**Rationale**: AEAD guarantees: decrypt only succeeds if tag is valid.

**Phase**: Core (0)

---

### 3.3 Entry Metadata Encryption

**Check**: Entry metadata (name, tags, type) encrypted.

**Verification**:
- Code location: `crates/padlock-core/src/entry.rs`
- [ ] Name field: encrypted
- [ ] Tags field: encrypted
- [ ] Type field: encrypted
- [ ] Only ID + creation timestamp unencrypted
- [ ] Test: `test_security_crypto_entry_metadata_encrypted`

**Rationale**: Metadata leaks information (e.g., "admin", "prod_db").

**Phase**: MVP (1)

---

### 3.4 Backups (Encrypted)

**Check**: Automatic backups are encrypted.

**Verification**:
- Code location: `crates/padlock-core/src/backup.rs`
- [ ] Backup file format: Same as vault (encrypted)
- [ ] Backup location: `~/.padlock/backups/vault-TIMESTAMP.backup`
- [ ] Backup permissions: 0o600
- [ ] Test: `test_security_backup_encrypted`
- [ ] Verify: Hex dump backup, no plaintext

**Rationale**: Backups are as sensitive as original vault.

**Phase**: MVP (1)

---

### 3.5 Temporary Files (Secure Deletion)

**Check**: Temp files created during operations are securely deleted.

**Verification**:
- Code location: `crates/padlock-core/src/utils.rs::secure_tempfile()`
- [ ] Use `tempfile` crate (not /tmp)
- [ ] Automatic cleanup on drop
- [ ] Permissions: 0o600
- [ ] Override/shred before delete (optional for spinning disk)
- [ ] Test: `test_security_temp_files_no_plaintext_after_delete`

**Rationale**: Temp files can be recovered with disk tools if not overwritten.

**Phase**: MVP (1)

---

### 3.6 Cache Management

**Check**: Decrypted plaintext not cached (except in Agent).

**Verification**:
- Code location: Search for `cache`, `memoize`
- [ ] No global plaintext cache
- [ ] Agent caches decrypted keys in memory (bounded)
- [ ] Cache cleared on timeout (configurable, default 5 min)
- [ ] Test: `test_security_cache_timeout_clears_plaintext`

**Rationale**: Cache could be inspected via debugger.

**Phase**: MVP (1)

---

### 3.7 Error Messages (No Secrets)

**Check**: Error messages don't leak secrets.

**Verification**:
- Code location: Search for `println!`, `log`, `eprintln!`
- [ ] Ciphertext not printed
- [ ] Plaintext not printed
- [ ] Key not printed
- [ ] Only error type + safe context printed
- [ ] Example bad: "Failed to decrypt: ciphertext=0x..."
- [ ] Example good: "Failed to decrypt entry: invalid authentication tag"
- [ ] Test: `test_security_error_messages_no_secrets`

**Rationale**: Error messages sent to logs, terminals, syslog — all untrusted.

**Phase**: Core (0)

---

## Category 4: Memory Safety (4 items)

### 4.1 Memory Zeroization

**Check**: All secrets zeroized before deallocation.

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs`
- [ ] `use zeroize::Zeroize`
- [ ] Master key: Implement `Zeroize`
- [ ] Plaintext buffers: Zeroized after use
- [ ] Passphrase: Zeroized after verification
- [ ] Test: `test_security_memory_plaintext_zeroed_after_decrypt`
- [ ] Verify: No plaintext strings in binary (use `strings padlock-cli | grep password`)

**Rationale**: Cold boot or memory dump could recover unzeroed secrets.

**Phase**: Core (0)

---

### 4.2 Stack Smashing Protection

**Check**: Stack buffer overflows mitigated.

**Verification**:
- Code location: `Cargo.toml` [profile.release]
- [ ] Default: Stack smashing protection enabled (LLVM)
- [ ] No unsafe buffer operations
- [ ] Grep for `std::mem::transmute`: Should be 0 uses (danger)
- [ ] Test: `cargo build --release`

**Rationale**: Buffer overflow → code injection.

**Phase**: Core (0)

---

### 4.3 Memory Leak Detection

**Check**: No memory leaks under normal operation.

**Verification**:
- Tool: `valgrind` or `cargo-miri`
- [ ] Run: `valgrind --leak-check=full ./padlock-cli ...`
- [ ] Run: `cargo miri test` (if possible)
- [ ] Test: No "definitely lost" blocks
- [ ] Acceptable: "possibly lost" (conservative analysis)

**Rationale**: Leaked memory containing secrets survives process exit.

**Phase**: MVP (1)

---

### 4.4 Use-After-Free Detection

**Check**: No use-after-free bugs.

**Verification**:
- Tool: `cargo-miri` or sanitizers
- [ ] Run: `cargo +nightly miri test`
- [ ] Run: Compiled with `-Zsanitizer=memory`
- [ ] No "use-after-free" reports

**Rationale**: Use-after-free → crashes or code execution.

**Phase**: MVP (1)

---

## Category 5: Filesystem Security (5 items)

### 5.1 Vault File Permissions

**Check**: Vault file created with 0o600 (user-only).

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs::save()`
- [ ] `File::create()` followed by `fs::set_permissions(0o600)`
- [ ] Verify on Linux: `stat vault.pdl | grep "Access: (0600)"`
- [ ] Verify on macOS: `ls -la vault.pdl | grep rw-------`
- [ ] Test: `test_security_vault_file_permissions_0o600`

**Rationale**: Other users on system can't read vault.

**Phase**: Core (0)

---

### 5.2 Socket Permissions (Agent)

**Check**: Unix domain socket created with 0o700 (user-only).

**Verification**:
- Code location: `crates/padlock-agent/src/socket.rs`
- [ ] Socket created with `bind()` + `chmod(0o700)`
- [ ] Socket path: `~/.padlock/socket` (world-unreadable)
- [ ] Test: `test_security_agent_socket_permissions_0o700`
- [ ] Verify: `ls -la ~/.padlock/socket | grep rwx------`

**Rationale**: Other users can't connect to agent.

**Phase**: MVP (1)

---

### 5.3 Atomic Writes (Crash Recovery)

**Check**: Vault writes are atomic (no partial files on crash).

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs::save()`
- [ ] Write to temporary file first
- [ ] Verify checksum/size
- [ ] Atomic rename to final path
- [ ] Example pattern:
  ```rust
  let temp_path = path.with_extension("tmp");
  file.write_all(&data)?;
  file.sync_all()?;  // Flush to disk
  fs::rename(&temp_path, path)?;  // Atomic
  ```
- [ ] Test: `test_security_atomic_write_kill_during_write_no_corruption`

**Rationale**: If process killed during write, vault shouldn't be corrupted.

**Phase**: MVP (1)

---

### 5.4 Lock File Handling

**Check**: Concurrent writes prevented via lock file.

**Verification**:
- Code location: `crates/padlock-core/src/vault.rs::lock()`
- [ ] Lock file: `~/.padlock/vault.lock`
- [ ] Obtained before reading vault
- [ ] Released after writing vault
- [ ] Permissions: 0o600
- [ ] Test: `test_security_vault_concurrent_writes_blocked`
- [ ] Verify: Start 2 processes, both try to modify vault simultaneously

**Rationale**: Concurrent writes can corrupt vault.

**Phase**: MVP (1)

---

### 5.5 Backup File Rotation

**Check**: Old backups rotated and deleted securely.

**Verification**:
- Code location: `crates/padlock-core/src/backup.rs`
- [ ] Keep only last N backups (default: 10)
- [ ] Delete old backups via `secure_delete()` (overwrite + remove)
- [ ] Backup permissions: 0o600
- [ ] Test: `test_security_backup_rotation_deletes_securely`

**Rationale**: Old backups are security liabilities.

**Phase**: MVP (1)

---

## Category 6: Session Security (3 items)

### 6.1 Agent Session Timeout

**Check**: Agent sessions timeout after inactivity.

**Verification**:
- Code location: `crates/padlock-agent/src/session.rs`
- [ ] Default timeout: 5 minutes (configurable)
- [ ] Lock agent on timeout
- [ ] Require passphrase to unlock
- [ ] Test: `test_security_agent_session_timeout`
- [ ] Verify: Open agent, wait 5+ min, agent requires passphrase

**Rationale**: Left-unlocked agent (e.g., unattended terminal) can be abused.

**Phase**: MVP (1)

---

### 6.2 Passphrase Entry Security

**Check**: Passphrase prompt doesn't echo to terminal.

**Verification**:
- Code location: `crates/padlock-cli/src/input.rs::read_passphrase()`
- [ ] Uses `rpasswort` or `termios` to disable echo
- [ ] Passphrase not printed
- [ ] Asterisks or dots shown instead (optional)
- [ ] Test: `test_security_passphrase_entry_no_echo`
- [ ] Verify: Manually, type passphrase at prompt — nothing visible

**Rationale**: Attacker shouldn't see passphrase on screen (shoulder surfing).

**Phase**: Core (0)

---

### 6.3 Session Reuse (No Automatic Unlock)

**Check**: Opening vault doesn't reuse old session (requires fresh passphrase).

**Verification**:
- Code location: `crates/padlock-cli/src/main.rs`
- [ ] No session caching between CLI invocations
- [ ] Every `padlock open` prompts for passphrase
- [ ] Exception: Agent (deliberate, with timeout)
- [ ] Test: `test_security_cli_no_automatic_unlock`

**Rationale**: Old CLI sessions shouldn't be reused.

**Phase**: Core (0)

---

## Category 7: SSH Agent Conformance (4 items)

### 7.1 Agent Protocol (RFC Conformance)

**Check**: SSH agent conforms to RFC draft-miller-ssh-agent-00.

**Verification**:
- Code location: `crates/padlock-agent/src/protocol.rs`
- [ ] Message format: 4-byte length + payload
- [ ] `SSH_AGENTC_REQUEST_IDENTITIES` (11) → identity list
- [ ] `SSH_AGENTC_SIGN_REQUEST` (13) → signature
- [ ] `SSH_AGENTC_ADD_IDENTITY` (17) → add key (not implemented)
- [ ] All other messages → `SSH_AGENT_FAILURE` (5)
- [ ] Test: `test_security_agent_list_keys_conforms_to_spec`
- [ ] Test: `test_security_agent_sign_request_conformance`

**Rationale**: SSH client expects RFC-compliant responses.

**Phase**: MVP (1)

---

### 7.2 Agent Key Signing

**Check**: Keys are signed correctly for SSH protocol.

**Verification**:
- Code location: `crates/padlock-agent/src/signing.rs`
- [ ] Uses Ed25519 or RSA (depending on key type)
- [ ] Signature verifiable with ssh-keygen
- [ ] Test: `test_security_agent_sign_request_signature_valid`
- [ ] Verify manually:
  ```bash
  ssh-agent -a /tmp/agent.sock
  padlock agent --socket /tmp/agent.sock
  ssh -i /dev/null -o IdentityAgent=/tmp/agent.sock host.example.com
  ```

**Rationale**: SSH client verifies signatures.

**Phase**: MVP (1)

---

### 7.3 Malformed Message Rejection

**Check**: Malformed SSH agent protocol messages rejected gracefully.

**Verification**:
- Code location: `crates/padlock-agent/src/protocol.rs::parse()`
- [ ] No panics on invalid input
- [ ] Returns `SSH_AGENT_FAILURE` for malformed messages
- [ ] Logs invalid message (rate-limited)
- [ ] Test: `test_security_agent_malformed_message_rejected`
- [ ] Fuzz target: `fuzz/fuzz_targets/agent_protocol.rs`

**Rationale**: Malformed messages shouldn't crash agent.

**Phase**: MVP (1)

---

### 7.4 Concurrent Agent Connections

**Check**: Agent handles multiple concurrent SSH clients.

**Verification**:
- Code location: `crates/padlock-agent/src/server.rs`
- [ ] Uses `tokio` or thread pool for parallelism
- [ ] Each connection: Independent message parser
- [ ] Shared state: Read-only (vault entries)
- [ ] Test: `test_security_agent_concurrent_connections`
- [ ] Verify: `for i in {1..100}; do ssh-add -L & done; wait`

**Rationale**: Agent shouldn't deadlock or corrupt state under load.

**Phase**: MVP (1)

---

## Category 8: Synchronization (2 items)

### 8.1 Vault Sync (Optional Feature)

**Check**: If sync enabled, encrypted end-to-end.

**Verification**:
- Code location: `crates/padlock-sync/src/client.rs` (if implemented)
- [ ] Vault encrypted before upload
- [ ] Sync server never sees plaintext
- [ ] Server stores only ciphertext
- [ ] Metadata (sizes, timestamps) encrypted or omitted
- [ ] Test: `test_security_sync_e2e_encrypted`

**Rationale**: Sync server breach shouldn't leak secrets.

**Phase**: Future (3)

---

### 8.2 Conflict Resolution (Integrity)

**Check**: Vault conflicts resolved without data loss.

**Verification**:
- Code location: `crates/padlock-sync/src/merge.rs` (if implemented)
- [ ] Merge strategy: Last-write-wins with timestamps
- [ ] Conflicting entries: Both retained (separate IDs)
- [ ] No plaintext in conflict logs
- [ ] Test: `test_security_sync_conflict_resolution_integrity`

**Rationale**: Conflict resolution shouldn't corrupt vault.

**Phase**: Future (3)

---

## Category 9: Code Quality (3 items)

### 9.1 No Unsafe Blocks

**Check**: Unsafe code minimized and audited.

**Verification**:
- Search: `grep -r "unsafe {" crates/`
- [ ] Count: Should be <10 total in project
- [ ] Each unsafe: Documented with // SAFETY comment
- [ ] Each unsafe: Reviewed for soundness
- [ ] Example locations:
  - `zeroize` in crypto module (approved)
  - `FFI` in agent socket code (approved)
  - Avoid: Arbitrary unsafe blocks
- [ ] Test: `cargo clippy -- -D unsafe`

**Rationale**: Unsafe code can break memory safety guarantees.

**Phase**: Core (0)

---

### 9.2 No Panics in Crypto

**Check**: Cryptographic functions never panic on untrusted input.

**Verification**:
- Code location: `crates/padlock-core/src/crypto.rs`
- [ ] Functions return `Result` (not `unwrap()`)
- [ ] All `.unwrap()` have comments explaining safety
- [ ] Test: Fuzz crypto functions with arbitrary inputs
- [ ] Fuzz target: `fuzz/fuzz_targets/crypto_round_trip.rs`

**Rationale**: Panics leak information (attacker sees crash patterns).

**Phase**: Core (0)

---

### 9.3 Clippy Warnings (Zero)

**Check**: All Clippy warnings fixed.

**Verification**:
- Run: `cargo clippy --all-targets -- -D warnings -D clippy::pedantic`
- [ ] Zero warnings
- [ ] CI enforces this (blocks PR if violated)

**Rationale**: Clippy detects security anti-patterns.

**Phase**: Core (0)

---

## Category 10: Supply Chain (4 items)

### 10.1 Dependency Audit

**Check**: All dependencies audited for known vulnerabilities.

**Verification**:
- Tool: `cargo deny check advisories`
- [ ] Zero known advisories
- [ ] Daily audit via CI (`audit.yml`)
- [ ] GitHub alerts enabled
- [ ] Vulnerabilities fixed within 48 hours
- [ ] Test: CI runs `cargo deny`

**Rationale**: Vulnerable dependencies compromise security.

**Phase**: Core (0)

---

### 10.2 License Compliance

**Check**: All dependencies have approved licenses.

**Verification**:
- Tool: `cargo deny check licenses`
- [ ] Approved: MIT, Apache-2.0, BSD
- [ ] Rejected: GPL, AGPL, proprietary
- [ ] CI enforces (blocks PR if violated)

**Rationale**: GPL can force source code disclosure.

**Phase**: Core (0)

---

### 10.3 Supply Chain Verification (Cargo.vet)

**Check**: Transitive dependencies reviewed.

**Verification**:
- Tool: `cargo vet`
- [ ] All transitive dependencies reviewed
- [ ] High-risk crates (crypto, networking): Extra review
- [ ] Documentation in `supply-chain/config.toml`
- [ ] Test: CI runs `cargo vet`

**Rationale**: Typosquatting attacks (e.g., `tokio` vs. `tokio2`).

**Phase**: MVP (1)

---

### 10.4 Build Reproducibility

**Check**: Binaries are reproducible (same source → same binary).

**Verification**:
- Build twice: `cargo build --release`
- [ ] SHA256 hashes match
- [ ] Version info consistent
- [ ] Test: CI builds twice, compares hashes
- [ ] CI: `cargo build --release` x2, verify `sha256sum match`

**Rationale**: Allows users to verify binary integrity.

**Phase**: MVP (1)

---

## Category 11: Distribution & Information Leakage (7 items)

### 11.1 Binary Signatures (Release)

**Check**: Released binaries signed with maintainer key.

**Verification**:
- Code location: Release workflow
- [ ] Binaries signed with GPG or ECDSA
- [ ] Public key published on website
- [ ] Signature included with release
- [ ] Test: Users can verify: `gpg --verify padlock.sig padlock`
- [ ] CI: `release.yml` includes signing step

**Rationale**: Users verify binary authenticity.

**Phase**: Release (2)

---

### 11.2 SBOM (Software Bill of Materials)

**Check**: SBOM generated for each release.

**Verification**:
- Code location: Release workflow
- [ ] Generate: `cargo sbom --format spdx`
- [ ] Include with release artifacts
- [ ] SPDX format: Standard, machine-readable
- [ ] Test: SBOM includes all crates, versions

**Rationale**: Dependency transparency for supply chain security.

**Phase**: Release (2)

---

### 11.3 Debug Symbols Stripped

**Check**: Release binaries have debug symbols removed.

**Verification**:
- Code location: `Cargo.toml` [profile.release]
- [ ] `strip = true` (removes debug symbols)
- [ ] Verify: `objdump -t padlock | grep -i debug` (should be empty)
- [ ] Test: Binary size much smaller than debug build

**Rationale**: Debug symbols leak source code locations.

**Phase**: Release (2)

---

### 11.4 Debug Output Disabled

**Check**: Debug assertions and logging disabled in release builds.

**Verification**:
- Code location: Search for `debug_assert!`, `eprintln!`
- [ ] No `println!` in release (use `log::debug!`)
- [ ] `debug!` macros compiled out with `--release`
- [ ] Test: Run release binary with `RUST_LOG=debug` (no output)

**Rationale**: Debug output leaks secrets in production.

**Phase**: Core (0)

---

### 11.5 No Hardcoded Secrets

**Check**: No hardcoded keys, tokens, or credentials in source.

**Verification**:
- Search: `grep -r "0x[0-9a-f]" crates/ | grep -v test | grep -v "0x0\|0xFF"`
- [ ] No hex-encoded secrets
- [ ] No base64 secrets
- [ ] No test keys in production code (only in tests/)
- [ ] CI: `cargo audit` flags embedded credentials

**Rationale**: Source code repositories are often public.

**Phase**: Core (0)

---

### 11.6 Path Disclosure Prevention

**Check**: Error messages don't disclose file paths.

**Verification**:
- Code location: Search for `file_path`, `home_dir()`
- [ ] Error messages omit paths
- [ ] Example bad: "Failed to open /home/alice/.padlock/vault.pdl"
- [ ] Example good: "Failed to open vault: permission denied"
- [ ] Test: `test_security_error_messages_no_paths`

**Rationale**: Paths leak information about system structure.

**Phase**: Core (0)

---

### 11.7 No Information Leakage in Logs

**Check**: No secrets in logs, event logs, or system messages.

**Verification**:
- Code location: All `log::`, `println!`, `eprintln!`
- [ ] Plaintext never logged
- [ ] Ciphertext never logged
- [ ] Keys never logged
- [ ] Passphrases never logged
- [ ] Acceptable logs:
  - "Vault opened successfully"
  - "Entry added: 3 characters"
  - "Sync completed: 5 entries"
- [ ] Test: `test_security_logs_no_secrets`

**Rationale**: Logs are readable by sysadmins, stored, and forwarded.

**Phase**: Core (0)

---

## Critical Security Invariants

These 6 invariants **MUST NEVER BE VIOLATED**:

```
┌────────────────────────────────────────────────────────────┐
│ Invariant 1: Secrets never plaintext on disk               │
├────────────────────────────────────────────────────────────┤
│ - All vault entries encrypted before writing               │
│ - All backups encrypted                                    │
│ - All temp files encrypted (if created)                    │
│ - Violated if: hex dump shows readable passwords           │
│ - Test: test_security_vault_no_plaintext_on_disk          │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ Invariant 2: Secrets zeroed from memory after use           │
├────────────────────────────────────────────────────────────┤
│ - Master key zeroized after KDF                            │
│ - Plaintext zeroized after decryption                      │
│ - Passphrase zeroized after verification                   │
│ - Violated if: Core dump shows unzeroed secrets            │
│ - Test: test_security_memory_plaintext_zeroed             │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ Invariant 3: AEAD tag verified before plaintext returned    │
├────────────────────────────────────────────────────────────┤
│ - Decrypt: verify tag first                                │
│ - No early return on correct ciphertext                    │
│ - Return Err if tag fails, no plaintext leaked             │
│ - Violated if: Tampering undetected or plaintext returned  │
│ - Test: test_security_aead_tag_verification               │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ Invariant 4: File permissions prevent unauthorized access   │
├────────────────────────────────────────────────────────────┤
│ - Vault file: 0o600 (user only)                            │
│ - Agent socket: 0o700 (user only)                          │
│ - Lock file: 0o600 (user only)                             │
│ - Violated if: `ls -la` shows group or other bits          │
│ - Test: test_security_file_permissions                    │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ Invariant 5: No secret data in error/log output             │
├────────────────────────────────────────────────────────────┤
│ - Error messages omit: plaintext, ciphertext, keys         │
│ - Logs omit: plaintext, keys, passphrases, paths           │
│ - Debug output omit: sensitive data                        │
│ - Violated if: strace/ltrace shows secrets                 │
│ - Test: test_security_error_messages_no_secrets           │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ Invariant 6: Constant-time comparisons for authentication    │
├────────────────────────────────────────────────────────────┤
│ - Passphrase check: Constant-time (no timing leak)         │
│ - HMAC verification: Constant-time                         │
│ - Violated if: Attacker can distinguish valid/invalid      │
│ - Test: test_security_passphrase_timing_constant          │
└────────────────────────────────────────────────────────────┘
```

**Enforcement**:
- Code review: Every change audited
- Tests: Each invariant has dedicated test
- Mutation testing: Verify tests catch breaks
- CI: Blocks merge if any test fails

---

## Security Audit Checklist (49 items)

### By Phase

**Phase 0 (Core)** — 22 items
- Crypto (8): AES-256-GCM, HMAC-SHA256, Argon2id, Nonce, RNG, Timing, Zeroize, Key Rotation
- Threat Model (3): Adversary Classes, Assets, Fail-Safe Defaults
- Data Protection (1): Vault File Encryption
- Entry Protection (2): Entry Encryption (AEAD), Entry Tampering Detection
- Memory (2): Zeroization, Stack Protection
- Filesystem (1): Vault File Permissions
- Session (1): Passphrase Entry (no echo)
- SSH Agent (0)
- Code Quality (2): No panics, Clippy warnings
- Supply Chain (1): Dependency Audit
- Distribution (4): No hardcoded secrets, Path disclosure, Logs, Debug output

**Phase 1 (MVP)** — 16 items
- Data Protection (3): Metadata encryption, Backups, Temp files
- Memory (2): Leak detection, UAF detection
- Filesystem (4): Atomic writes, Lock files, Backup rotation, Permissions checks
- Session (2): Session timeout, Session reuse prevention
- SSH Agent (4): RFC conformance, Key signing, Malformed message rejection, Concurrent connections
- Supply Chain (1): Build reproducibility

**Phase 2 (Release)** — 4 items
- Distribution (4): Binary signatures, SBOM, Debug symbols, Hardcoded secrets

**Phase 3 (Future)** — 2 items
- Sync (2): E2E encryption, Conflict resolution

---

## Security Test Execution

```bash
# Run all security tests
cargo test --test security_

# Run specific category
cargo test --test security_crypto
cargo test --test security_vault
cargo test --test security_memory
cargo test --test security_agent

# Run with verbose output
cargo test -- --nocapture

# Run with backtraces
RUST_BACKTRACE=1 cargo test

# Fuzz for 10 minutes
cargo fuzz run vault_parser -- -max_len=16384 -timeout=10

# Check coverage
cargo llvm-cov --workspace --html

# Mutation testing
cargo mutants --timeout 30
```

---

## Security Review Workflow

1. **Code Change**: Developer submits PR
2. **Automated Checks**: CI runs all 49 security tests
3. **Code Review**: Security reviewer audits changes
4. **Threat Assessment**: Check against threat model
5. **Merge**: Only after all checks pass
6. **Release**: Sign binaries, publish SBOM

---

## References

- SYSTEM_DESIGN.md §11: Threat Model & Security Analysis
- THREAT_MODEL.md: Detailed adversary descriptions (to create)
- RFC draft-miller-ssh-agent-00: SSH Agent Protocol
- NIST SP 800-132: PBKDF2 (Argon2id is modern alternative)
- OWASP: Secure Coding Practices
- CWE/SANS Top 25: Common Weaknesses

This comprehensive checklist ensures Padlock meets security standards from day one.

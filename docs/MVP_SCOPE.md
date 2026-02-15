# Padlock MVP Scope

**Version:** 1.0
**Last Updated:** 2026-02-07
**Status:** Active

## Overview

Padlock is a Rust-based credential manager designed specifically for developers and operators who need to manage SSH keys, API credentials, TOTP secrets, and Git signing keys locally with strong security guarantees and tight integration with Unix tooling.

This document defines the scope of the Minimum Viable Product (MVP) release: what is included, what is explicitly deferred, key design decisions with security-first rationale, success criteria, and minimum supported platforms.

---

## Feature Scope Table

| Feature Category | Feature | MVP Status | Rationale |
|---|---|---|---|
| **Vault Lifecycle** | Initialize vault | IN | Required for first-time setup and security bootstrap |
| **Vault Lifecycle** | Unlock vault (with master password) | IN | Core security requirement; access control |
| **Vault Lifecycle** | Lock vault | IN | Essential for security posture; prevents memory exposure |
| **Credential Management** | Create credential entry | IN | CRUD foundation for all credential types |
| **Credential Management** | Read credential entry | IN | CRUD foundation |
| **Credential Management** | Update credential entry | IN | CRUD foundation |
| **Credential Management** | Delete credential entry | IN | CRUD foundation |
| **Credential Management** | List credentials | IN | Essential for user discoverability |
| **SSH Key Management** | Store SSH private keys in vault | IN | Primary use case; enables Git/server authentication |
| **SSH Key Management** | Load SSH key on demand | IN | Required for SSH agent integration |
| **SSH Key Management** | TOTP secret storage and generation | IN | Multi-factor auth support is standard expectation |
| **SSH Key Management** | Passphrase-protected SSH key support | IN | User's SSH keys may be passphrase-protected; must decrypt on load |
| **TOTP Generation** | Generate TOTP codes from stored secrets | IN | Core MFA requirement |
| **TOTP Generation** | QR code display (optional output) | OUT | Can be done in UI/TUI later; not essential for MVP |
| **CLI Interface** | Interactive shell for vault operations | IN | Primary user interface for MVP |
| **CLI Interface** | Non-interactive/scripting support | IN | Operators need to integrate with automation tools |
| **SSH Agent Integration** | SSH agent protocol implementation | IN | Allows use of vault keys with standard SSH clients |
| **SSH Agent Integration** | Agent socket communication (Unix socket) | IN | Standard mechanism for SSH agent on Unix |
| **Git SSH Signing** | Sign Git commits with SSH keys | IN | Developers require signed commits; security-critical feature |
| **Git SSH Signing** | Support for OpenSSH signature format | IN | Industry-standard format |
| **Audit Logging** | Log all vault access events | IN | Security compliance; forensic investigation |
| **Audit Logging** | Log all credential operations (CRUD) | IN | Accountability and compliance |
| **Audit Logging** | Structured audit log output | IN | Enables integration with log aggregation systems |
| **Password Generation** | Generate strong random passwords | IN | Users need secure credential generation |
| **Password Generation** | Customizable password policies | IN | Different services have different requirements |
| **Sync/Replication** | Vault synchronization across devices | OUT | Deferred to v1.1; adds significant complexity and transport security requirements |
| **Platform Integration** | macOS Keychain integration | OUT | Security best practice but adds platform-specific code; defer to v1.1 |
| **Platform Integration** | Linux systemd-credential support | OUT | Only available on systemd systems; defer to v1.1 |
| **Platform Integration** | Windows DPAPI support | OUT | Windows is not a minimum supported platform for MVP |
| **Import/Export** | Import credentials from other tools | OUT | Can be scripted by users if needed; not essential MVP feature |
| **Import/Export** | Export vault to encrypted format | OUT | Backup strategy deferred; users use filesystem backups |
| **Certificate Management** | X.509 certificate storage | OUT | Future feature; currently focused on keys, not certificates |
| **Certificate Management** | Certificate expiry warnings | OUT | Future feature; not in MVP scope |
| **GPG Shim** | GPG compatibility layer | OUT | Adds complexity; GPG support via third-party wrappers if needed |
| **X.509 Shim** | OpenSSL compatibility wrapper | OUT | Not required for MVP use cases |
| **WASM/FFI** | WebAssembly bindings | OUT | Not in scope for MVP; native CLI first |
| **WASM/FFI** | Foreign Function Interface (FFI) | OUT | Not in scope for MVP; native CLI first |
| **Plugin System** | Plugin/extension architecture | OUT | Premature; defer until architecture stabilizes |

---

## Design Decisions (Security-First Rationale)

### 1. Master Password Over Passwordless Unlock

**Decision:** Vault unlocking requires a master password; no passwordless unlock in MVP.

**Rationale:**
- Master password is the root of trust for all operations.
- Passwordless unlock (e.g., biometric, SSO) requires external trust assumptions and platform-specific integration.
- Master password is cryptographically simple: derive key via Argon2, validate with HMAC.
- Users expect something "they know" as the security foundation.
- Adding biometric unlock in v1.1 as an _optional_ layer on top of master password is possible.

---

### 2. AES-256-GCM for Credential Storage

**Decision:** Use AES-256-GCM (Authenticated Encryption) for all credential data at rest.

**Rationale:**
- AES-256-GCM provides both confidentiality and authenticity in a single operation.
- NIST-approved, widely audited, high confidence in security properties.
- Prevents padding oracle attacks (vs CBC mode).
- Authentication prevents tampering/corruption attacks.
- Hardware acceleration available on modern CPUs (AES-NI).
- Alternative (ChaCha20-Poly1305) also acceptable but AES-GCM is more standard for this use case.

---

### 3. Argon2 for Master Password Derivation

**Decision:** Use Argon2id (with conservative parameters) to derive the vault encryption key from the master password.

**Rationale:**
- Argon2 is the password hashing competition winner (PHC).
- Resistant to GPU/ASIC attacks via high memory requirements.
- Resists side-channel timing attacks.
- Parameters (t=2, m=65536, p=1) are conservative: ~100ms on modern hardware, high entropy derivation.
- Alternative (scrypt) acceptable but Argon2 is superior in threat model.
- Do NOT use bcrypt/PBKDF2 for master password; these are too fast.

---

### 4. Vault File Format: Encrypted JSON in Directories

**Decision:** Store vault on-disk as a directory structure with encrypted files (one file per credential) rather than a monolithic encrypted blob.

**Rationale:**
- Granular encryption enables incremental operations (update one credential without rewriting entire vault).
- Metadata not encrypted (names) for usability; sensitive data (private key material) is always encrypted.
- Risk: Directory structure leaks credential count and names. Mitigation: document this trade-off; recommend full-disk encryption and vault directory permissions (0700).
- Alternative (monolithic blob) is simpler but forces decrypt-all/encrypt-all on every operation; slower.
- Alternative (SQLite encrypted) adds dependency; directory structure is transparent and auditable.

---

### 5. SSH Agent Protocol Over REST/gRPC

**Decision:** Implement SSH agent protocol (RFC 4251) via Unix socket, not REST or gRPC.

**Rationale:**
- SSH agent protocol is the de facto standard; all SSH clients know how to speak it.
- Unix socket is the standard transport on Linux/macOS; secure (filesystem permissions, no network exposure).
- REST/gRPC would require all SSH clients to be rewritten; infeasible.
- Zero additional dependencies (no HTTP server needed).
- Protocol is simple: binary framing, signature requests, key listing.

---

### 6. Audit Log in Structured Format (JSON Lines)

**Decision:** Audit logs are written to a file in JSON Lines format (one JSON object per line), not binary or plain text.

**Rationale:**
- JSON Lines is parseable, not lossy, and integrates with standard log aggregation tools (Splunk, ELK, etc.).
- Each line is a complete audit event; no need to parse entire file.
- Structured data enables queries and filtering (timestamp, user, action, resource, result).
- Alternative (SQLite) adds complexity for MVP; file-based is simpler.
- Alternative (plain text) loses structure; not suitable for security/compliance.
- Audit log is _always_ written, even when vault is locked (events are logged before decryption access is granted).

---

### 7. No Network Access in MVP (Sync Deferred)

**Decision:** Vault has no network access in MVP. Synchronization is explicitly deferred to v1.1+.

**Rationale:**
- Network access requires secure transport (TLS), identity verification (mTLS or OAuth), and trust infrastructure.
- Sync introduces significant complexity: conflict resolution, partial failures, key rotation, revocation.
- MVP can be useful without sync (single-machine use cases are common).
- Users can sync via other means: rsync, git, encrypted file sharing.
- Deferral allows MVP to ship faster and focus on core security properties.

---

### 8. CLI-Only in MVP (No GUI)

**Decision:** MVP is CLI-based (TUI-friendly). No GUI application (Electron, Qt, etc.).

**Rationale:**
- CLI is faster to implement and test; reduces surface area.
- CLI is automation-friendly (operators can script vault operations).
- TUI (text-based UI) can be added later without changing core security.
- GUI requires platform-specific considerations (App Store signing, codesigning, UAC/sudo on Windows).
- CLI is the natural interface for developers and operators.

---

## MVP Success Criteria

The MVP is considered "done" when:

1. **Vault Lifecycle:**
   - `padlock init` creates a new vault with master password and encryption key.
   - `padlock unlock` opens vault (in-memory, decrypts credentials).
   - `padlock lock` clears all in-memory secrets.
   - Vault state persists across lock/unlock cycles.

2. **Credential CRUD:**
   - All CRUD operations work: `create`, `read`, `update`, `delete`, `list`.
   - Credentials are stored encrypted at rest.
   - Metadata (timestamps, audit info) is accurate.

3. **SSH Key Management:**
   - SSH private keys can be stored with or without passphrases.
   - Keys are decrypted on-demand and available to SSH agent.
   - `padlock ssh-key load` successfully integrates with SSH agent.

4. **TOTP Generation:**
   - TOTP secrets are stored encrypted.
   - `padlock totp <credential>` generates valid TOTP codes (verified against TOTP validators).
   - Time sync is validated (warn if system time is significantly off).

5. **SSH Agent Integration:**
   - SSH agent socket is created and responds to SSH agent protocol requests.
   - Standard SSH clients (`ssh`, `git`) can use vault keys via agent.
   - Signature operations are logged in audit log.

6. **Git SSH Signing:**
   - `padlock git-sign` produces valid OpenSSH signatures.
   - Signed commits pass `git verify-commit` validation.
   - Integration with Git's `gpg.ssh.program` config.

7. **Audit Logging:**
   - All vault operations (init, unlock, lock) are logged.
   - All credential operations (CRUD) are logged.
   - All SSH operations (sign, load, list keys) are logged.
   - Audit log is human-readable (JSON Lines) and can be queried.

8. **Password Generation:**
   - `padlock generate-password` produces cryptographically random passwords.
   - Passwords meet specified length and character set requirements.
   - Generated passwords are not stored unless user explicitly creates a credential.

9. **Security Properties:**
   - No plaintext credential material in log files or temporary files.
   - Vault files are protected with filesystem permissions (0700).
   - Encryption keys are derived securely (Argon2id).
   - Secrets are cleared from memory after use (zeroize).

10. **CLI Usability:**
    - Help text is clear and accurate (`padlock --help`, `padlock <command> --help`).
    - Error messages are actionable (not cryptic).
    - Non-interactive mode works for scripting (e.g., `padlock unlock < password.txt`).

11. **Testing:**
    - Unit tests cover all CRUD operations, crypto, and vault lifecycle.
    - Integration tests verify end-to-end workflows (init, create SSH key, sign, audit).
    - Security tests verify no plaintext leakage, correct crypto operations.

12. **Documentation:**
    - README with quick-start guide.
    - Man pages for all CLI commands.
    - Security policy (threat model, assumptions, limitations).

---

## Minimum Supported Platforms

The MVP will build and run on:

- **Linux x86_64:** Primary development target. Full support for all features.
- **macOS x86_64:** Full support for all features.
- **macOS aarch64 (Apple Silicon):** Full support for all features.

**Explicitly not supported in MVP:**
- Windows (any architecture)
- Linux aarch64/ARM (raspberry pi, jetson, etc.)
- 32-bit architectures
- iOS/Android

**Rationale:**
- MVP targets developer/operator workstations: macOS and Linux are dominant.
- Reduces CI/CD complexity (fewer platforms to test).
- Windows support requires different keyring integration (DPAPI) and is deferred to v1.1.
- Mobile and ARM support can be added once core architecture stabilizes.

---

## Out-of-Scope: Explicitly Deferred Features

The following features are valuable but explicitly deferred to v1.1 or later. They are not in scope for MVP.

### Sync and Replication
- Vault synchronization across devices (e.g., desktop to laptop).
- Requires: secure transport (TLS), identity verification, conflict resolution, key rotation.
- Deferral rationale: Single-machine use cases are common; users can sync via other means.
- v1.1 approach: Consider secure sync over cloud provider (with end-to-end encryption) or peer-to-peer sync.

### Platform Keyring Integration
- macOS Keychain: defer integration (currently use local encrypted files).
- Linux systemd-credential: defer integration.
- Windows DPAPI: defer (Windows not supported in MVP).
- Deferral rationale: Adds platform-specific code; encrypted files are sufficient for MVP.
- v1.1 approach: Integrate with OS keyrings for additional convenience layer.

### Import/Export
- Import credentials from 1Password, LastPass, Dashlane, etc.
- Export vault to standardized encrypted format.
- Deferral rationale: Can be scripted by users; not essential for MVP.
- v1.1 approach: Provide importers for common tools.

### Certificate Management
- Store X.509 certificates alongside credentials.
- Certificate expiry warnings and renewal reminders.
- Deferral rationale: MVP focuses on keys and secrets, not certificates.
- v1.1 approach: Extend data model to support certificates.

### GPG Shim
- Wrapper/compatibility layer for GNU Privacy Guard.
- Deferral rationale: Adds complexity; GPG users can wrap vault via scripts if needed.
- v1.1 approach: Provide GPG agent shim (if demand is high).

### X.509/OpenSSL Shim
- Compatibility layer for OpenSSL-based tools.
- Deferral rationale: Not required for MVP use cases; can be added later.
- v1.1 approach: If demand justifies.

### WebAssembly (WASM) and FFI
- Export vault logic to WebAssembly for browser-based tools.
- FFI for integration with other languages (Python, Go, Ruby, etc.).
- Deferral rationale: Adds surface area; native CLI is sufficient for MVP.
- v1.1 approach: Consider once core architecture is stable.

### Plugin System
- Extensibility mechanism for custom credential types or storage backends.
- Deferral rationale: Premature; architecture not yet proven.
- v1.1+ approach: Define plugin interface once core design is validated.

---

## Design Principles (Guiding Philosophy)

1. **Security First:** Every design decision prioritizes security over convenience.
2. **Simplicity:** Fewer features done well beats many features done poorly.
3. **Unix Philosophy:** Do one thing and do it well; integrate with standard Unix tools (SSH, Git).
4. **Auditability:** All operations are logged in a human-readable format.
5. **Transparency:** Code is open source; design decisions are documented.
6. **No Surprises:** Security properties are explicit; limitations are documented.

---

## Assumptions and Threat Model

### Assumptions
- User's master password has sufficient entropy (12+ random characters, or passphrase).
- User's machine is not compromised by malware or rootkits.
- Vault directory is stored on a volume with full-disk encryption.
- User's SSH/Git credentials are kept confidential (not shared or committed).

### What We Protect Against
- Unauthorized access to vault files (via encryption).
- Tampering with encrypted credentials (via authentication).
- Weak master passwords (via Argon2id key derivation).
- Plaintext credential leakage in logs or temporary files.
- Unauthorized SSH operations (via SSH agent protocol).

### What We Do NOT Protect Against
- Compromise of user's machine (rooted, malware).
- Weak master passwords chosen by user.
- Phishing or social engineering.
- Network-level attacks (sync is not in MVP scope).
- Quantum computers (post-quantum crypto deferred to future).

---

## Next Steps

1. **v1.0 (MVP):** Ship core vault, credential CRUD, SSH integration, audit logging.
2. **v1.1:** Add sync, platform keyring integration, import/export.
3. **v1.2+:** Add GUI, certificate management, plugin system.
4. **Future:** Post-quantum crypto, HSM support, distributed trust.


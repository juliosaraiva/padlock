# Padlock — System Design Document

**Version**: 0.1.0-draft
**Date**: 2026-01-30
**Status**: Design Phase

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Architecture Overview](#2-architecture-overview)
3. [Cryptographic Design](#3-cryptographic-design)
4. [Data Model](#4-data-model)
5. [SSH Agent Design](#5-ssh-agent-design)
6. [Commit Signing Design](#6-commit-signing-design)
7. [Sync Protocol Design](#7-sync-protocol-design)
8. [CLI Interface Design](#8-cli-interface-design)
9. [Extensibility Architecture](#9-extensibility-architecture)
10. [Language Analysis](#10-language-analysis)
11. [Security Audit Checklist](#11-security-audit-checklist)

---

## 1. Threat Model

### 1.1 System Description

Padlock is a credential management platform that stores passwords, API keys, SSH keys, certificates, TOTP seeds, and arbitrary secrets in an encrypted vault. It runs as a CLI tool and SSH agent daemon on the user's machine, and optionally syncs encrypted data across devices.

### 1.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  TRUSTED: User's Process Memory (after unlock)          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Padlock Core (decrypted secrets, keys in mem)  │    │
│  │  - mlock'd, guard-paged, zeroed on drop         │    │
│  └─────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────┤
│  SEMI-TRUSTED: Local Filesystem                         │
│  - Encrypted vault files (ciphertext only)              │
│  - Platform keyring (stores cached key material)        │
├─────────────────────────────────────────────────────────┤
│  UNTRUSTED: Network / Sync Server                       │
│  - Encrypted blobs only                                 │
│  - Server cannot decrypt, modify undetected, or forge   │
├─────────────────────────────────────────────────────────┤
│  UNTRUSTED: Other Users / Processes                     │
│  - Cannot access Unix domain socket (0600 perms)        │
│  - Cannot read vault files (0600 perms)                 │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Adversary Classes

| # | Adversary | Capability | Targets | Attack Vectors | Mitigations | Residual Risk |
|---|-----------|-----------|---------|----------------|-------------|---------------|
| 1 | **Local unprivileged attacker** | Read access to user-readable files, process listing | Vault files on disk, SSH agent socket, environment variables | Read encrypted vault files; access misconfigured socket permissions; read `/proc/PID/environ` | Vault files encrypted with XChaCha20-Poly1305 + Argon2id-derived key; socket permissions 0600; secrets never in env vars (injected via fd or temp pipe) | Attacker learns vault file exists; metadata (file count, size) may reveal usage patterns |
| 2 | **Local privileged attacker (root)** | Full system access, ptrace, memory reads, swap access | Process memory, swap/pagefile, core dumps, `/proc/PID/mem` | Read decrypted secrets from process memory; read swap; capture core dumps; attach debugger | `mlock()` to prevent swap; `prctl(PR_SET_DUMPABLE, 0)` to disable core dumps; memory guard pages; secrets zeroed immediately after use; short auto-lock timeout | Root can always read process memory. This is a **non-goal** for full defense — mitigations reduce the attack window. Platform Secure Enclave (where available) provides hardware-backed key protection even against root |
| 3 | **Remote network attacker** | MITM position, replay capability, traffic analysis | Sync protocol traffic, API calls | Intercept sync data; replay old sync payloads; correlate traffic patterns; inject malicious sync payloads | E2E encryption (sync server sees only ciphertext); authenticated encryption prevents tampering; nonces prevent replay; certificate pinning for sync transport; padding to limit traffic analysis | Traffic pattern metadata (sync timing, payload sizes) partially visible even with E2E encryption |
| 4 | **Supply chain attacker** | Compromised dependency, malicious build artifact | Build pipeline, third-party crates | Inject backdoor via compromised dependency; tamper with published binary; typosquatting | `cargo-deny` for dependency auditing; `cargo-vet` for supply chain review; reproducible builds; signed releases; minimal dependency tree; pin all dependency versions; SBOM generation | Sophisticated supply chain attacks against audited dependencies remain possible but high-cost |
| 5 | **Physical access attacker** | Stolen/seized device, offline disk access | Encrypted vault at rest | Brute-force vault passphrase offline; cold boot attack on RAM; extract from unencrypted swap | Argon2id with high memory cost (1 GiB) makes brute-force expensive; vault auto-locks on sleep/screen lock; memory zeroing reduces cold boot window; recommend full-disk encryption as defense-in-depth | Weak passphrases remain vulnerable to offline brute-force despite Argon2id. **[DECISION NEEDED]**: Should Padlock enforce a minimum passphrase strength policy? |
| 6 | **Insider threat** | Legitimate vault access, social engineering | Over-privileged access to shared vaults (future), audit log tampering | Access secrets beyond need-to-know; share secrets inappropriately; tamper with audit logs | Per-secret ACLs (future); tamper-evident audit log with chained HMACs; secret access notifications; time-limited access grants | Single-user v1 limits insider threat scope. Multi-user access control is a future concern |

### 1.4 Assets Under Protection

| Asset | Sensitivity | Storage State | In-Memory State |
|-------|-------------|---------------|-----------------|
| Passwords / API keys / tokens | Critical | Encrypted (vault) | Decrypted only during use, zeroed after |
| SSH private keys | Critical | Encrypted (vault) | Decrypted for signing only, zeroed after |
| TLS certificates + private keys | Critical | Encrypted (vault) | Decrypted for TLS handshake / signing only |
| TOTP seeds | Critical | Encrypted (vault) | Decrypted for code generation, zeroed after |
| Master passphrase | Critical | Never stored — derived via KDF | In memory only during unlock, zeroed after KDF |
| Key Encryption Key (KEK) | Critical | Encrypted by passphrase-derived key | In memory while vault is unlocked, mlock'd |
| Data Encryption Keys (DEKs) | Critical | Encrypted by KEK in vault | Decrypted per-operation, zeroed after |
| Vault metadata | Moderate | Encrypted (within vault) | Decrypted while vault is open |
| Audit log | Moderate | Append-only file, HMAC-chained | N/A |
| Sync device keys | Critical | Encrypted by KEK | In memory during sync operations only |

---

## 2. Architecture Overview

### 2.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                         PADLOCK SYSTEM                               │
│                                                                      │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐     │
│  │   CLI        │   │  SSH Agent   │   │  Git Signing Shim     │     │
│  │  Frontend    │   │  Daemon      │   │  (gpg.program proxy)  │     │
│  └──────┬───────┘   └──────┬───────┘   └───────────┬───────────┘     │
│         │                  │                        │                │
│  ───────┴──────────────────┴────────────────────────┴─────────────   │
│                        Core Library API                              │
│  ────────────────────────────────────────────────────────────────    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                      CORE LIBRARY                            │    │
│  │                                                              │    │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────────────┐  │    │
│  │  │ Vault      │  │ Crypto     │  │ Secret Engine         │  │    │
│  │  │ Manager    │  │ Engine     │  │ (generate/rotate/     │  │    │
│  │  │            │  │            │  │  expire)              │  │    │
│  │  └────────────┘  └────────────┘  └───────────────────────┘  │    │
│  │                                                              │    │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────────────┐  │    │
│  │  │ SSH Agent  │  │ Signing    │  │ Sync Engine           │  │    │
│  │  │ Protocol   │  │ Engine     │  │ (E2E encrypted)       │  │    │
│  │  │ Handler    │  │ (SSH/GPG/  │  │                       │  │    │
│  │  │            │  │  X.509)    │  │                       │  │    │
│  │  └────────────┘  └────────────┘  └───────────────────────┘  │    │
│  │                                                              │    │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────────────┐  │    │
│  │  │ Audit      │  │ Platform   │  │ Credential            │  │    │
│  │  │ Logger     │  │ Adapter    │  │ Provider              │  │    │
│  │  │            │  │ Interface  │  │ (.netrc, git-cred,    │  │    │
│  │  │            │  │            │  │  env injection)       │  │    │
│  │  └────────────┘  └────────────┘  └───────────────────────┘  │    │
│  │                                                              │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ───────────────────────────────────────────────────────────────     │
│                     Platform Adapter Layer                           │
│  ───────────────────────────────────────────────────────────────     │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │ macOS        │  │ Linux        │  │ Windows                  │   │
│  │ Keychain /   │  │ kernel       │  │ DPAPI /                  │   │
│  │ Secure       │  │ keyring /    │  │ Credential               │   │
│  │ Enclave      │  │ libsecret    │  │ Manager                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘   │
│                                                                      │
│  ───────────────────────────────────────────────────────────────     │
│                     Storage Backend Layer                            │
│  ───────────────────────────────────────────────────────────────     │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │ Local        │  │ Cloud        │  │ Self-hosted              │   │
│  │ Filesystem   │  │ Storage      │  │ Server                   │   │
│  │              │  │ (S3, GCS,    │  │ (future)                 │   │
│  │              │  │  iCloud)     │  │                          │   │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow — Unlock and Secret Access

```
User                    CLI                 Core Library            Vault (disk)
 │                       │                       │                       │
 │  padlock unlock       │                       │                       │
 │──────────────────────>│                       │                       │
 │                       │  unlock(passphrase)   │                       │
 │                       │──────────────────────>│                       │
 │                       │                       │  read vault header    │
 │                       │                       │──────────────────────>│
 │                       │                       │  header (salt, params)│
 │                       │                       │<──────────────────────│
 │                       │                       │                       │
 │                       │                       │ Argon2id(passphrase,  │
 │                       │                       │   salt) -> PDK        │
 │                       │                       │                       │
 │                       │                       │ Decrypt KEK with PDK  │
 │                       │                       │ Verify HMAC           │
 │                       │                       │                       │
 │                       │                       │ Store KEK in mlock'd  │
 │                       │                       │ memory                │
 │                       │                       │                       │
 │                       │  OK (unlocked)        │                       │
 │  unlocked             │<──────────────────────│                       │
 │<──────────────────────│                       │                       │
 │                       │                       │                       │
 │  padlock get github   │                       │                       │
 │──────────────────────>│                       │                       │
 │                       │  get("github")        │                       │
 │                       │──────────────────────>│                       │
 │                       │                       │  read encrypted entry │
 │                       │                       │──────────────────────>│
 │                       │                       │  ciphertext           │
 │                       │                       │<──────────────────────│
 │                       │                       │                       │
 │                       │                       │ Derive DEK from KEK   │
 │                       │                       │ Decrypt entry with DEK│
 │                       │                       │ Zero DEK immediately  │
 │                       │                       │                       │
 │                       │  secret (in SecretBuf)│                       │
 │  password copied      │<──────────────────────│                       │
 │<──────────────────────│                       │                       │
 │                       │                       │                       │
 │                       │                       │ Zero SecretBuf after  │
 │                       │                       │ clipboard timeout     │
```

### 2.3 Data Flow — SSH Agent Signing

```
SSH Client              Agent Socket           Core Library            Vault
 │                       │                       │                       │
 │  SSH_AUTH_SOCK connect │                       │                       │
 │──────────────────────>│                       │                       │
 │                       │                       │                       │
 │  REQUEST_IDENTITIES   │                       │                       │
 │──────────────────────>│                       │                       │
 │                       │  list_ssh_keys()      │                       │
 │                       │──────────────────────>│                       │
 │                       │                       │  read key metadata    │
 │                       │                       │──────────────────────>│
 │                       │                       │  (public keys only)   │
 │                       │                       │<──────────────────────│
 │                       │  [pub_key_1, ...]     │                       │
 │  IDENTITIES_ANSWER    │<──────────────────────│                       │
 │<──────────────────────│                       │                       │
 │                       │                       │                       │
 │  SIGN_REQUEST(key,data)                       │                       │
 │──────────────────────>│                       │                       │
 │                       │  sign(key_id, data)   │                       │
 │                       │──────────────────────>│                       │
 │                       │                       │  [confirm if policy]  │
 │                       │                       │  decrypt private key  │
 │                       │                       │  compute signature    │
 │                       │                       │  zero private key     │
 │                       │  signature            │                       │
 │  SIGN_RESPONSE        │<──────────────────────│                       │
 │<──────────────────────│                       │                       │
```

### 2.4 Design Principles

1. **Defense in depth**: Multiple layers — encrypted at rest, protected in memory, authenticated transport, audit logged.
2. **Least privilege**: Secrets decrypted only when needed, for the minimum time. DEKs derived per-operation and zeroed immediately.
3. **Zero trust sync**: The sync server is an untrusted courier. It handles only opaque encrypted blobs.
4. **Fail closed**: If authentication fails, if the vault is corrupted, if a signature cannot be verified — deny access. Never fall back to insecure defaults.
5. **No security through obscurity**: All security properties must hold even if the attacker has the source code and knows the algorithms. Security derives from key material and cryptographic properties only.
6. **Explicit user intent for signing**: Every commit-signing and SSH-signing operation requires either an unlocked vault session or an explicit confirmation, preventing silent signing of malicious content.

---

## 3. Cryptographic Design

### 3.1 Algorithm Choices

| Purpose | Algorithm | Parameters | Standard | Justification |
|---------|-----------|------------|----------|---------------|
| **Vault encryption** | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce | draft-irtf-cfrg-xchacha (widely deployed via libsodium) | 24-byte random nonce eliminates nonce management complexity. Constant-time on all platforms without hardware acceleration. For a secrets manager encrypting small payloads, the performance difference vs AES-GCM is irrelevant. No FIPS requirement for a developer tool |
| **Key derivation (passphrase)** | Argon2id | m=1 GiB, t=2, p=4, salt=16 bytes | RFC 9106 | Argon2id is the OWASP-recommended password-hashing function. 1 GiB memory cost makes GPU/ASIC attacks expensive. Hybrid mode (Argon2i first pass, Argon2d subsequent) resists both side-channel and brute-force attacks |
| **Key derivation (subkeys)** | HKDF-SHA-256 | 256-bit output, context-specific info strings | RFC 5869 | Deterministic, fast subkey derivation from the KEK for each secret entry. Info strings ensure domain separation between DEKs |
| **Key agreement (sync)** | X25519 | Curve25519 | RFC 7748 | Standard ECDH for device-to-device key exchange during sync pairing |
| **Device pairing** | SPAKE2 (balanced PAKE) | Over Curve25519, 6-digit numeric code | RFC 9382 | Allows two devices sharing a short code to establish a strong shared secret without revealing the code to eavesdroppers |
| **Vault integrity** | HMAC-SHA-256 | 256-bit key derived from KEK | RFC 2104 | Chained HMAC over vault header and entry index to detect tampering |
| **Audit log integrity** | HMAC-SHA-256 chain | Each entry's HMAC includes previous HMAC | RFC 2104 | Tamper-evident append-only log. Deletion or modification of any entry breaks the chain |
| **SSH key types** | Ed25519, ECDSA (P-256, P-384), RSA (2048, 4096) | Per key type standards | RFC 8032, FIPS 186-4, RFC 8017 | Support all common SSH key types. Ed25519 recommended as default for new keys |

### 3.2 Key Hierarchy

```
User Passphrase (never stored)
       │
       ▼
  Argon2id(passphrase, salt, m=1GiB, t=2, p=4)
       │
       ▼
  Passphrase-Derived Key (PDK) — 256 bits
       │
       ├──> Decrypt KEK blob
       │
       ▼
  Key Encryption Key (KEK) — 256 bits (randomly generated at vault creation)
       │
       ├──> HKDF(KEK, info="entry:<entry_id>") ──> DEK per secret entry
       │
       ├──> HKDF(KEK, info="audit-log") ──> Audit log HMAC key
       │
       ├──> HKDF(KEK, info="vault-integrity") ──> Vault integrity HMAC key
       │
       └──> HKDF(KEK, info="sync-identity") ──> Device sync identity key material
```

**Key Properties**:
- **Passphrase change** does not require re-encrypting all secrets. Only the KEK blob is re-encrypted with the new PDK.
- **KEK rotation**: Generate a new KEK, re-encrypt all DEKs (but not the secret data itself — DEKs are derived via HKDF from KEK, so rotation means re-deriving and re-encrypting all entry ciphertext under new DEKs). **[DECISION NEEDED]**: Whether to use HKDF-derived DEKs (simpler, deterministic, but rotation requires re-encrypting all entries) or random per-entry DEKs wrapped by KEK (rotation requires re-wrapping DEKs, not re-encrypting data).
- **Platform keyring integration**: After successful passphrase-based unlock, the KEK (or a session key derived from it) can be cached in the platform keyring (macOS Keychain, Linux kernel keyring) for passwordless subsequent unlocks until the session expires. On macOS with Secure Enclave, a P-256 key pair is generated in the Secure Enclave, and the KEK is wrapped via ECDH-derived key — tying vault access to the physical device and enabling Touch ID unlock.

### 3.3 Encryption Operations

**Encrypting a secret entry**:
1. Derive `DEK = HKDF-SHA-256(KEK, salt=entry_id, info="entry-encrypt")` — 256 bits.
2. Generate random 24-byte nonce.
3. Serialize the plaintext entry (secret value + metadata) as MessagePack.
4. `ciphertext = XChaCha20-Poly1305.Encrypt(DEK, nonce, plaintext, aad=entry_id || version)`.
5. Store: `nonce || ciphertext || tag` (tag is included in ciphertext by AEAD).
6. Zero DEK and plaintext from memory.

**Decrypting a secret entry**:
1. Derive DEK as above.
2. Read `nonce || ciphertext` from storage.
3. `plaintext = XChaCha20-Poly1305.Decrypt(DEK, nonce, ciphertext, aad=entry_id || version)`.
4. If authentication fails, return error (do not reveal partial plaintext).
5. Deserialize MessagePack to entry struct.
6. Zero DEK; return secret in `SecretBuf` (mlock'd, zeroize-on-drop).

### 3.4 Nonce Strategy

XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce. With random nonces, the birthday bound collision probability reaches 50% at approximately 2^96 messages per key. Since each entry uses a unique DEK derived via HKDF with the entry ID, nonce collision across entries is impossible even with identical random nonces. Random 24-byte nonces generated from the OS CSPRNG are safe for all practical purposes.

### 3.5 Memory Protection

| Protection | Mechanism | Platform |
|------------|-----------|----------|
| Prevent swapping | `mlock()` / `VirtualLock()` | All (Linux: requires `RLIMIT_MEMLOCK` tuning) |
| Prevent core dumps | `prctl(PR_SET_DUMPABLE, 0)` / `setrlimit(RLIMIT_CORE, 0)` | Linux, macOS |
| Guard pages | `mmap` with `PROT_NONE` guard pages surrounding secret allocations | All |
| Zeroing on drop | `zeroize` crate with volatile writes + compiler fences | All (Rust-level guarantee) |
| Type-safe secrets | `secrecy::Secret<T>` wrapper prevents accidental Debug/Display logging | Rust type system |
| Canary values | Optional canary bytes around sensitive allocations to detect overflow | All |

---

## 4. Data Model

### 4.1 Vault Directory Structure

```
~/.padlock/
├── vault.padlock          # Main vault file (single encrypted file)
├── vault.padlock.backup   # Previous version (atomic rename backup)
├── audit.log              # Tamper-evident audit log (append-only)
├── config.toml            # Padlock configuration (non-secret)
├── agent.sock             # SSH agent Unix domain socket (runtime only)
├── agent.pid              # PID file for agent daemon
└── sync/
    ├── identity.key       # Device identity key (encrypted by KEK)
    └── peers/             # Paired device public keys
        ├── <device_id_1>.pub
        └── <device_id_2>.pub
```

File permissions: `0700` for `~/.padlock/`, `0600` for all files within.

### 4.2 Vault File Format

The vault is a single file with a binary format. This avoids metadata leakage from directory/file names (a known weakness of `pass`).

```
┌─────────────────────────────────────────────────────────┐
│ Magic bytes: "PADLOCK\x00" (8 bytes)                    │
│ Format version: uint16 (2 bytes)                        │
│ Flags: uint16 (2 bytes)                                 │
├─────────────────────────────────────────────────────────┤
│ HEADER (plaintext, authenticated)                       │
│  ├─ KDF algorithm: uint8 (1 = Argon2id)                │
│  ├─ KDF params:                                         │
│  │   ├─ memory_cost: uint32 (KiB)                      │
│  │   ├─ time_cost: uint32 (iterations)                 │
│  │   ├─ parallelism: uint32                            │
│  │   └─ salt: [u8; 16]                                 │
│  ├─ Cipher: uint8 (1 = XChaCha20-Poly1305)             │
│  ├─ KEK blob:                                          │
│  │   ├─ nonce: [u8; 24]                                │
│  │   └─ encrypted_kek: [u8; 32 + 16] (key + tag)      │
│  └─ Header HMAC: [u8; 32]                              │
├─────────────────────────────────────────────────────────┤
│ ENTRY INDEX (encrypted with KEK-derived index key)      │
│  ├─ nonce: [u8; 24]                                    │
│  ├─ ciphertext: encrypted MessagePack array of:        │
│  │   [{                                                 │
│  │     id: UUID,                                        │
│  │     offset: uint64,  // byte offset in entries blob │
│  │     length: uint32,  // byte length of entry blob   │
│  │     entry_type: uint8,                               │
│  │     name_hash: [u8; 32], // HMAC(KEK, name) for     │
│  │                          // lookup without decrypt   │
│  │   }, ...]                                            │
│  └─ tag: [u8; 16]                                      │
├─────────────────────────────────────────────────────────┤
│ ENTRIES BLOB (concatenated encrypted entries)            │
│  ├─ Entry 1: nonce || encrypted_msgpack || tag          │
│  ├─ Entry 2: nonce || encrypted_msgpack || tag          │
│  └─ ...                                                 │
├─────────────────────────────────────────────────────────┤
│ VAULT INTEGRITY HMAC: [u8; 32]                          │
│  HMAC(integrity_key, header || index || entries)        │
└─────────────────────────────────────────────────────────┘
```

### 4.3 Secret Entry Schema

Each entry, after decryption from the entries blob, deserializes to:

```
Entry {
    // Identity
    id: UUID,                    // Unique identifier (UUIDv4)
    name: String,                // Human-readable name (e.g., "github-api")
    entry_type: EntryType,       // Credential, SSHKey, Certificate, TOTP, Binary

    // Core secret data (type-specific)
    data: EntryData,             // Union/enum — see below

    // Metadata
    tags: Vec<String>,           // User-defined tags for organization
    notes: Option<String>,       // Free-form notes
    url: Option<String>,         // Associated URL (for credentials)
    username: Option<String>,    // Associated username

    // Lifecycle
    created_at: Timestamp,       // ISO 8601
    modified_at: Timestamp,
    accessed_at: Timestamp,
    expires_at: Option<Timestamp>, // Optional expiry
    version: uint32,             // Incremented on each modification

    // History (optional, configurable)
    previous_versions: Vec<HistoryEntry>,  // Encrypted previous values
}

enum EntryType {
    Credential,    // Password, API key, token
    SSHKey,        // SSH key pair (private + public)
    Certificate,   // TLS/X.509 certificate + private key
    TOTP,          // TOTP seed + parameters
    Binary,        // Arbitrary binary blob (files, etc.)
    Netrc,         // .netrc-style machine/login/password
}

enum EntryData {
    Credential {
        password: SecretString,
    },
    SSHKey {
        private_key: SecretBytes,   // OpenSSH format private key
        public_key: String,          // OpenSSH format public key
        key_type: SSHKeyType,        // Ed25519, ECDSA, RSA
        fingerprint: String,         // SHA-256 fingerprint
        confirm_before_use: bool,    // Require user confirmation per signing
        lifetime: Option<Duration>,  // Auto-remove from agent after timeout
    },
    Certificate {
        certificate_pem: String,     // X.509 certificate (PEM)
        private_key: SecretBytes,    // Private key (PEM, encrypted)
        chain: Vec<String>,          // CA chain certificates (PEM)
        key_type: CertKeyType,       // RSA, ECDSA, Ed25519
    },
    TOTP {
        secret: SecretBytes,         // TOTP seed
        algorithm: TOTPAlgorithm,    // SHA1, SHA256, SHA512
        digits: u8,                  // 6 or 8
        period: u32,                 // Typically 30 seconds
        issuer: Option<String>,
    },
    Binary {
        data: SecretBytes,
        mime_type: Option<String>,
        filename: Option<String>,
    },
    Netrc {
        machine: String,             // Hostname
        login: String,
        password: SecretString,
        account: Option<String>,
    },
}
```

### 4.4 Serialization

- **In-vault serialization**: MessagePack (compact binary, well-defined schema, fast encode/decode, cross-language support).
- **CLI output**: JSON (machine-readable) or human-readable table format (default).
- **Sync wire format**: MessagePack over encrypted channel.

**[DECISION NEEDED]**: Whether to keep secret history (previous versions). Pros: recovery from accidental overwrites, audit trail. Cons: increases vault size, old secrets remain in the vault file (even encrypted). Recommended: opt-in per entry, with configurable max history depth (default: 5).

### 4.5 Vault Operations and Atomicity

All vault modifications follow an atomic write pattern:
1. Write new vault content to a temporary file (`vault.padlock.tmp`).
2. `fsync` the temporary file.
3. Rename `vault.padlock` to `vault.padlock.backup`.
4. Rename `vault.padlock.tmp` to `vault.padlock`.
5. `fsync` the directory.

This ensures the vault is never in a partially-written state.

---

## 5. SSH Agent Design

### 5.1 Protocol Implementation

Padlock implements the OpenSSH SSH agent protocol, communicating over a Unix domain socket.

**Supported message types**:

| Message Type | Code | Direction | Implementation |
|-------------|------|-----------|----------------|
| `SSH_AGENTC_REQUEST_IDENTITIES` | 11 | Client → Agent | Return public keys for all SSH key entries in the vault |
| `SSH_AGENT_IDENTITIES_ANSWER` | 12 | Agent → Client | List of (public_key_blob, comment) pairs |
| `SSH_AGENTC_SIGN_REQUEST` | 13 | Client → Agent | Decrypt the requested private key, compute signature, zero key |
| `SSH_AGENT_SIGN_RESPONSE` | 14 | Agent → Client | Return the computed signature |
| `SSH_AGENTC_ADD_IDENTITY` | 17 | Client → Agent | Import a key into the vault (requires vault to be unlocked) |
| `SSH_AGENTC_ADD_ID_CONSTRAINED` | 25 | Client → Agent | Import with lifetime/confirmation constraints |
| `SSH_AGENTC_REMOVE_IDENTITY` | 18 | Client → Agent | Remove a key from the agent's active set (not from vault) |
| `SSH_AGENTC_REMOVE_ALL_IDENTITIES` | 19 | Client → Agent | Clear all keys from the agent's active set |
| `SSH_AGENTC_EXTENSION` | 27 | Client → Agent | Support OpenSSH extensions (session-bind, restrict-destination) |
| `SSH_AGENT_SUCCESS` | 6 | Agent → Client | Operation succeeded |
| `SSH_AGENT_FAILURE` | 5 | Agent → Client | Operation failed |

### 5.2 Agent Lifecycle

```
padlock agent start
    │
    ▼
Create Unix domain socket at ~/.padlock/agent.sock (mode 0600)
Write PID to ~/.padlock/agent.pid
Print: SSH_AUTH_SOCK=~/.padlock/agent.sock; export SSH_AUTH_SOCK;
    │
    ▼
Event loop (tokio async):
    ├─ Accept connections on agent socket
    ├─ For each connection:
    │   ├─ Read message (length-prefixed, big-endian uint32)
    │   ├─ Parse message type
    │   ├─ Dispatch to handler
    │   └─ Write response
    ├─ Handle SIGTERM/SIGINT → graceful shutdown
    ├─ Handle vault lock events → clear cached keys
    └─ Handle auto-lock timeout → lock vault
```

### 5.3 Key Management Policies

| Policy | Configuration | Default |
|--------|--------------|---------|
| **Key lifetime** | Per-key timeout after which key is removed from active set | No timeout (key available while vault is unlocked) |
| **Confirm before use** | Require user confirmation (via terminal prompt or platform auth) before each signing | Off (configurable per key) |
| **Auto-lock** | Lock vault after inactivity period | 15 minutes |
| **Max keys** | Maximum number of keys loaded in agent | Unlimited |
| **Agent forwarding safety** | Support `restrict-destination` and `session-bind` extensions | Enabled |
| **FIDO/U2F passthrough** | Forward FIDO security key operations | **[DECISION NEEDED]**: Whether to support FIDO key types or defer to native ssh-agent for hardware keys |

### 5.4 Confirmation Flow

When `confirm_before_use` is set for a key:

1. Agent receives `SIGN_REQUEST`.
2. Agent checks if the vault is unlocked.
3. Agent prompts the user via:
   - **Terminal**: Print prompt to controlling terminal (if agent was started interactively).
   - **Platform auth**: macOS Touch ID / system password dialog via Security framework.
   - **SSH_ASKPASS**: If `SSH_ASKPASS` is set, invoke it (compatibility with OpenSSH behavior).
4. If confirmed, proceed with signing.
5. If denied, return `SSH_AGENT_FAILURE`.

### 5.5 Integration

**Shell integration** (added to `.bashrc`/`.zshrc`/`.config/fish/config.fish`):

```bash
# padlock SSH agent
if [ -S "$HOME/.padlock/agent.sock" ]; then
    export SSH_AUTH_SOCK="$HOME/.padlock/agent.sock"
fi
```

Or via `padlock agent shell-env` which prints the appropriate export command.

**Compatibility**: The agent is fully compatible with OpenSSH's `ssh`, `scp`, `sftp`, `git` (via SSH transport), and any tool that respects `SSH_AUTH_SOCK`.

---

## 6. Commit Signing Design

### 6.1 Overview

Padlock supports signing Git commits and tags through all three Git signing backends. The SSH-based approach is the primary recommendation as it leverages the SSH agent directly with no additional protocol implementation.

### 6.2 SSH Signing (Primary — Recommended)

**How it works**:

1. The user stores an SSH key (Ed25519 recommended) in Padlock.
2. Padlock's SSH agent exposes this key via `SSH_AUTH_SOCK`.
3. Git is configured with:
   ```gitconfig
   [gpg]
       format = ssh
   [user]
       signingKey = ssh-ed25519 AAAAC3... (public key from Padlock)
   [gpg "ssh"]
       allowedSignersFile = ~/.config/git/allowed_signers
   [commit]
       gpgSign = true
   [tag]
       gpgSign = true
   ```
4. When `git commit` runs:
   - Git invokes `ssh-keygen -Y sign -f <pubkey_file> -n git -O hashalg=sha512 <data>`.
   - `ssh-keygen` connects to `SSH_AUTH_SOCK` (Padlock's agent).
   - Padlock decrypts the private key, computes the signature, and returns it.
   - The private key is zeroed from memory.
5. The SSH signature is embedded in the commit object.

**Verification**:
- Git uses `ssh-keygen -Y verify` with the `allowedSignersFile`.
- Padlock can manage and update the allowed signers file via `padlock git allowed-signers` which exports trusted public keys.

### 6.3 GPG Signing (Compatibility)

For environments that require GPG-format signatures, Padlock provides a `padlock-gpg-shim` binary that implements the subset of the `gpg` CLI interface that Git uses.

**Shimmed interface**:

| Git invokes | Padlock shim handles |
|-------------|---------------------|
| `gpg --status-fd=2 -bsau <key_id>` (stdin = data to sign) | Look up the GPG key in the vault, decrypt private key, compute OpenPGP-format detached signature, output to stdout, write status to fd 2 |
| `gpg --status-fd=1 --keyid-format=long --verify <sig> -` (stdin = signed data) | Verify the OpenPGP signature against trusted keys in the vault |
| `gpg --list-keys` / `gpg --list-secret-keys` | List GPG keys stored in the vault |

**Configuration**:
```gitconfig
[gpg]
    format = openpgp
    program = padlock-gpg-shim
```

**Trade-offs**: Implementing a full GPG shim is complex. The shim only handles the specific invocations Git makes. For full GPG functionality, users should use actual GPG. **[DECISION NEEDED]**: Whether to implement the GPG shim in v1 or defer to a later release, recommending SSH signing for v1.

### 6.4 X.509/S/MIME Signing

For enterprise environments with PKI infrastructure, Padlock can sign commits using X.509 certificates stored in the vault.

**Implementation**: Similar to the GPG shim approach — a `padlock-x509-shim` that handles the `gpgsm` interface subset used by Git.

```gitconfig
[gpg]
    format = x509
    x509.program = padlock-x509-shim
```

**[DECISION NEEDED]**: X.509 signing priority. Likely deferred to post-v1 unless enterprise demand is clear.

### 6.5 Key Selection Policy

When a user has multiple signing keys, Padlock determines which key to use:

1. **Per-repository configuration**: `padlock git setup` can write per-repo `.git/config` with the appropriate `user.signingKey`.
2. **Key tagging**: Keys in the vault can be tagged with patterns (e.g., `git:work`, `git:personal`).
3. **Gitconfig matching**: Padlock respects Git's `includeIf` directives — different signing keys for `~/work/` vs `~/personal/`.
4. **Interactive selection**: If multiple keys match and no default is configured, prompt the user.
5. **Default key**: A vault-level default signing key can be configured via `padlock config set git.default-signing-key <key_name>`.

### 6.6 Setup Command

```bash
# Configure the current repo for SSH signing with Padlock
$ padlock git setup
  ✓ Found SSH key "personal-ed25519" tagged with git:default
  ✓ Set gpg.format = ssh
  ✓ Set user.signingKey = ssh-ed25519 AAAAC3...
  ✓ Set gpg.ssh.allowedSignersFile = ~/.config/git/allowed_signers
  ✓ Set commit.gpgSign = true
  ✓ Updated allowed_signers file with 3 trusted keys

# Or specify a key
$ padlock git setup --key work-signing-key --scope global
```

### 6.7 Signing Protection

- **Confirmation**: When `confirm_before_use` is set for a signing key, Padlock prompts before each signing operation (same mechanism as SSH agent confirmation).
- **Audit logging**: Every signing operation is recorded in the audit log with: timestamp, key used, data hash (not the data itself), source (git-commit, git-tag, ssh-auth).
- **Rate limiting**: Optional rate limit on signing operations to detect automated abuse (e.g., a compromised process rapidly signing content).

---

## 7. Sync Protocol Design

### 7.1 Design Goals

1. **End-to-end encrypted**: The sync server never sees plaintext secrets or metadata.
2. **Server-untrusted**: A compromised server cannot decrypt, forge, or undetectably modify data.
3. **Conflict resolution**: Handle concurrent edits from multiple devices.
4. **Bandwidth efficient**: Transfer only changed entries, not the full vault.
5. **Offline capable**: Devices can operate fully offline and sync when connectivity returns.

### 7.2 Device Pairing

New devices are paired using a PAKE protocol to establish mutual trust without relying on the sync server.

**Pairing flow**:

```
Device A (existing)                    Device B (new)
       │                                      │
       │  padlock sync pair                   │
       │  Display: "Pairing code: 847 291"    │
       │                                      │
       │                                      │  padlock sync join
       │                                      │  Enter code: 847291
       │                                      │
       │◄──────── SPAKE2 exchange ───────────►│
       │  (6-digit code as shared password)   │
       │                                      │
       │  Derive shared_secret via SPAKE2     │  Derive shared_secret
       │                                      │
       │  Encrypted channel established       │
       │                                      │
       │  Send: device_A_identity_pubkey      │
       │  Send: encrypted_KEK (wrapped with   │
       │        shared_secret)                │
       │  Send: vault snapshot                │
       │                                      │
       │                                      │  Receive and decrypt KEK
       │                                      │  Import vault snapshot
       │                                      │  Generate device_B_identity_key
       │                                      │  Send: device_B_identity_pubkey
       │                                      │
       │  Store device_B as trusted peer      │  Store device_A as trusted peer
       │                                      │
       │  Pairing complete ✓                  │  Pairing complete ✓
```

**Security properties**:
- The 6-digit code provides ~20 bits of entropy, which is sufficient for an interactive PAKE (SPAKE2 is resistant to offline dictionary attacks against the code).
- The code is single-use and time-limited (5 minutes).
- An attacker would need to be an active MITM during the pairing window AND guess the code.

### 7.3 Sync Wire Protocol

After pairing, devices sync via encrypted messages. The sync protocol is transport-agnostic — it can run over a relay server, direct LAN connection, or cloud storage.

**Sync message format**:

```
SyncMessage {
    sender_device_id: UUID,
    sequence_number: uint64,          // Monotonically increasing per device
    timestamp: Timestamp,
    payload: EncryptedPayload,        // XChaCha20-Poly1305 encrypted
    signature: Ed25519Signature,      // Signed with device identity key
}

EncryptedPayload (after decryption) {
    operations: Vec<SyncOperation>,
}

enum SyncOperation {
    UpsertEntry {
        entry_id: UUID,
        encrypted_entry: Vec<u8>,     // Entry encrypted with DEK as usual
        version: uint64,              // Lamport clock
        entry_hash: [u8; 32],         // SHA-256 of plaintext entry for dedup
    },
    DeleteEntry {
        entry_id: UUID,
        version: uint64,
    },
    UpdateMetadata {
        entry_id: UUID,
        field: String,
        value: Vec<u8>,               // Encrypted
        version: uint64,
    },
}
```

### 7.4 Conflict Resolution

Padlock uses a **vector clock** per entry for conflict detection and **last-writer-wins (LWW) with user override** for resolution.

**Algorithm**:
1. Each device maintains a vector clock: `{device_A: 5, device_B: 3}` per entry.
2. When syncing, compare vector clocks:
   - If one strictly dominates the other → take the dominant version (no conflict).
   - If neither dominates (concurrent edits) → **conflict**.
3. On conflict:
   - Auto-resolve: Take the version with the latest wall-clock timestamp (LWW).
   - Flag for user review: Mark the entry as conflicted, preserve both versions.
   - User resolves manually via `padlock sync conflicts`.

**[DECISION NEEDED]**: Default conflict resolution strategy — auto-LWW (simpler, risk of data loss) vs always-flag (safer, more user friction).

### 7.5 Sync Backends

| Backend | Transport | Use Case |
|---------|-----------|----------|
| **File-based** | Shared directory (Dropbox, iCloud Drive, Syncthing) | Simple, no server needed. Devices write encrypted blobs to shared folder |
| **Cloud storage** | S3, GCS, Azure Blob | Self-managed. Devices push/pull encrypted blobs via object storage API |
| **Padlock relay server** (future) | WebSocket over TLS | Real-time sync with push notifications. Server stores only encrypted blobs |

For v1, file-based sync is the primary target. The sync engine writes encrypted operation logs to a shared directory, and each device reads and applies operations it hasn't seen.

### 7.6 Metadata Leakage Minimization

- **Entry IDs** are UUIDs — they reveal nothing about the secret type or name.
- **File names** in the sync directory are opaque hashes: `SHA-256(device_id || sequence_number)`.
- **Payload sizes** are padded to fixed block sizes (1 KiB increments) to prevent size-based fingerprinting.
- **Timestamps** in sync messages use coarse granularity (minute resolution) to reduce timing analysis.

---

## 8. CLI Interface Design

### 8.1 Command Structure

```
padlock <command> [subcommand] [options] [arguments]
```

**Top-level commands**:

| Command | Description |
|---------|-------------|
| `padlock init` | Initialize a new vault |
| `padlock unlock` | Unlock the vault with passphrase |
| `padlock lock` | Lock the vault (zero KEK from memory) |
| `padlock status` | Show vault status (locked/unlocked, entry count, agent status) |
| `padlock get <name>` | Retrieve a secret |
| `padlock set <name>` | Store or update a secret |
| `padlock rm <name>` | Delete a secret |
| `padlock ls` | List all entries (names, types, tags — no secret values) |
| `padlock search <query>` | Search entries by name, tags, or notes |
| `padlock generate` | Generate a random password or key |
| `padlock ssh` | SSH key management subcommands |
| `padlock cert` | Certificate management subcommands |
| `padlock totp` | TOTP management subcommands |
| `padlock git` | Git signing integration subcommands |
| `padlock agent` | SSH agent daemon subcommands |
| `padlock sync` | Cross-device sync subcommands |
| `padlock audit` | View audit log |
| `padlock export` | Export entries (encrypted or plaintext) |
| `padlock import` | Import from other tools (.netrc, ssh keys, gpg, 1password, bitwarden) |
| `padlock config` | Configuration management |
| `padlock completions` | Generate shell completions |

### 8.2 Subcommands

**SSH key management**:
```
padlock ssh list                       # List SSH keys in vault
padlock ssh add <name> [--type ed25519|ecdsa|rsa] [--bits 4096]
                                       # Generate and store new SSH key
padlock ssh import <name> <key_file>   # Import existing SSH key
padlock ssh export <name>              # Export public key to stdout
padlock ssh fingerprint <name>         # Show key fingerprint
padlock ssh config <name>              # Show SSH config snippet for this key
```

**Certificate management**:
```
padlock cert list                      # List certificates
padlock cert add <name> --cert <pem> --key <pem> [--chain <pem>]
padlock cert generate <name> --cn <common_name> [--self-signed]
padlock cert export <name>             # Export certificate (PEM)
padlock cert verify <name>             # Verify certificate chain
padlock cert renew <name>              # Renew via ACME (future)
```

**TOTP management**:
```
padlock totp add <name> --secret <base32> [--algorithm sha1] [--digits 6] [--period 30]
padlock totp add <name> --uri <otpauth://...>
padlock totp get <name>                # Generate current TOTP code
padlock totp list                      # List TOTP entries
```

**Git signing**:
```
padlock git setup [--key <name>] [--scope global|local]   # Configure git signing
padlock git allowed-signers [--output <file>]             # Export allowed signers
padlock git verify <commit>                               # Verify a commit signature
```

**Agent management**:
```
padlock agent start [--foreground]     # Start SSH agent daemon
padlock agent stop                     # Stop agent daemon
padlock agent status                   # Show agent status
padlock agent shell-env                # Print shell environment variables
padlock agent list                     # List keys currently in agent
```

**Sync**:
```
padlock sync init --backend <file|s3>  # Initialize sync
padlock sync pair                      # Generate pairing code
padlock sync join                      # Join using pairing code
padlock sync push                      # Push local changes
padlock sync pull                      # Pull remote changes
padlock sync status                    # Show sync status
padlock sync conflicts                 # List and resolve conflicts
padlock sync devices                   # List paired devices
padlock sync revoke <device_id>        # Revoke a paired device
```

### 8.3 Output Modes

All commands support:

| Flag | Output |
|------|--------|
| (default) | Human-readable formatted text |
| `--json` | Machine-readable JSON |
| `--quiet` / `-q` | Minimal output (just the secret value, for piping) |
| `--no-color` | Disable colored output |

### 8.4 Example Usage Flows

**Initial setup**:
```bash
$ padlock init
Enter vault passphrase: ••••••••••••
Confirm passphrase: ••••••••••••
Vault created at ~/.padlock/vault.padlock
KDF: Argon2id (m=1GiB, t=2, p=4)
Cipher: XChaCha20-Poly1305

$ padlock ssh add personal --type ed25519
Generated Ed25519 key: SHA256:xK3h...
Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... padlock:personal

$ padlock agent start
SSH agent started at /Users/julio/.padlock/agent.sock
To use: export SSH_AUTH_SOCK=/Users/julio/.padlock/agent.sock

$ padlock git setup --key personal --scope global
✓ Configured SSH signing globally
```

**Daily workflow**:
```bash
$ padlock get github-token -q | gh auth login --with-token
# Token piped directly, never displayed

$ ssh git@github.com
# Agent provides key from vault automatically

$ git commit -m "feat: add login endpoint"
# Padlock agent signs the commit via SSH agent protocol

$ padlock totp get aws-console
123456 (expires in 18s)
```

**Credential provider for tools expecting .netrc**:
```bash
$ padlock get --netrc-format github.com
machine github.com
  login julio
  password ghp_xxxx...

# Or via process substitution:
$ curl --netrc-file <(padlock get --netrc-format github.com) https://api.github.com/user
```

**Environment variable injection**:
```bash
# Run a command with secrets injected as env vars
$ padlock exec --env AWS_ACCESS_KEY_ID=aws/access-key \
               --env AWS_SECRET_ACCESS_KEY=aws/secret-key \
               -- aws s3 ls

# The secrets are injected via the process environment, not via shell
# They do not appear in shell history or /proc/self/cmdline
```

### 8.5 Shell Completions

Generated via `padlock completions <shell>` for `bash`, `zsh`, and `fish`. Completions include:
- Command and subcommand names.
- Entry names (for `get`, `set`, `rm`, `ssh`, etc.) — completed by querying the vault index.
- Tag names for `--tag` flags.
- Key names for `--key` flags.

### 8.6 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Vault locked (authentication required) |
| 3 | Entry not found |
| 4 | Authentication failed (wrong passphrase) |
| 5 | Vault integrity error (tampering detected) |
| 6 | Sync conflict |
| 10 | Agent not running |

---

## 9. Extensibility Architecture

### 9.1 Core Library Boundary

The core library (`padlock-core`) is a standalone Rust crate with no CLI, no terminal I/O, and no platform-specific code in its public API. All platform-specific behavior is injected via trait objects.

```
padlock-core (library crate)
├── vault/           # Vault open/close/read/write operations
├── crypto/          # Encryption, decryption, KDF, HMAC
├── entries/         # Entry CRUD, search, serialization
├── ssh_agent/       # SSH agent protocol message parsing and handling
├── signing/         # Git commit/tag signing logic
├── sync/            # Sync protocol, conflict resolution
├── audit/           # Audit log read/write
├── generate/        # Secret/password/key generation
│
├── traits/          # Abstraction boundaries
│   ├── PlatformKeyring     # Store/retrieve cached keys from OS keyring
│   ├── UserConfirmation    # Prompt user for confirmation (signing, etc.)
│   ├── StorageBackend      # Read/write vault files (local, cloud, etc.)
│   └── SyncTransport       # Send/receive sync messages
│
└── types/           # Shared types (Entry, EntryData, SecretBuf, etc.)
```

### 9.2 Frontend Integration Pattern

Each frontend implements the trait interfaces and passes them to the core library:

```
┌─────────────────────┐     ┌─────────────────────┐
│   CLI Frontend      │     │   macOS App (future) │
│   (padlock-cli)     │     │   (SwiftUI)          │
│                     │     │                      │
│ impl UserConfirm:   │     │ impl UserConfirm:    │
│   terminal prompt   │     │   Touch ID dialog    │
│                     │     │                      │
│ impl PlatformKey:   │     │ impl PlatformKey:    │
│   secret-tool /     │     │   Keychain +         │
│   security CLI      │     │   Secure Enclave     │
│                     │     │                      │
│ impl StorageBack:   │     │ impl StorageBack:    │
│   std::fs           │     │   FileManager        │
│                     │     │                      │
└────────┬────────────┘     └────────┬─────────────┘
         │                           │
         └──────────┬────────────────┘
                    │
            ┌───────▼────────┐
            │  padlock-core  │
            │  (library)     │
            └────────────────┘
```

### 9.3 FFI Layer

For non-Rust frontends, `padlock-core` is exposed via UniFFI (Mozilla's cross-language FFI tool):

| Target | FFI Mechanism | Generated Bindings |
|--------|---------------|--------------------|
| **Swift (macOS/iOS)** | UniFFI → Swift package | Idiomatic Swift structs, enums, async functions |
| **Kotlin (Android)** | UniFFI → Kotlin package | Idiomatic Kotlin data classes, coroutines |
| **Python** | UniFFI → Python module | Python classes with type hints |
| **C/C++** | `cbindgen` → C header | C-compatible function signatures, opaque pointers |
| **WASM (web)** | `wasm-pack` + `wasm-bindgen` | JavaScript/TypeScript API | Uses RustCrypto (pure Rust) for crypto in WASM — `ring` does not compile to WASM |

**UniFFI interface definition** (simplified):

```
namespace padlock {
    // Vault operations
    [Throws=PadlockError]
    Vault open_vault(string path, string passphrase);

    // Entry operations
    [Throws=PadlockError]
    Entry get_entry(Vault vault, string name);

    [Throws=PadlockError]
    void set_entry(Vault vault, string name, EntryData data);
};
```

### 9.4 Plugin Architecture (Future)

**[DECISION NEEDED]**: Whether to support plugins (e.g., custom secret backends, custom sync transports). If yes, the recommended approach is a trait-based plugin system compiled as dynamic libraries (`.so`/`.dylib`) loaded at runtime. For v1, the built-in backends are sufficient.

### 9.5 Platform Adapter Details

**macOS**:
- **Keychain**: Store cached KEK or session token via `Security.framework` (`SecItemAdd`/`SecItemCopyMatching`). The item's access control can require Touch ID.
- **Secure Enclave**: Generate a P-256 key in the Secure Enclave. Use ECDH between the SE key and an ephemeral key to derive a wrapping key for the KEK. This ties vault unlock to the physical device and enables biometric authentication.
- **Notifications**: Use `NSDistributedNotificationCenter` to notify other Padlock processes of vault lock/unlock events.

**Linux**:
- **Kernel keyring**: `keyctl` / `add_key(2)` to cache KEK in the session or user keyring. Keys are in kernel memory, harder to extract than userspace.
- **libsecret / GNOME Keyring**: Alternative for desktop Linux via the Secret Service D-Bus API.
- **systemd integration**: `padlock agent` can be managed as a systemd user service (`~/.config/systemd/user/padlock-agent.service`).

**Windows** (future):
- **DPAPI**: `CryptProtectData`/`CryptUnprotectData` for KEK caching.
- **Windows Hello**: Biometric authentication for vault unlock.
- **Named pipe**: SSH agent socket equivalent on Windows.

---

## 10. Language Analysis

### 10.1 Weighted Criteria Evaluation

| # | Criterion | Weight | Rust Score | Go Score | Rust Weighted | Go Weighted | Confidence |
|---|-----------|--------|-----------|----------|---------------|-------------|------------|
| 1 | Memory safety guarantees | 25% | 10 | 7 | 2.50 | 1.75 | 9/10 |
| 2 | Cryptographic library ecosystem | 20% | 9 | 8 | 1.80 | 1.60 | 8/10 |
| 3 | Cross-platform FFI capability | 15% | 10 | 4 | 1.50 | 0.60 | 9/10 |
| 4 | WASM compilation support | 10% | 9 | 4 | 0.90 | 0.40 | 9/10 |
| 5 | Async runtime for SSH agent | 10% | 7 | 9 | 0.70 | 0.90 | 8/10 |
| 6 | Binary size and distribution | 5% | 9 | 8 | 0.45 | 0.40 | 9/10 |
| 7 | Developer ecosystem and hiring | 5% | 7 | 9 | 0.35 | 0.45 | 8/10 |
| 8 | Build times and DX | 5% | 6 | 9 | 0.30 | 0.45 | 9/10 |
| 9 | Secure memory handling | 5% | 9 | 5 | 0.45 | 0.25 | 9/10 |
| | **TOTAL** | **100%** | | | **8.95** | **6.80** | |

### 10.2 Criterion Details

**1. Memory Safety (25%) — Rust: 10, Go: 7**

Rust's ownership/borrowing model provides compile-time guarantees against use-after-free, double-free, buffer overflows, and data races. For cryptographic code handling secrets in memory, this is the strongest guarantee available. Go's garbage collector prevents use-after-free and buffer overflows at runtime, but data races are possible (and are undefined behavior per the Go memory model). The GC introduces uncertainty about when secret memory is actually freed, and goroutine stack growth can silently copy stack-allocated secrets without zeroing the original.

**2. Crypto Ecosystem (20%) — Rust: 9, Go: 8**

Both ecosystems cover all algorithms Padlock needs (Argon2id, XChaCha20-Poly1305, AES-256-GCM, Ed25519, X25519, HKDF). Rust gets a slight edge for `ring`'s misuse-resistant API design, `aws-lc-rs` for FIPS compliance, and the deeper integration between RustCrypto crates and Rust's type system (e.g., `zeroize` derive macros). Go's stdlib crypto is solid and well-audited. Go 1.24+ adds native FIPS support via BoringCrypto.

**3. Cross-Platform FFI (15%) — Rust: 10, Go: 4**

This is the largest differentiator. Padlock's architecture as a core library consumed by future Swift, Kotlin, Python, and WASM frontends maps directly to Rust's FFI strengths. UniFFI generates idiomatic bindings for Swift and Kotlin with automatic memory management. Mozilla's `application-services` project — a Rust core for Firefox Sync (passwords, credentials) consumed by Swift/Kotlin — is a direct precedent. Go's cgo embeds the entire Go runtime (~5-10 MB) in every shared library consumer, gomobile supports only a restricted type subset, and loading multiple Go shared libraries in one process is unsupported.

**4. WASM (10%) — Rust: 9, Go: 4**

Rust WASM produces 100-300 KB binaries with full crypto support (RustCrypto is pure Rust). Go WASM produces 5-15 MB binaries (full Go runtime). TinyGo reduces this but breaks many crypto stdlib packages. For a future web-based vault interface, Rust WASM is the only practical choice.

**5. Async Runtime (10%) — Rust: 7, Go: 9**

Go's goroutine model is simpler and more readable for the SSH agent daemon use case. `golang.org/x/crypto/ssh/agent` provides a nearly turnkey implementation. Rust's tokio is equally capable but requires understanding async/await, `Pin`, `Send` bounds, and the colored function problem. The SSH agent is a relatively simple daemon — this criterion favors Go but not decisively.

**6-8. Binary Size, Ecosystem, Build Times (5% each)**

Go has faster build times (5-15s vs 30-120s clean) and a slightly larger hiring pool. Rust produces smaller binaries (3-8 MB vs 8-15 MB). Both produce single static binaries with no runtime dependencies.

**9. Secure Memory (5%) — Rust: 9, Go: 5**

Rust's `zeroize` + `secrecy` crates integrate with the type system and the deterministic `Drop` trait. Secrets wrapped in `Secret<T>` are guaranteed to be zeroed when they go out of scope, cannot be accidentally logged via `Debug`/`Display`, and are not subject to GC relocation. Go's `memguard` is well-designed but fights against the language — the GC can copy secrets during compaction, goroutine stack growth silently copies stack data, and there is no `Drop` equivalent (Go finalizers are not guaranteed to run promptly).

### 10.3 Recommendation: Rust

**Rust is recommended** with a weighted score of 8.95 vs Go's 6.80. The decisive factors:

1. **FFI is the architecture's linchpin.** Padlock is designed as a core library with multiple frontends. Rust + UniFFI is purpose-built for this pattern, with Mozilla's application-services as a direct precedent.
2. **Memory safety for crypto is categorically stronger.** Deterministic destruction, no GC secret copies, compile-time data race prevention.
3. **WASM is a clear Rust advantage.** The future web vault frontend requires a small, fast WASM module. Rust delivers; Go does not.
4. **Secure memory handling is fundamentally more sound.** `zeroize` + `secrecy` + `Drop` > `memguard` fighting the GC.

**Where Go would be preferable**: If Padlock were a standalone CLI tool with no library/FFI requirement and no WASM target, and the team had deep Go experience. Go's `x/crypto/ssh/agent` and simpler concurrency model would then outweigh Rust's type-system advantages.

### 10.4 Recommended Rust Crate Stack

| Concern | Crate | Notes |
|---------|-------|-------|
| AEAD encryption | `chacha20poly1305` (RustCrypto) | XChaCha20-Poly1305, pure Rust, WASM-compatible |
| AES-GCM (optional/FIPS) | `aes-gcm` (RustCrypto) or `aws-lc-rs` | HW-accelerated, FIPS via aws-lc-rs |
| Key derivation | `argon2` (RustCrypto) | Argon2id, pure Rust |
| HKDF | `hkdf` (RustCrypto) | SHA-256 based |
| HMAC | `hmac` + `sha2` (RustCrypto) | |
| Secret handling | `secrecy` + `zeroize` | Type-safe, zero-on-drop |
| Memory protection | `memsec` | mlock, guard pages |
| Serialization | `serde` + `rmp-serde` (MessagePack) | Fast, compact |
| CLI | `clap` | Derive-based argument parsing |
| Async runtime | `tokio` | SSH agent daemon |
| SSH protocol | `russh` | SSH agent protocol messages |
| UUID | `uuid` | UUIDv4 generation |
| FFI | `uniffi` | Swift/Kotlin/Python bindings |
| WASM | `wasm-pack` + `wasm-bindgen` | Web target |
| Random | `rand` + `getrandom` | CSPRNG |
| Ed25519 | `ed25519-dalek` | Signing |
| X25519 | `x25519-dalek` | Key agreement |
| SPAKE2 | `spake2` | Device pairing |

---

## 11. Security Audit Checklist

### 11.1 Pre-Release Security Verification

| # | Check | Category | Status |
|---|-------|----------|--------|
| 1 | Every cryptographic algorithm choice references a current, non-deprecated standard (RFC 9106, RFC 8439, NIST SP 800-38D, RFC 5869, RFC 7748, RFC 8032) | Crypto | ☐ |
| 2 | Threat model covers all six adversary classes (local unpriv, local priv, remote, supply chain, physical, insider) | Threat Model | ☐ |
| 3 | Sync protocol is end-to-end encrypted — server is untrusted and cannot decrypt, forge, or undetectably modify data | Sync | ☐ |
| 4 | SSH agent is compatible with OpenSSH's expected behavior — test with `ssh`, `scp`, `sftp`, `git` | SSH Agent | ☐ |
| 5 | Architecture allows adding a new frontend (macOS, mobile, web) without changing the core library | Architecture | ☐ |
| 6 | Language recommendation is justified by weighted scoring against Padlock's specific requirements, not preference | Language | ☐ |
| 7 | No secret is ever written to disk in plaintext, even temporarily — verify with strace/dtrace on all write paths | Data Protection | ☐ |
| 8 | Memory containing secrets is zeroed after use — verify with memory dumps and `zeroize` integration tests | Data Protection | ☐ |
| 9 | The design does not depend on security-through-obscurity anywhere — all security properties hold with full source access | Design | ☐ |
| 10 | Commit signing works with all three Git signing backends (SSH, GPG, X.509) | Signing | ☐ |
| 11 | Signing operations require explicit user intent — no silent signing of arbitrary content | Signing | ☐ |

### 11.2 Implementation Security Checks

| # | Check | Category |
|---|-------|----------|
| 12 | Argon2id parameters are at least m=256 MiB, t=3, p=4 (configurable upward) | Crypto |
| 13 | Random nonces are generated from OS CSPRNG (`getrandom` / `/dev/urandom`) | Crypto |
| 14 | AEAD authentication is verified before any plaintext is processed or returned | Crypto |
| 15 | Vault file permissions are 0600; vault directory permissions are 0700 | Filesystem |
| 16 | SSH agent socket permissions are 0600 | Filesystem |
| 17 | `prctl(PR_SET_DUMPABLE, 0)` is set on Linux to prevent core dumps | Memory |
| 18 | `mlock()` is used for all buffers containing key material or decrypted secrets | Memory |
| 19 | `setrlimit(RLIMIT_CORE, 0)` is set to prevent core dumps | Memory |
| 20 | Passphrase is zeroed from memory immediately after KDF computation | Memory |
| 21 | DEKs are zeroed from memory immediately after encrypt/decrypt operation | Memory |
| 22 | Private keys are zeroed from memory after SSH signing operation completes | Memory |
| 23 | Clipboard is cleared after configurable timeout (default: 45 seconds) | Clipboard |
| 24 | Vault write operations are atomic (tmp file → fsync → rename) | Data Integrity |
| 25 | Audit log entries are HMAC-chained — tampering with any entry breaks the chain | Audit |
| 26 | `unsafe` blocks are minimized and documented; each `unsafe` block has a safety comment | Code Quality |
| 27 | All dependencies are pinned and audited via `cargo-deny` and `cargo-vet` | Supply Chain |
| 28 | Builds are reproducible — same source produces identical binary | Supply Chain |
| 29 | Binary releases are signed with a release key | Distribution |
| 30 | No secret data appears in error messages, log output, or debug traces | Information Leakage |
| 31 | `Secret<T>` wrapper is used for all sensitive values — `Debug`/`Display` impls are redacted | Information Leakage |
| 32 | Auto-lock timeout is enforced (default: 15 minutes of inactivity) | Session Management |
| 33 | Agent forwarding extensions (`session-bind`, `restrict-destination`) are supported | SSH Agent |
| 34 | SPAKE2 pairing codes are time-limited (5 minutes) and single-use | Sync |
| 35 | Sync payloads are padded to fixed block sizes to prevent size-based fingerprinting | Sync |

### 11.3 Testing Requirements

| # | Test Category | Description |
|---|---------------|-------------|
| 36 | Crypto round-trip | Encrypt → decrypt produces identical plaintext for all entry types |
| 37 | Wrong passphrase | Decryption with wrong passphrase fails with authentication error, not garbled plaintext |
| 38 | Vault corruption | Modifying any byte of the vault file is detected by integrity HMAC |
| 39 | Entry tampering | Modifying any byte of an encrypted entry is detected by AEAD tag |
| 40 | Nonce uniqueness | 1 million encryptions produce no duplicate nonces (statistical test) |
| 41 | Memory zeroing | After `SecretBuf` drop, a memory scan finds no residual secret data |
| 42 | Agent protocol conformance | OpenSSH `ssh-add -l`, `ssh`, `ssh-keygen -Y sign` all work against Padlock agent |
| 43 | Concurrent agent access | Multiple simultaneous SSH connections handled correctly |
| 44 | Sync conflict resolution | Concurrent edits from two devices are detected and resolved |
| 45 | Atomic write recovery | Kill process during vault write → vault is either old or new, never corrupt |
| 46 | Passphrase change | After passphrase change, old passphrase fails, new passphrase succeeds, all entries intact |
| 47 | Cross-platform build | CI builds and tests on Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64 |
| 48 | Fuzzing | Fuzz the SSH agent message parser, vault file parser, and MessagePack deserializer |
| 49 | WASM build | Core library compiles to WASM and crypto operations produce correct results |

---

## Open Design Decisions

The following decisions are flagged throughout this document and require human input:

| # | Decision | Section | Options | Recommendation |
|---|----------|---------|---------|----------------|
| 1 | Should Padlock enforce minimum passphrase strength? | Threat Model §1.3 | (a) Enforce minimum entropy, (b) Warn but allow weak, (c) No enforcement | (b) Warn but allow — respect user autonomy while educating |
| 2 | HKDF-derived DEKs vs random DEKs wrapped by KEK? | Crypto Design §3.2 | (a) HKDF-derived: simpler, deterministic, rotation re-encrypts all entries. (b) Random + wrap: rotation re-wraps DEKs only, entries untouched | (b) Random DEKs wrapped by KEK — enables efficient key rotation |
| 3 | Should v1 include the GPG signing shim? | Commit Signing §6.3 | (a) Include GPG shim in v1, (b) Defer to post-v1, SSH signing only | (b) Defer — SSH signing covers the primary use case |
| 4 | Should v1 include X.509 signing? | Commit Signing §6.4 | (a) Include in v1, (b) Defer | (b) Defer — enterprise feature, limited v1 demand |
| 5 | Default sync conflict resolution strategy? | Sync §7.4 | (a) Auto LWW, (b) Always flag for user, (c) Configurable | (c) Configurable, default to auto-LWW with notification |
| 6 | Support FIDO/U2F key passthrough in agent? | SSH Agent §5.3 | (a) Support in v1, (b) Defer | (b) Defer — users can fall back to native ssh-agent for FIDO keys |
| 7 | Secret history (previous versions)? | Data Model §4.4 | (a) Always keep history, (b) Opt-in per entry, (c) Never | (b) Opt-in with max depth of 5 |
| 8 | Plugin architecture? | Extensibility §9.4 | (a) Design plugin system for v1, (b) Defer | (b) Defer — built-in backends sufficient for v1 |

---

## References

### Standards and RFCs

| Reference | URL |
|-----------|-----|
| RFC 9106 — Argon2 | https://www.rfc-editor.org/rfc/rfc9106 |
| RFC 8439 — ChaCha20-Poly1305 | https://www.rfc-editor.org/rfc/rfc8439 |
| NIST SP 800-38D — AES-GCM | https://csrc.nist.gov/pubs/sp/800/38d/final |
| NIST SP 800-132 — PBKDF | https://csrc.nist.gov/pubs/sp/800/132/final |
| RFC 5869 — HKDF | https://www.rfc-editor.org/rfc/rfc5869 |
| RFC 7748 — X25519 | https://www.rfc-editor.org/rfc/rfc7748 |
| RFC 8032 — Ed25519 | https://www.rfc-editor.org/rfc/rfc8032 |
| RFC 9382 — SPAKE2 | https://www.rfc-editor.org/rfc/rfc9382 |
| draft-miller-ssh-agent — SSH Agent Protocol | IETF Internet-Draft |
| XChaCha20 Draft | https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/ |

### Existing Tool References

| Tool | Reference |
|------|-----------|
| age | https://age-encryption.org/v1 |
| 1Password Security Design | https://1password.com/security |
| Bitwarden Security White Paper | https://bitwarden.com/help/bitwarden-security-white-paper/ |
| HashiCorp Vault Architecture | https://developer.hashicorp.com/vault/docs/internals/architecture |
| pass | https://www.passwordstore.org/ |
| OWASP Password Storage | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html |

### CVEs Referenced

| CVE | Description |
|-----|-------------|
| CVE-2023-38408 | OpenSSH ssh-agent RCE via PKCS#11 provider (< 9.3p2) |
| CVE-2022-34903 | GnuPG signature status injection |
| CVE-2018-12020 | GnuPG SigSpoof — forged signature status display |
| CVE-2023-24532 | Go crypto/elliptic P-256 scalar multiplication issue |
| CVE-2023-32422 | macOS Keychain auth bypass |

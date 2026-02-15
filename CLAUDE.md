# Padlock — Claude Code Project Instructions

## What Is Padlock

Padlock is a security-first credential management platform for developers. It stores passwords, API keys, SSH keys, certificates, TOTP seeds, and arbitrary secrets in an encrypted vault. It runs as a CLI tool and SSH agent daemon, with optional cross-device sync.

**Language**: Rust (2021 edition)
**Architecture**: Domain-Driven Design (DDD) with a core library (`padlock-core`) and thin frontends
**Priority**: Security > Correctness > Performance > Usability

## Project Structure

```
padlock/
├── CLAUDE.md                    # You are here
├── MASTER_PLAN.md               # Phased roadmap and strategy
├── Cargo.toml                   # Workspace root
├── docs/
│   ├── SYSTEM_DESIGN.md         # Full system design document (source of truth)
│   ├── MVP_SCOPE.md             # MVP scope and resolved design decisions
│   └── decisions/               # Architecture Decision Records (ADRs)
├── knowledge/                   # Context files for each domain — READ THESE
│   ├── 00-project/CONTEXT.md    # Project overview, conventions, workspace layout
│   ├── 01-crypto/CONTEXT.md     # Cryptographic engine design and crates
│   ├── 02-vault/CONTEXT.md      # Vault file format, storage, atomicity
│   ├── 03-entries/CONTEXT.md    # Entry types, CRUD, serialization
│   ├── 04-cli/CONTEXT.md        # CLI commands, clap, output modes
│   ├── 05-ssh-agent/CONTEXT.md  # SSH agent protocol, daemon, socket
│   ├── 06-git-signing/CONTEXT.md # Git commit signing via SSH
│   ├── 07-sync/CONTEXT.md       # Cross-device sync (post-MVP)
│   ├── 08-platform/CONTEXT.md   # OS keyring, Secure Enclave, systemd
│   ├── 09-testing/CONTEXT.md    # Test strategy, coverage, fuzzing
│   ├── 10-ci-cd/CONTEXT.md      # GitHub Actions, release pipeline
│   ├── 11-security/CONTEXT.md   # Security audit checklist, threat model
│   └── 12-tooling/CONTEXT.md    # Dev tools, automations, workflow
├── crates/
│   ├── padlock-core/            # Core library (no I/O, no platform code)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── crypto/          # Encryption, KDF, HMAC, key hierarchy
│   │   │   ├── vault/           # Vault open/close/read/write
│   │   │   ├── entries/         # Entry CRUD, search, serialization
│   │   │   ├── ssh_agent/       # SSH agent protocol handler
│   │   │   ├── signing/         # Git commit/tag signing
│   │   │   ├── sync/            # Sync protocol (post-MVP)
│   │   │   ├── audit/           # Tamper-evident audit log
│   │   │   ├── generate/        # Password/key generation
│   │   │   ├── traits/          # Abstraction boundaries
│   │   │   └── types/           # Shared types (Entry, SecretBuf, etc.)
│   │   └── tests/               # Integration tests
│   ├── padlock-cli/             # CLI frontend (thin wrapper over core)
│   │   └── src/
│   │       ├── main.rs
│   │       └── commands/        # One module per CLI command group
│   └── padlock-test-utils/      # Shared test helpers
│       └── src/lib.rs
└── fuzz/                        # Fuzzing targets (cargo-fuzz)
    └── fuzz_targets/
```

## Before You Write Any Code

1. **Read the relevant knowledge/ CONTEXT.md file** for the component you're working on.
2. **Read docs/SYSTEM_DESIGN.md** sections referenced in the context file.
3. **Read docs/MVP_SCOPE.md** to know what's in scope.
4. **Check MASTER_PLAN.md** for phase dependencies — don't build Phase 5 code if Phase 1 isn't solid.

## Coding Standards

### Rust Conventions
- Edition 2021, stable toolchain
- `#![forbid(unsafe_code)]` in padlock-cli. `#![deny(unsafe_code)]` in padlock-core (allow with safety comments only)
- Every `unsafe` block MUST have a `// SAFETY:` comment explaining why it's sound
- All public items have doc comments (`///`)
- Use `thiserror` for library errors, `anyhow` for CLI errors
- Prefer `impl Trait` over `dyn Trait` where possible
- No `.unwrap()` or `.expect()` in library code — propagate errors with `?`
- Use `#[must_use]` on functions that return values that should not be ignored

### Security-Critical Rules
- **Never log secrets.** Use `secrecy::Secret<T>` for all sensitive values. It redacts Debug/Display.
- **Zero all secrets after use.** Derive `Zeroize` + `ZeroizeOnDrop` on all types containing secret data.
- **mlock secret memory.** Use `memsec` for buffers containing key material.
- **No plaintext secrets on disk.** Not even in temp files.
- **Constant-time comparisons** for all authentication checks (`subtle::ConstantTimeEq`).
- **Fail closed.** If authentication fails or data is corrupted, deny access. Never fall through.
- **Validate all inputs** at trust boundaries (CLI args, SSH agent messages, vault file parsing).

### DDD Structure
- `padlock-core` is the domain. It has NO dependencies on:
  - Terminal I/O (no `println!`, no `stdin`)
  - Filesystem (uses `StorageBackend` trait)
  - Platform APIs (uses `PlatformKeyring` trait)
  - Network (uses `SyncTransport` trait)
- `padlock-cli` is an adapter. It implements traits and wires them to the core.
- Domain logic lives in the core. CLI is just plumbing.

### Error Handling
- Define domain errors in `padlock-core::error`
- Use enums, not strings: `VaultError::Locked`, not `"vault is locked"`
- Error types must NOT contain secret data
- CLI translates domain errors to user-friendly messages + exit codes

### Testing
- **Minimum 95% coverage** — measure with `cargo llvm-cov`
- Unit tests: in-module `#[cfg(test)]` blocks for private logic
- Integration tests: in `crates/padlock-core/tests/` for cross-module flows
- Property tests: use `proptest` for crypto round-trips and serialization
- Fuzzing: `cargo-fuzz` targets for parsers (vault file, SSH messages, MessagePack)
- Every bug fix gets a regression test
- Test naming: `test_<function>_<scenario>_<expected>` (e.g., `test_decrypt_wrong_passphrase_returns_auth_error`)

## Key Crate Dependencies

| Concern | Crate | Why |
|---------|-------|-----|
| AEAD | `chacha20poly1305` | XChaCha20-Poly1305, pure Rust, WASM-safe |
| KDF | `argon2` | Argon2id per RFC 9106 |
| HKDF | `hkdf` + `sha2` | Subkey derivation |
| HMAC | `hmac` + `sha2` | Vault integrity, audit log |
| Secrets | `secrecy` + `zeroize` | Type-safe, zero-on-drop |
| Memory | `memsec` | mlock, guard pages |
| Serialization | `serde` + `rmp-serde` | MessagePack |
| CLI | `clap` (derive) | Argument parsing |
| Async | `tokio` | SSH agent daemon |
| SSH | `ssh-key`, `ssh-agent` | SSH protocol types |
| UUID | `uuid` | Entry IDs |
| Random | `rand` + `getrandom` | CSPRNG |
| Ed25519 | `ed25519-dalek` | Key generation + signing |
| X25519 | `x25519-dalek` | Key agreement (sync) |
| SPAKE2 | `spake2` | Device pairing |
| Errors | `thiserror` (lib) / `anyhow` (CLI) | Error handling |
| Time | `chrono` | Timestamps |
| Config | `toml` + `serde` | config.toml parsing |
| Testing | `proptest`, `cargo-fuzz`, `cargo-llvm-cov` | Property tests, fuzzing, coverage |

## Commands Reference

```bash
# Build
cargo build --workspace

# Test everything
cargo test --workspace

# Test with coverage
cargo llvm-cov --workspace --html

# Clippy (strict)
cargo clippy --workspace -- -D warnings -D clippy::pedantic

# Format check
cargo fmt --check --all

# Run fuzzer (example)
cargo fuzz run fuzz_vault_parser -- -max_total_time=300

# Audit dependencies
cargo deny check
cargo vet
```

## Commit Convention

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `security`
Scopes: `crypto`, `vault`, `entries`, `cli`, `agent`, `signing`, `sync`, `ci`, `deps`

Examples:
- `feat(crypto): implement XChaCha20-Poly1305 encryption`
- `security(vault): add mlock for KEK storage buffer`
- `test(crypto): add proptest for encrypt/decrypt round-trip`

## Agent Team Orchestration

This project uses a multi-agent team for development. Agent definitions are in `.claude/agents/`.

### Starting a Phase
1. Spawn the tech-lead agent: it reads MASTER_PLAN.md and orchestrates
2. Tech-lead spawns up to 3 specialist agents per phase
3. Max 4 concurrent agents (tech-lead + 3 workers)
4. Each agent reads the relevant knowledge/ CONTEXT.md before working

### Agent Roster
| Agent | Role | Active Phases |
|-------|------|--------------|
| tech-lead | Orchestrator | All |
| software-architect | Design, ADRs, trait boundaries | 0-4 |
| software-engineer | Rust implementation | All |
| quality-engineer | Tests, coverage, fuzzing | 1-8 |
| security-engineer | Security review, hardening | 1-3, 7 |
| sre | CI/CD, release pipeline | 0, 7-8 |
| product-engineer | CLI UX, output, completions | 3-6 |
| product-owner | Requirements validation | 0, 4, 7-8 |
| pentester | Penetration testing | 7 |
| os-engineer | Platform code, memory protection | 1, 5, 8 |

### Custom Skills
| Skill | Purpose |
|-------|---------|
| padlock-crypto | Crypto implementation patterns, key hierarchy, security invariants |
| padlock-vault | Vault binary format, atomic write, state machine |
| padlock-security-review | 49-item security audit checklist |
| padlock-phase-gate | Quality gate checklist for phase transitions |
| padlock-rust-conventions | Rust coding patterns and DDD structure |

## When You're Stuck

1. Re-read the relevant `knowledge/` CONTEXT.md file
2. Check `docs/SYSTEM_DESIGN.md` for the design intent
3. Look at the security audit checklist in `knowledge/11-security/CONTEXT.md`
4. When in doubt, choose the more secure option

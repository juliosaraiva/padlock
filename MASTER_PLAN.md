# Padlock — Master Plan

**Status**: Pre-implementation
**Approach**: Phased, security-first, DDD
**Target**: MVP → Beta → GA

---

## Vision

Padlock replaces the fragmented mess of `.env` files, plaintext SSH keys, scattered API tokens, and half-configured GPG setups with a single encrypted vault managed from the terminal. Every secret is encrypted at rest, every signing operation is audited, every key is zeroed from memory after use.

---

## Resolved Design Decisions

All 8 open decisions from SYSTEM_DESIGN.md, resolved with security-first priority:

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Passphrase strength enforcement | **(b) Warn but allow** | Educate without blocking. Show entropy estimate via `zxcvbn`. Warn on < 40 bits. |
| 2 | DEK strategy | **(b) Random DEKs wrapped by KEK** | Enables efficient key rotation without re-encrypting all secret data. More secure isolation between entries. |
| 3 | GPG shim in v1 | **(b) Defer** | SSH signing covers 90%+ of developer use cases. Reduces attack surface in v1. |
| 4 | X.509 signing in v1 | **(b) Defer** | Enterprise feature. No demand signal yet. |
| 5 | Sync conflict resolution | **(c) Configurable, default auto-LWW with notification** | Balances usability with safety. Users who want manual resolution can enable it. |
| 6 | FIDO/U2F passthrough | **(b) Defer** | Users can keep native ssh-agent for hardware keys. Avoids complexity in v1. |
| 7 | Secret history | **(b) Opt-in per entry, max depth 5** | Recovery from accidental overwrites justifies the storage cost. Opt-in respects minimalism. |
| 8 | Plugin architecture | **(b) Defer** | Trait-based design already enables extensibility. Formal plugin system is premature. |

Full ADRs are in `docs/decisions/`.

---

## Phase Map

```
Phase 0: Foundation          ████░░░░░░░░░░░░░░░░  Week 1-2
Phase 1: Crypto Engine       ░░░░████░░░░░░░░░░░░  Week 3-5
Phase 2: Vault Core          ░░░░░░░░███░░░░░░░░░  Week 6-7
Phase 3: Entry Management    ░░░░░░░░░░░███░░░░░░  Week 8-9
Phase 4: CLI Interface       ░░░░░░░░░░░░░░██░░░░  Week 10-11
Phase 5: SSH Agent           ░░░░░░░░░░░░░░░░███░  Week 12-14
Phase 6: Git Signing         ░░░░░░░░░░░░░░░░░░██  Week 15-16
Phase 7: Polish & Audit      ░░░░░░░░░░░░░░░░░░░█  Week 17-18
Phase 8: Distribution        ░░░░░░░░░░░░░░░░░░░░█ Week 19
─────────────────────────────────────────────────────
Post-MVP: Sync, Platform Adapters, Import/Export, Cert Mgmt, WASM/FFI
```

---

## Phase 0: Foundation (Week 1-2)

**Goal**: Project scaffolding, CI, and dev tooling — nothing compiles yet, but everything is ready.

### Deliverables

- [ ] Cargo workspace with three crates: `padlock-core`, `padlock-cli`, `padlock-test-utils`
- [ ] `CLAUDE.md` at workspace root (done — this file)
- [ ] `.github/workflows/ci.yml` — build, test, clippy, fmt, deny, coverage
- [ ] `deny.toml` — dependency audit config
- [ ] `rustfmt.toml` — formatting config
- [ ] `.cargo/config.toml` — build settings
- [ ] All `Cargo.toml` files with dependencies pinned
- [ ] `fuzz/` directory with initial empty targets
- [ ] Pre-commit hook: `cargo fmt --check && cargo clippy -- -D warnings`
- [ ] `padlock-core/src/lib.rs` with module stubs and feature flags
- [ ] Error types skeleton (`padlock-core/src/error.rs`)
- [ ] Trait definitions (`padlock-core/src/traits/`)

### Context Files
- `knowledge/00-project/CONTEXT.md` — workspace layout, conventions
- `knowledge/10-ci-cd/CONTEXT.md` — CI pipeline design
- `knowledge/12-tooling/CONTEXT.md` — dev tool recommendations

### Use Claude Code For
- Generating all boilerplate Cargo.toml files
- Writing the GitHub Actions workflow
- Setting up deny.toml and rustfmt.toml
- Scaffolding module stubs with doc comments

---

## Phase 1: Crypto Engine (Week 3-5)

**Goal**: The cryptographic foundation. Everything else builds on this. Must be bulletproof.

### Deliverables

- [ ] `SecretBuf` type: mlock'd, guard-paged, zeroize-on-drop buffer
- [ ] `SecretString` wrapper using `secrecy`
- [ ] Argon2id key derivation (passphrase → PDK)
- [ ] HKDF-SHA-256 subkey derivation (KEK → DEK, KEK → HMAC keys)
- [ ] XChaCha20-Poly1305 encrypt/decrypt with AAD
- [ ] Random DEK generation + wrapping/unwrapping by KEK
- [ ] HMAC-SHA-256 computation and verification
- [ ] Nonce generation from OS CSPRNG
- [ ] Key hierarchy implementation (PDK → KEK → DEK)
- [ ] Memory protection: mlock, prctl, guard pages
- [ ] Password strength estimation (zxcvbn integration)
- [ ] Comprehensive test suite: round-trips, wrong-key rejection, proptest
- [ ] Fuzzing target for decrypt operations

### Security Checks
- [ ] All secret buffers use mlock
- [ ] All secret buffers zeroize on drop
- [ ] AEAD tag is verified before ANY plaintext is returned
- [ ] Nonces are from getrandom (OS CSPRNG)
- [ ] Constant-time comparison for all auth checks

### Context Files
- `knowledge/01-crypto/CONTEXT.md` — full crypto design and crate usage

### Use Claude Code For
- Implementing the crypto module with tests
- Writing proptest strategies for encrypt/decrypt round-trips
- Setting up fuzzing targets

### Use Claude Project For
- Reviewing crypto design decisions
- Discussing algorithm parameter choices
- Security-focused code review of the crypto module

---

## Phase 2: Vault Core (Week 6-7)

**Goal**: Read and write the vault file format. Atomic operations. Integrity verification.

### Deliverables

- [ ] Vault file format parser (magic bytes, header, index, entries, integrity HMAC)
- [ ] Vault creation (init)
- [ ] Vault open/unlock (passphrase → PDK → KEK)
- [ ] Vault close/lock (zero KEK from memory)
- [ ] Vault header read/write with KDF params
- [ ] KEK blob encrypt/decrypt
- [ ] Entry index encrypt/decrypt
- [ ] Vault integrity HMAC computation and verification
- [ ] Atomic file write (tmp → fsync → rename → fsync dir)
- [ ] Backup file management
- [ ] Passphrase change (re-encrypt KEK blob only)
- [ ] File permission enforcement (0700 dir, 0600 files)
- [ ] Vault corruption detection tests
- [ ] Atomic write crash-recovery tests

### Context Files
- `knowledge/02-vault/CONTEXT.md` — vault format, storage, atomicity

### Use Claude Code For
- Implementing the binary vault format parser/writer
- Writing atomic file operation logic
- Integration tests for vault lifecycle

---

## Phase 3: Entry Management (Week 8-9)

**Goal**: CRUD operations for all secret types. Search. Serialization.

### Deliverables

- [ ] Entry type enum (Credential, SSHKey, TOTP, Binary, Netrc, Certificate)
- [ ] Entry data structures with serde + zeroize derives
- [ ] MessagePack serialization/deserialization
- [ ] Create entry (encrypt + add to index + write vault)
- [ ] Read entry (find in index + decrypt)
- [ ] Update entry (re-encrypt + update index + atomic write)
- [ ] Delete entry (remove from index + atomic write)
- [ ] List entries (decrypt index, return metadata only)
- [ ] Search by name, tags, entry type
- [ ] Name hash lookup (HMAC-based, without decrypting index)
- [ ] Entry versioning (version counter incremented on update)
- [ ] Optional history (previous versions, opt-in, max depth 5)
- [ ] Fuzzing target for MessagePack deserializer

### Context Files
- `knowledge/03-entries/CONTEXT.md` — entry types, schema, serialization

### Use Claude Code For
- Generating entry data structures with all derives
- Implementing CRUD with comprehensive tests
- MessagePack round-trip tests for every entry type variant

---

## Phase 4: CLI Interface (Week 10-11)

**Goal**: The user-facing CLI. Thin wrapper over core library.

### Deliverables

- [ ] clap derive-based command structure
- [ ] `padlock init` — create vault
- [ ] `padlock unlock` — unlock with passphrase (terminal prompt)
- [ ] `padlock lock` — lock vault
- [ ] `padlock status` — vault state, entry count, agent status
- [ ] `padlock get <name>` — retrieve secret (copy to clipboard with timeout)
- [ ] `padlock set <name>` — store/update secret (read from stdin or prompt)
- [ ] `padlock rm <name>` — delete secret (with confirmation)
- [ ] `padlock ls` — list entries
- [ ] `padlock search <query>` — search
- [ ] `padlock generate` — random password/passphrase generation
- [ ] Output modes: human-readable (default), `--json`, `--quiet`
- [ ] `--no-color` flag
- [ ] Clipboard integration with auto-clear (45s default)
- [ ] Shell completions (`bash`, `zsh`, `fish`)
- [ ] Exit codes per spec (0-10)
- [ ] Config file parsing (`~/.padlock/config.toml`)
- [ ] `padlock exec --env` for environment injection

### Context Files
- `knowledge/04-cli/CONTEXT.md` — CLI commands, UX patterns

### Use Claude Code For
- Scaffolding the clap command tree
- Implementing each command handler
- Writing integration tests that exercise the full CLI flow

---

## Phase 5: SSH Agent (Week 12-14)

**Goal**: A fully functional SSH agent that replaces ssh-agent for Padlock-managed keys.

### Deliverables

- [ ] Unix domain socket listener (tokio async)
- [ ] SSH agent protocol message parsing (all message types from spec)
- [ ] `REQUEST_IDENTITIES` → return public keys from vault
- [ ] `SIGN_REQUEST` → decrypt private key, sign, zero key
- [ ] `ADD_IDENTITY` / `ADD_ID_CONSTRAINED` → import key into vault
- [ ] `REMOVE_IDENTITY` / `REMOVE_ALL_IDENTITIES` → remove from active set
- [ ] `EXTENSION` support (session-bind, restrict-destination)
- [ ] Agent lifecycle: start, stop, status, PID file
- [ ] Auto-lock timeout (default 15 minutes)
- [ ] Per-key confirm-before-use policy
- [ ] `padlock agent start/stop/status/shell-env/list` commands
- [ ] Shell integration snippet generation
- [ ] Concurrent connection handling (multiple SSH sessions)
- [ ] Graceful shutdown on SIGTERM/SIGINT
- [ ] Fuzzing target for SSH agent message parser

### Context Files
- `knowledge/05-ssh-agent/CONTEXT.md` — protocol, lifecycle, policies

### Use Claude Code For
- Implementing the SSH agent protocol handler
- Writing the tokio async event loop
- Integration tests with `ssh-add` and `ssh-keygen`

### Use Claude Project For
- Discussing SSH agent security implications
- Reviewing protocol conformance edge cases

---

## Phase 6: Git Signing (Week 15-16)

**Goal**: Sign Git commits and tags using SSH keys from the vault.

### Deliverables

- [ ] `padlock git setup` — configure current repo for SSH signing
- [ ] `padlock git setup --scope global` — global config
- [ ] `padlock git allowed-signers` — export allowed signers file
- [ ] `padlock git verify <commit>` — verify commit signature
- [ ] Per-repo key selection (via tags, gitconfig includeIf)
- [ ] Default signing key configuration
- [ ] Interactive key selection when multiple keys match
- [ ] Audit log entries for every signing operation
- [ ] Documentation for signing workflow

### Context Files
- `knowledge/06-git-signing/CONTEXT.md` — SSH signing, key selection

### Use Claude Code For
- Implementing git config manipulation
- Writing the allowed signers file generator
- Integration tests with actual git repos

---

## Phase 7: Polish & Security Audit (Week 17-18)

**Goal**: Harden everything. Run the full security audit checklist.

### Deliverables

- [ ] Run all 49 checks from Security Audit Checklist (SYSTEM_DESIGN.md §11)
- [ ] Fuzzing campaigns: vault parser, SSH agent parser, MessagePack deserializer
- [ ] Memory zeroing verification (scan process memory after SecretBuf drop)
- [ ] Confirm no secrets in error messages, logs, or debug traces
- [ ] Confirm `Secret<T>` is used everywhere sensitive data flows
- [ ] Confirm all `unsafe` blocks have safety comments
- [ ] Error handling audit: no panics in library code
- [ ] `cargo deny check` clean
- [ ] `cargo clippy --pedantic` clean
- [ ] Coverage report: confirm 95%+
- [ ] Audit log integrity chain test
- [ ] Cross-platform build test (Linux x86_64, macOS x86_64, macOS aarch64)
- [ ] Write man pages or `--help` documentation
- [ ] Write README.md

### Use Claude Code For
- Running the audit checklist programmatically
- Fixing any issues found during audit
- Generating coverage reports

### Use Claude Project For
- Full security design review conversation
- Discussing residual risks and mitigations

---

## Phase 8: Distribution (Week 19)

**Goal**: Ship it.

### Deliverables

- [ ] Homebrew formula (tap or core)
- [ ] `cargo install padlock-cli` support
- [ ] Release binary signing
- [ ] GitHub Release workflow (build matrix → sign → publish)
- [ ] SBOM generation
- [ ] Changelog generation
- [ ] v0.1.0 release

### Context Files
- `knowledge/10-ci-cd/CONTEXT.md` — release pipeline

### Use Claude Code For
- Writing the Homebrew formula
- Setting up the release GitHub Action
- Generating the initial changelog

---

## Post-MVP Roadmap

| Phase | Feature | Priority | Depends On |
|-------|---------|----------|------------|
| 9 | Cross-device sync (file-based) | High | MVP complete |
| 10 | Platform keyring (macOS Keychain, Linux keyring) | High | MVP complete |
| 11 | Import/export (1Password, Bitwarden, .netrc, GPG) | Medium | Entries |
| 12 | Certificate management (store, verify chain) | Medium | Entries |
| 13 | GPG signing shim | Low | Git signing |
| 14 | X.509 signing shim | Low | Git signing |
| 15 | UniFFI bindings (Swift, Kotlin, Python) | Medium | Core stable |
| 16 | WASM build + web vault | Low | Core stable |
| 17 | Plugin architecture | Low | Post-stabilization |

---

## Development Workflow Recommendations

### When to Use Claude Code

Claude Code is your **implementation partner**. Use it for:

- **Scaffolding**: Generate Cargo.toml, module stubs, trait definitions, test skeletons
- **Writing code**: Implement functions, write tests, set up CI pipelines
- **Refactoring**: Rename across codebase, restructure modules, extract traits
- **Debugging**: Run tests, analyze failures, fix bugs
- **Code generation**: Derive macros, CLI boilerplate, serialization impls
- **Testing**: Write unit tests, integration tests, proptest strategies, fuzzing harnesses
- **Documentation**: Doc comments, README, man pages

**Workflow**: Before writing code for any component, tell Claude Code to read the relevant `knowledge/` CONTEXT.md file. This gives it domain-specific instructions and crate usage patterns.

### When to Use Claude Project (claude.ai)

Claude Project is your **design partner**. Use it for:

- **Architecture review**: "Review the key hierarchy design for weaknesses"
- **Security analysis**: "What attack vectors does this design miss?"
- **Design decisions**: "Should we use HKDF-derived or random DEKs?"
- **Threat modeling**: "Model an adversary with root access to the host"
- **Protocol analysis**: "Verify the SPAKE2 pairing flow is secure"
- **Trade-off discussions**: "Pros/cons of vector clocks vs CRDTs for sync"

**Setup**: Create a Claude Project with `SYSTEM_DESIGN.md` and `MASTER_PLAN.md` as project knowledge. Use it as a long-running design conversation.

### Skills and Automations to Build

#### Claude Code Custom Skills
1. **`security-review`** — Run security audit checklist against current code
2. **`crypto-test`** — Run crypto-specific test suite with coverage
3. **`fuzz-run`** — Launch fuzzing campaign for specified target
4. **`release-check`** — Pre-release validation (tests, clippy, deny, coverage)

#### GitHub Actions Workflows
1. **`ci.yml`** — On every push: build, test, clippy, fmt, deny
2. **`coverage.yml`** — Weekly: full coverage report with llvm-cov
3. **`fuzz.yml`** — Nightly: run all fuzz targets for 10 minutes each
4. **`audit.yml`** — Daily: `cargo deny check` + `cargo vet`
5. **`release.yml`** — On tag: build matrix, sign binaries, publish to Homebrew

#### Local Automations
1. **Pre-commit hook**: fmt + clippy + test
2. **Cargo alias**: `cargo xtask security-check` — runs the audit checklist
3. **Makefile / justfile**: Common commands (build, test, fuzz, coverage, release)

### Tools That 10x Speed

| Tool | Purpose | When |
|------|---------|------|
| `cargo-watch` | Auto-rebuild on file changes | During development |
| `cargo-llvm-cov` | Code coverage with HTML reports | After each phase |
| `cargo-fuzz` | Fuzzing with libFuzzer | Continuous, from Phase 1 |
| `cargo-deny` | Dependency license + vulnerability audit | Every CI run |
| `cargo-vet` | Supply chain review | Every dependency update |
| `cargo-expand` | See macro expansion output | When debugging derives |
| `cargo-udeps` | Find unused dependencies | Periodic cleanup |
| `cargo-machete` | Faster unused dep detection | Quick checks |
| `cargo-mutants` | Mutation testing | Verify test quality |
| `just` (justfile) | Task runner (better than Make for this) | All phases |
| `git-cliff` | Changelog generation from commits | Release phase |
| `cargo-release` | Automate version bumps + publish | Release phase |
| `hyperfine` | CLI benchmarking | Performance validation |

---

## Quality Gates

No phase is complete until:

1. All deliverables are checked off
2. Tests pass with 95%+ coverage for that phase's code
3. `cargo clippy --pedantic` is clean
4. `cargo deny check` is clean
5. All security checks relevant to that phase pass
6. Code review (self-review using Claude Project for security phases)

---

## File Index

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Claude Code reads this first — project rules |
| `MASTER_PLAN.md` | This file — roadmap and strategy |
| `docs/SYSTEM_DESIGN.md` | Full system design (source of truth) |
| `docs/MVP_SCOPE.md` | What's in/out for MVP |
| `docs/decisions/ADR-*.md` | Architecture decision records |
| `knowledge/*/CONTEXT.md` | Domain-specific context for each component |

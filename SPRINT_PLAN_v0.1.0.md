# Padlock v0.1.0 MVP Sprint Plan

**Date:** 2026-02-15
**Team:** padlock-dev (tech-lead, quality-engineer, security-engineer, product-engineer, + support roles)
**Goal:** Complete remaining 23/68 Linear tasks and ship v0.1.0 release
**Current Status:** 45/68 tasks complete (66%), Phases 0-6 done, Phases 7-8 in progress

---

## Critical Path (9 Core Tasks)

### Week 1: Hardening & Security (Phase 7)

**Task #2: ENG-214 — Implement Fuzz Targets** ⏱️ 3 hours
- **Owner:** quality-engineer
- **Status:** In Progress
- **Deliverable:** 3 fuzzing targets (vault_parser, ssh_agent_protocol, msgpack_decoder)
- **Blocks:** ENG-196, ENG-198, ENG-188, ENG-215, ENG-164
- **Details:**
  - Create `/fuzz/fuzz_targets/fuzz_vault_parser.rs`
  - Create `/fuzz/fuzz_targets/fuzz_ssh_agent_protocol.rs`
  - Create `/fuzz/fuzz_targets/fuzz_msgpack_decoder.rs`
  - Each with 10+ corpus test cases
  - Runnable: `cargo +nightly fuzz run fuzz_vault_parser`

**Task #3: ENG-151 — Security Audit** ⏱️ 6 hours
- **Owner:** security-engineer
- **Status:** In Progress
- **Deliverable:** SECURITY_AUDIT_REPORT.md with 49-item checklist (all pass)
- **Output:** /Users/juliosaraiva/Developer/padlock/SECURITY_AUDIT_REPORT.md
- **Categories:**
  1. Cryptography (8 checks) — algorithm params, nonce, KDF
  2. Memory Safety (12 checks) — mlock, zeroize, guard pages
  3. Access Control (6 checks) — permissions, SSH socket, vault state
  4. Input Validation (8 checks) — CLI args, SSH messages, vault format
  5. Error Handling (6 checks) — no panics, no secret leakage, fail-closed
  6. Logging (5 checks) — no secrets in logs, audit integrity
  7. Atomic Operations (4 checks) — vault writes, file sync, consistency

**Task #6: ENG-160 — Coverage Report** ⏱️ 1 hour
- **Owner:** quality-engineer (parallel with Task #2)
- **Status:** Pending
- **Deliverable:** Coverage report (target: 95%+ padlock-core, 90%+ padlock-cli)
- **Command:** `cargo llvm-cov --workspace --html`
- **Output:** target/llvm-cov/html/, COVERAGE.md

---

### Week 2: Release Preparation (Phase 8)

**Task #4: ENG-189 — Release Artifacts** ⏱️ 2 hours
- **Owner:** product-engineer
- **Status:** In Progress
- **Deliverable:** Enhanced release.yml with SHA256 checksums + SBOM
- **File:** /.github/workflows/release.yml
- **Changes:**
  1. Add checksums.txt generation (one SHA-256 per binary)
  2. Add SBOM generation (cargo-sbom or cargo-generate-sbom)
  3. Upload both as release assets
  4. Verify: `sha256sum --check checksums.txt`
- **Blocks:** Task #5 (ENG-204)
- **Note:** release.yml already has per-file checksums; enhance to create combined checksums.txt + SBOM

**Task #5: ENG-204 — v0.1.0 Tag & Changelog** ⏱️ 1 hour
- **Owner:** project-manager
- **Status:** Pending
- **Deliverable:**
  - CHANGELOG.md (git commit history → markdown)
  - Version bump (Cargo.toml → 0.1.0 in all crates)
  - Annotated tag: `v0.1.0`
- **Commands:**
  ```bash
  git tag -a v0.1.0 -m 'Padlock v0.1.0 — MVP release'
  git push origin v0.1.0  # Triggers release.yml workflow
  ```
- **Depends on:** Task #4 (ENG-189)
- **Blocks:** Task #7 (ENG-195), Task #8 (ENG-201)

**Task #7: ENG-195 — Homebrew Formula** ⏱️ 2 hours
- **Owner:** product-engineer
- **Status:** Pending
- **Deliverable:** Formula/padlock.rb for Homebrew
- **Options:**
  1. Submit to homebrew-core
  2. Create homebrew-padlock tap
- **Depends on:** Task #5 (v0.1.0 tag exists)
- **Testing:** `brew install padlock`, verify `padlock --version`

**Task #8: ENG-201 — crates.io Publish** ⏱️ 1 hour
- **Owner:** project-manager
- **Status:** Pending
- **Deliverable:** padlock-core and padlock-cli published to crates.io
- **Requirements:**
  1. crates.io account + auth token
  2. Cargo.toml metadata complete (license, description, repository)
  3. Version = 0.1.0
- **Command:** `cargo publish` (both crates)
- **Depends on:** Task #5 (version 0.1.0 exists)

**Task #9: ENG-211 — 8 Architecture Decision Records** ⏱️ 4 hours
- **Owner:** software-architect
- **Status:** Pending
- **Deliverable:** 8 ADRs in docs/decisions/ADR-*.md
- **ADRs:**
  1. ADR-001: Encryption algorithm (XChaCha20-Poly1305 over AES-GCM)
  2. ADR-002: Key derivation (Argon2id parameters)
  3. ADR-003: Vault file format (binary with MessagePack)
  4. ADR-004: SSH agent protocol (RFC 4251 via Unix socket)
  5. ADR-005: DDD architecture (core library separation)
  6. ADR-006: Entry types and serialization
  7. ADR-007: Audit logging (JSON Lines, always-on)
  8. ADR-008: Key rotation and passphrase change
- **Format:** Context, Decision, Rationale, Consequences, Alternatives
- **Note:** Can proceed in parallel with other tasks

---

## Task Dependency Graph

```
Task #1 (Bootstrap)
  └─ (no dependencies, completes first)

Task #2 (ENG-214 Fuzz)     ←───────────────┐
  ├─ Blocks: ENG-196, ENG-198, ENG-188, ENG-215, ENG-164
  └─ Parallel with Task #6

Task #3 (ENG-151 Audit)
  ├─ Blocks: Phase 7 completion
  └─ Independent of other tasks

Task #4 (ENG-189 Artifacts)
  └─ Blocks: Task #5 (ENG-204)

Task #5 (ENG-204 Tag)
  ├─ Depends on: Task #4 (ENG-189)
  └─ Blocks: Task #7 (ENG-195), Task #8 (ENG-201)

Task #6 (ENG-160 Coverage)
  ├─ Parallel with Task #2
  └─ Independent

Task #7 (ENG-195 Homebrew)
  └─ Depends on: Task #5 (ENG-204)

Task #8 (ENG-201 crates.io)
  └─ Depends on: Task #5 (ENG-204)

Task #9 (ENG-211 ADRs)
  └─ Independent (can start immediately)

Recommended Execution Order:
  1. Task #1 (Bootstrap) — 1 hour, unblocks visualization
  2. Parallel Phase 7 (Tasks #2, #3, #6) — 6-10 hours
  3. Task #9 (ADRs) — 4 hours, can overlap with Phase 7
  4. Sequential Phase 8 (Tasks #4 → #5 → #7, #8) — 6 hours total
```

---

## Remaining 14 Secondary Tasks (from LINEAR_SYNC_SUMMARY.md)

### Phase 7: Hardening (Dependent on Task #2)

After ENG-214 fuzz targets are complete:

1. **ENG-196:** fuzz_vault_parser extended corpus (blocked by ENG-214)
2. **ENG-198:** fuzz_ssh_agent_protocol extended corpus (blocked by ENG-214)
3. **ENG-188:** fuzz_msgpack_decoder extended corpus (blocked by ENG-214)
4. **ENG-215:** fuzz_cli_argument_parser (blocked by ENG-214)
5. **ENG-164:** Extended fuzzing campaigns (blocked by ENG-214)
6. **ENG-171:** Mutation testing (low priority, not critical for MVP)

### Phase 8: Documentation

7. **ENG-177:** Documentation (README, docs exist; needs man pages + SECURITY.md)
8. **ENG-199:** SECURITY.md threat model + assumptions

### Phase 6+: Advanced Features (Deferred Post-MVP)

9. **ENG-135:** TOTP management UI (generation works, full CLI incomplete)
10. **ENG-137:** Credential providers (`exec` works, `netrc`/`git-credential` missing)
11. **ENG-133:** SSH key import/export (generation works, import/export deferred)
12. **ENG-136:** Certificate management (deferred to v1.1)

### Platform Integration (Deferred to v1.1)

13. **ENG-139:** macOS Keychain and Secure Enclave
14. **ENG-140:** Linux keyring and libsecret

---

## Quality Gates (Before v0.1.0 Release)

All must pass before marking phase complete:

1. ✅ `cargo test --workspace` — all tests pass
2. ✅ `cargo clippy --workspace -- -D warnings -D clippy::pedantic` — zero warnings
3. ✅ `cargo fmt --check --all` — formatting clean
4. ✅ `cargo deny check` — no dependency issues
5. ⚠️ Coverage report: 95%+ padlock-core, 90%+ padlock-cli (Task #6)
6. ⚠️ Security audit: all 49 items pass (Task #3)
7. ✅ No TODO/FIXME/HACK comments unresolved
8. ✅ All public items have doc comments
9. ✅ Commit history uses conventional commits

---

## Team Structure

| Role | Agent | Status | Assigned Tasks |
|------|-------|--------|-----------------|
| **Tech Lead** | team-lead@padlock-dev | Active | Orchestration, Linear sync |
| **Quality Eng** | quality-engineer | Active | Task #2 (Fuzz), Task #6 (Coverage) |
| **Security Eng** | security-engineer | Active | Task #3 (Audit) |
| **Product Eng** | product-engineer | Active | Task #4 (Artifacts), Task #7 (Homebrew) |
| **Project Manager** | project-manager (on-call) | Pending | Task #5 (Tag), Task #8 (crates.io) |
| **Software Architect** | software-architect (on-call) | Pending | Task #9 (ADRs) |

---

## Timeline Estimate

- **Phase 7 (Security & Hardening):** 10 hours
  - Task #2 (Fuzz): 3h
  - Task #3 (Audit): 6h
  - Task #6 (Coverage): 1h
  - Parallel: ADRs can start here (4h)

- **Phase 8 (Release):** 6 hours
  - Task #4 (Artifacts): 2h
  - Task #5 (Tag): 1h
  - Task #7 (Homebrew): 2h
  - Task #8 (crates.io): 1h

- **Total Critical Path:** 16 hours (sequential bottleneck is Task #4 → #5)
- **Estimated Timeline:** 3-4 working days with 4 concurrent agents

---

## Success Criteria for v0.1.0

- All 9 critical tasks complete (✅ in_progress or complete)
- All 49 security checks pass
- Coverage report: 95%+ for padlock-core
- GitHub Release published with:
  - Binary artifacts (x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin)
  - checksums.txt (SHA-256 for all binaries)
  - SBOM.json (SPDX format with all dependencies)
  - CHANGELOG.md
- Homebrew formula working: `brew install padlock`
- crates.io packages published and installable: `cargo install padlock-cli`
- All 8 ADRs documented
- Git tag `v0.1.0` created and pushed
- All tests passing in CI

---

## Communication Protocol

- **Status Updates:** Every 2 hours from agents via TaskUpdate
- **Blockers:** Immediately escalate via SendMessage to team-lead
- **Code Review:** Use GitHub PR + commit convention validation
- **Documentation:** Update relevant docs/ and knowledge/ files
- **Linear Sync:** Update Linear issue status when task completes

---

**Generated:** 2026-02-15 by tech-lead@padlock-dev
**Next Review:** After Task #1 (Bootstrap) completes

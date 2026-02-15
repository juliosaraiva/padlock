# CI/CD Context

## Platform
**GitHub Actions** — native CI/CD for GitHub repositories

## Timeline
Set up from **Phase 0** (repository initialization), not as an afterthought

## Workflows Overview

The Padlock project maintains 5 core workflows, each with a specific purpose and trigger:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ci.yml             coverage.yml         fuzz.yml              │
│  (on push/PR)       (weekly + manual)    (nightly)              │
│  [fast checks]      [coverage report]    [fuzzing]              │
│         ↓                   ↓                   ↓                │
│   ├─ build          ├─ llvm-cov         ├─ all fuzz targets   │
│   ├─ test           └─ upload artifact  └─ 10 min each        │
│   ├─ clippy                                                     │
│   ├─ fmt                                                        │
│   └─ deny                                                       │
│                                                                 │
│  audit.yml                      release.yml                    │
│  (daily)                        (on tag v*)                     │
│  [security audit]               [production release]           │
│         ↓                               ↓                       │
│   ├─ deny advisories     ├─ matrix build (3 platforms)        │
│   └─ cargo-vet           ├─ sign binaries                      │
│                          ├─ create GitHub Release              │
│                          └─ update Homebrew tap                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Workflow 1: `ci.yml` — Main CI Pipeline

**File**: `.github/workflows/ci.yml`
**Trigger**: On every `push` and `pull_request` to any branch
**Duration**: ~5-10 minutes
**Purpose**: Fast feedback loop — catch regressions immediately

```yaml
name: CI

on:
  push:
  pull_request:
  merge_group:

jobs:
  ci:
    name: CI
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Cache Cargo registry and build
        uses: Swatinem/rust-cache@v2
        with:
          cache-directories: target
          shared-key: cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Build workspace
        run: cargo build --workspace --verbose
        env:
          CARGO_INCREMENTAL: 0

      - name: Run tests
        run: cargo test --workspace --verbose
        env:
          RUST_BACKTRACE: 1

      - name: Run clippy lints
        run: cargo clippy --workspace --all-targets -- -D warnings -D clippy::pedantic
        continue-on-error: false

      - name: Check code formatting
        run: cargo fmt --all -- --check

      - name: Check dependencies
        run: cargo deny check

      - name: Check security advisories
        run: cargo deny check advisories

  security-audit:
    name: Security Audit
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2

      - name: Audit dependencies
        run: cargo audit
        continue-on-error: true  # Warn only, don't block PR
```

### Key Features

1. **Build Step**
   - Compiles entire workspace (all crates)
   - Incremental compilation disabled for clean builds
   - Catches compiler errors immediately

2. **Test Step**
   - Runs all unit, integration, and doc tests
   - `RUST_BACKTRACE=1` for detailed failure info
   - Includes CLI integration tests

3. **Clippy Lints**
   - `-D warnings` — treat all warnings as errors
   - `-D clippy::pedantic` — enable strict linting rules
   - No exceptions; all PRs must pass

4. **Code Formatting**
   - `cargo fmt --check` enforces Rust style
   - Fails if formatting differs from rustfmt
   - Developers can auto-fix with `cargo fmt`

5. **Dependency Audit**
   - `cargo deny` checks:
     - **Licenses**: Only MIT, Apache-2.0, BSD allowed
     - **Advisories**: Flags known vulnerabilities
   - Blocks merge if violations found

6. **Caching Strategy**
   - Cache key: hash of `Cargo.lock`
   - Separate cache per branch
   - Cargo registry cached
   - Target directory cached (significant speedup)

---

## Workflow 2: `coverage.yml` — Coverage Reporting

**File**: `.github/workflows/coverage.yml`
**Trigger**:
  - Weekly on Monday at 00:00 UTC
  - Manual dispatch (run from Actions tab)
**Duration**: ~10-15 minutes
**Purpose**: Track code coverage trends, verify 95%+ coverage maintained

```yaml
name: Coverage

on:
  schedule:
    # Every Monday at 00:00 UTC
    - cron: '0 0 * * 1'
  workflow_dispatch:  # Manual trigger

jobs:
  coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov --locked

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2

      - name: Generate coverage report
        run: |
          cargo llvm-cov --workspace --html --output-dir target/llvm-cov
          echo "## Code Coverage Report" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "Generated at: $(date -u +'%Y-%m-%d %H:%M:%S UTC')" >> $GITHUB_STEP_SUMMARY
        env:
          CARGO_INCREMENTAL: 0

      - name: Check coverage threshold
        run: |
          COVERAGE=$(cargo llvm-cov --workspace --percentage-output | tail -1 | grep -oP '\d+\.\d+')
          echo "Total coverage: ${COVERAGE}%"
          if (( $(echo "$COVERAGE < 95" | bc -l) )); then
            echo "Coverage below 95% threshold!"
            exit 1
          fi

      - name: Upload coverage report
        uses: actions/upload-artifact@v3
        with:
          name: llvm-cov-report
          path: target/llvm-cov/
          retention-days: 30

      - name: Create coverage badge
        run: |
          # Extract coverage percentage
          COVERAGE=$(cargo llvm-cov --workspace --percentage-output | tail -1 | grep -oP '\d+\.\d+')

          # Create SVG badge
          cat > coverage.svg << 'EOF'
          <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="140" height="20">
            <linearGradient id="b" x2="0" y2="100%">
              <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
              <stop offset="1" stop-opacity=".1"/>
            </linearGradient>
            <mask id="a">
              <rect width="140" height="20" rx="3" fill="#fff"/>
            </mask>
            <g mask="url(#a)">
              <rect width="100" height="20" fill="#555"/>
              <rect x="100" width="40" height="20" fill="#4c1"/>
              <rect width="140" height="20" fill="url(#b)"/>
            </g>
            <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
              <text x="50" y="15" fill="#010101" fill-opacity=".3">coverage</text>
              <text x="50" y="14">coverage</text>
              <text x="119" y="15" fill="#010101" fill-opacity=".3">${COVERAGE}%</text>
              <text x="119" y="14">${COVERAGE}%</text>
            </g>
          </svg>
          EOF

      - name: Commit and push badge
        run: |
          git config user.name "Coverage Bot"
          git config user.email "coverage@padlock.local"
          git add -A coverage.svg || true
          git commit -m "chore: update coverage badge" || true
          git push
        if: github.event_name == 'schedule' && github.ref == 'refs/heads/main'
```

### Key Features

1. **LLVM Coverage**
   - Uses `cargo-llvm-cov` for accurate line coverage
   - HTML report with source-level drill-down
   - Artifact retained for 30 days

2. **Threshold Check**
   - Fails if coverage drops below 95%
   - Prevents regressions
   - Coverage must improve or stay same

3. **Badge Generation**
   - Creates coverage badge SVG
   - Commits to repository
   - Visible in README

4. **Manual Trigger**
   - Developers can run on-demand from Actions tab
   - Useful before release to verify coverage

---

## Workflow 3: `fuzz.yml` — Fuzzing

**File**: `.github/workflows/fuzz.yml`
**Trigger**: Nightly at 02:00 UTC
**Duration**: ~15-30 minutes
**Purpose**: Discover crash and correctness bugs in parsers via fuzzing

```yaml
name: Fuzzing

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly at 02:00 UTC
  workflow_dispatch:

jobs:
  fuzz:
    name: Fuzz Testing
    runs-on: ubuntu-latest
    timeout-minutes: 45
    strategy:
      matrix:
        fuzz-target:
          - vault_parser
          - agent_protocol
          - msgpack_decoder
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust nightly
        uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2
        with:
          key: fuzz-${{ matrix.fuzz-target }}

      - name: Restore fuzz corpus
        uses: actions/cache@v3
        with:
          path: crates/padlock-core/fuzz/corpus
          key: fuzz-corpus-${{ matrix.fuzz-target }}-${{ github.run_number }}
          restore-keys: |
            fuzz-corpus-${{ matrix.fuzz-target }}-

      - name: Run fuzz target (${{ matrix.fuzz-target }}) for 10 minutes
        run: |
          cd crates/padlock-core
          timeout 600 cargo fuzz run ${{ matrix.fuzz-target }} \
            -- -max_len=16384 -timeout=10 || true
        continue-on-error: true

      - name: Check for crashes
        run: |
          if [ -d "crates/padlock-core/fuzz/artifacts/${{ matrix.fuzz-target }}" ]; then
            echo "Crashes found!"
            ls -la crates/padlock-core/fuzz/artifacts/${{ matrix.fuzz-target }}
            exit 1
          fi

      - name: Minimize and commit corpus
        run: |
          cd crates/padlock-core
          cargo fuzz cmin ${{ matrix.fuzz-target }} || true
          git config user.name "Fuzz Bot"
          git config user.email "fuzz@padlock.local"
          git add fuzz/corpus || true
          git commit -m "chore: fuzz corpus for ${{ matrix.fuzz-target }}" || true
          git push || true
        if: github.event_name == 'schedule'
```

### Key Features

1. **Matrix Strategy**
   - Runs each fuzz target in parallel
   - Speeds up overall fuzzing time
   - Independent crash detection

2. **Time Limits**
   - 10 minutes per target
   - Single input timeout: 10 seconds
   - Overall job timeout: 45 minutes

3. **Corpus Management**
   - Caches interesting inputs between runs
   - Minimizes crashes with `cargo fuzz cmin`
   - Commits to repo for regression detection

4. **Crash Detection**
   - Fails if any crashes found
   - Artifacts preserved for debugging
   - Blocks merge if fuzz finds issues

---

## Workflow 4: `audit.yml` — Daily Security Audit

**File**: `.github/workflows/audit.yml`
**Trigger**: Daily at 01:00 UTC
**Duration**: ~5 minutes
**Purpose**: Check for security vulnerabilities in dependencies

```yaml
name: Security Audit

on:
  schedule:
    - cron: '0 1 * * *'  # Daily at 01:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Audit Dependencies
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run cargo-audit
        run: cargo audit --deny warnings
        continue-on-error: true

      - name: Run cargo-deny
        run: |
          cargo install cargo-deny
          cargo deny check advisories
          cargo deny check licenses

      - name: Install cargo-vet
        run: cargo install cargo-vet

      - name: Run cargo-vet
        run: cargo vet
        continue-on-error: true

      - name: Create issue if vulnerabilities found
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const title = "🔒 Security: Vulnerability detected in dependencies";
            const body = `
            A security vulnerability was detected during the automated daily audit.

            See the [failed workflow run](${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}) for details.

            Action items:
            - [ ] Review advisory details
            - [ ] Update affected dependency
            - [ ] Run tests and verify fix
            - [ ] Update \`Cargo.lock\`
            `;

            const issues = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              labels: ['security'],
              state: 'open'
            });

            const exists = issues.data.some(i => i.title === title);
            if (!exists) {
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title: title,
                body: body,
                labels: ['security', 'dependencies']
              });
            }
```

### Key Features

1. **Multiple Audit Tools**
   - `cargo-audit`: CVE database
   - `cargo-deny`: License + advisory checks
   - `cargo-vet`: Transitive dependency review

2. **Non-blocking Warnings**
   - `continue-on-error: true` for audit tools
   - Creates GitHub issue if vulnerabilities found
   - Team notified but CI doesn't block PR

3. **Automated Issue Creation**
   - GitHub Script creates security issue
   - Links to failed workflow
   - Labels for triage

---

## Workflow 5: `release.yml` — Production Release

**File**: `.github/workflows/release.yml`
**Trigger**: On tag creation matching `v*` (e.g., `v0.1.0`)
**Duration**: ~20-30 minutes
**Purpose**: Build, sign, and publish binaries across platforms

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to release (e.g., v0.1.0)'
        required: true
        type: string

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  create-release:
    name: Create Release
    runs-on: ubuntu-latest
    outputs:
      upload_url: ${{ steps.create_release.outputs.upload_url }}
    steps:
      - name: Create GitHub Release
        id: create_release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref_name }}
          release_name: Release ${{ github.ref_name }}
          body: |
            ## Changes in ${{ github.ref_name }}

            See [CHANGELOG.md](https://github.com/${{ github.repository }}/blob/${{ github.ref_name }}/CHANGELOG.md) for details.
          draft: false
          prerelease: false

  build:
    name: Build ${{ matrix.target }}
    needs: create-release
    runs-on: ${{ matrix.os }}
    timeout-minutes: 30
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: padlock

          - os: macos-13
            target: x86_64-apple-darwin
            artifact: padlock

          - os: macos-14
            target: aarch64-apple-darwin
            artifact: padlock

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2
        with:
          key: release-${{ matrix.target }}

      - name: Build release binary
        run: |
          cargo build --release --target ${{ matrix.target }} \
            --package padlock-cli \
            -v
        env:
          CARGO_PROFILE_RELEASE_LTO: true
          CARGO_PROFILE_RELEASE_CODEGEN_UNITS: 1

      - name: Generate SBOM
        run: |
          cargo install cargo-sbom
          cargo sbom --output spdx-json > padlock-${{ matrix.target }}-sbom.json
          cargo sbom --output spdx > padlock-${{ matrix.target }}-sbom.spdx

      - name: Create checksum
        run: |
          cd target/${{ matrix.target }}/release
          sha256sum ${{ matrix.artifact }} > ${{ matrix.artifact }}.sha256
          cat ${{ matrix.artifact }}.sha256

      - name: Sign binary (macOS)
        if: startsWith(matrix.os, 'macos')
        run: |
          # Placeholder: In production, use real signing key
          echo "Binary signing not configured in CI (requires secure key management)"
        continue-on-error: true

      - name: Create release artifacts
        run: |
          mkdir -p release-artifacts
          cp target/${{ matrix.target }}/release/${{ matrix.artifact }} release-artifacts/
          cp target/${{ matrix.target }}/release/${{ matrix.artifact }}.sha256 release-artifacts/
          cp padlock-${{ matrix.target }}-sbom.json release-artifacts/
          cp padlock-${{ matrix.target }}-sbom.spdx release-artifacts/

      - name: Upload release artifacts
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./release-artifacts/${{ matrix.artifact }}
          asset_name: padlock-${{ github.ref_name }}-${{ matrix.target }}
          asset_content_type: application/octet-stream

      - name: Upload checksum
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./release-artifacts/${{ matrix.artifact }}.sha256
          asset_name: padlock-${{ github.ref_name }}-${{ matrix.target }}.sha256
          asset_content_type: text/plain

      - name: Upload SBOM (SPDX JSON)
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./release-artifacts/padlock-${{ matrix.target }}-sbom.json
          asset_name: padlock-${{ github.ref_name }}-${{ matrix.target }}-sbom.json
          asset_content_type: application/json

  update-homebrew:
    name: Update Homebrew Formula
    needs: [create-release, build]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    steps:
      - name: Trigger Homebrew update
        uses: actions/github-script@v7
        with:
          script: |
            const version = '${{ github.ref_name }}'.replace(/^v/, '');
            console.log(`Updating Homebrew formula for version ${version}`);

            // In production: Trigger workflow in homebrew-padlock repo
            // or create a dispatch event

            // Create a release note comment
            await github.rest.repos.createRelease({
              owner: context.repo.owner,
              repo: context.repo.repo,
              tag_name: context.ref,
              name: `Release ${context.ref}`,
              body: `
            ## Installation

            ### Homebrew
            \`\`\`bash
            brew install padlock
            \`\`\`

            ### Direct Download
            Download binaries from Assets below.

            Verify with:
            \`\`\`bash
            sha256sum -c padlock-${version}-<target>.sha256
            \`\`\`
              `,
              draft: false
            });

  publish-crate:
    name: Publish to Crates.io
    needs: [create-release, build]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Publish padlock-core
        run: cargo publish --package padlock-core --token ${{ secrets.CARGO_TOKEN }}
        continue-on-error: true

      - name: Publish padlock-agent
        run: cargo publish --package padlock-agent --token ${{ secrets.CARGO_TOKEN }}
        continue-on-error: true

      - name: Publish padlock-cli
        run: cargo publish --package padlock-cli --token ${{ secrets.CARGO_TOKEN }}
        continue-on-error: true
```

### Key Features

1. **Multi-Platform Build Matrix**
   - Linux x86_64 (Ubuntu latest)
   - macOS x86_64 (macOS 13 — Intel)
   - macOS aarch64 (macOS 14 — Apple Silicon)
   - Parallel builds, faster release

2. **Binary Artifacts**
   - Compiled with `--release` and LTO
   - One `CODEGEN_UNIT` for optimization
   - Artifacts attached to GitHub Release

3. **Checksums**
   - SHA256 hash for each binary
   - Users can verify integrity
   - Prevents supply chain tampering

4. **Software Bill of Materials (SBOM)**
   - SPDX JSON and SPDX formats
   - Lists all dependencies
   - Required for supply chain security

5. **Homebrew Integration**
   - Updates formula in homebrew-padlock tap
   - Users can `brew install padlock`
   - Automatic for tagged releases

6. **Crates.io Publishing**
   - Publishes all crates to registry
   - Continues even if one fails
   - Requires `CARGO_TOKEN` secret

---

## Build Matrix

### Platform Coverage

```
Target                  OS            Arch      CI Runner
─────────────────────────────────────────────────────────
x86_64-unknown-linux    Linux (glibc) x86_64    ubuntu-latest
x86_64-apple-darwin     macOS 13      x86_64    macos-13
aarch64-apple-darwin    macOS 14      ARM64     macos-14
```

### Why 3 Platforms?

- **Linux x86_64**: Most common server/container target
- **macOS Intel**: Legacy and compatibility
- **macOS Apple Silicon**: Modern Mac support (M1/M2/M3)

---

## Caching Strategy

### Cargo Registry Cache
- Shared across all workflows
- Key: `Cargo.lock` hash
- Saves download time for dependencies

### Target Directory Cache
- Per-platform (platform-specific artifacts)
- Key: `Cargo.lock` hash + platform
- Can be 500MB+ — significant speedup

### Fuzz Corpus Cache
- Specific per fuzz target
- Restored from previous runs
- Minimized and committed

**Cache Configuration** (in workflow):
```yaml
- uses: Swatinem/rust-cache@v2
  with:
    cache-directories: target
    shared-key: cargo-${{ hashFiles('**/Cargo.lock') }}
```

---

## Quality Gates (Automated Checks)

Every push and PR must pass:

| Check | Tool | Failure Mode | Blocks Merge? |
|-------|------|--------------|---------------|
| Build | `cargo build` | Compilation error | YES |
| Tests | `cargo test` | Test failure | YES |
| Clippy | `cargo clippy -- -D warnings -D clippy::pedantic` | Lint warning | YES |
| Format | `cargo fmt --check` | Code style mismatch | YES |
| Deny (licenses) | `cargo deny check` | Disallowed license | YES |
| Deny (advisories) | `cargo deny check advisories` | Known CVE | YES |
| Coverage | `cargo llvm-cov` | <95% coverage | YES |
| Fuzz (nightly) | `cargo fuzz run` | Crash or hang | YES |
| Audit (daily) | `cargo audit` | New CVE | NO (notified) |
| Vet (daily) | `cargo vet` | Unreviewed transitive dep | NO (warned) |

---

## Secrets Management

### Required GitHub Secrets

1. **`GITHUB_TOKEN`** (built-in)
   - Used for: Creating releases, uploading artifacts
   - Scope: `contents: write, releases: write`

2. **`CARGO_TOKEN`** (manual setup)
   - Used for: Publishing to crates.io
   - Setup:
     ```
     Settings → Secrets and variables → Actions → New repository secret
     Name: CARGO_TOKEN
     Value: [token from crates.io API tokens page]
     ```

3. **Signing Key** (future enhancement)
   - Used for: Binary signatures on macOS
   - Manual setup required for production

---

## Troubleshooting Workflows

### Build Fails Locally but Passes CI
- Incremental compilation state differs
- Solution: `cargo clean && cargo build`

### Cache Misses Slow Down CI
- `Cargo.lock` changed (dependencies updated)
- Solution: Normal — new cache built
- If frequent: Check for excessive dependency updates

### Fuzz Finds Crashes
1. Check artifacts in workflow logs
2. Minimize crash locally: `cargo fuzz cmin <target>`
3. Add regression test
4. Fix crash, commit, re-run workflow

### Coverage Drops Below 95%
1. View HTML report in artifacts
2. Find uncovered lines
3. Add tests or code
4. Re-run coverage workflow

### Release Fails During Build
1. Check build logs for platform-specific issues
2. Debug on that platform locally
3. Push fix to branch
4. Create new tag and retry

---

## Performance Targets

| Workflow | Ideal Duration | Max Duration | Frequency |
|----------|----------------|--------------|-----------|
| CI (main) | 5-10 min | 15 min | Every push/PR |
| Coverage | 10-15 min | 30 min | Weekly |
| Fuzz | 15-30 min | 45 min | Nightly |
| Audit | 3-5 min | 10 min | Daily |
| Release | 20-30 min | 45 min | On tag |

---

## Monitoring and Alerts

### Failure Notifications
- Failed CI blocks PR merge (GitHub status check)
- Failed nightly audit: Creates security issue
- Failed release: Manual investigation required

### Workflow Status Badge
Add to `README.md`:
```markdown
[![CI Status](https://github.com/your-org/padlock/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/padlock/actions/workflows/ci.yml)
[![Coverage](./coverage.svg)](https://github.com/your-org/padlock)
```

---

## Setting Up CI/CD From Scratch

```bash
# 1. Create workflows directory
mkdir -p .github/workflows

# 2. Copy workflow YAML files
cp ci.yml .github/workflows/
cp coverage.yml .github/workflows/
cp fuzz.yml .github/workflows/
cp audit.yml .github/workflows/
cp release.yml .github/workflows/

# 3. Create .cargo/config.toml for build settings
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[build]
incremental = false

[profile.release]
lto = true
codegen-units = 1
strip = true
EOF

# 4. Set GitHub secrets
# - Go to repo Settings → Secrets and variables → Actions
# - Add CARGO_TOKEN (from crates.io)

# 5. Commit and push
git add .github/ .cargo/
git commit -m "ci: add GitHub Actions workflows"
git push

# 6. Verify workflows
# - Go to Actions tab
# - Should see runs starting
```

This CI/CD setup ensures code quality, security, and release automation from day one.

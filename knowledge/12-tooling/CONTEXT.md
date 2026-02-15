# Development Tools & Automation — Padlock

This file documents the development tooling ecosystem, automation workflows, and editor setup for the Padlock project.

## Development Tools

### Build & Test Automation
- **`cargo-watch`**: Auto-rebuild and test on file changes
  - Command: `cargo watch -x test -x clippy`
  - Useful for rapid iteration during feature development

### Code Quality & Coverage
- **`cargo-llvm-cov`**: Code coverage with HTML reports
  - Generates coverage metrics and visual reports
  - Helps identify untested code paths

- **`cargo-expand`**: Inspect macro expansion
  - Useful for debugging derive macro output and understanding generated code
  - Command: `cargo expand -p padlock-core`

### Testing & Verification
- **`cargo-fuzz`**: Fuzzing with libFuzzer
  - Automated input generation for parser and codec components
  - Catches edge cases and malformed input handling

- **`cargo-mutants`**: Mutation testing
  - Verifies that tests actually catch bugs
  - Mutates code and checks if tests fail
  - Ensures test quality is high

### Dependency & Supply Chain Management
- **`cargo-deny`**: Audit dependencies for license compliance and known vulnerabilities
  - Blocks unmaintained crates and incompatible licenses

- **`cargo-vet`**: Supply chain review and attestation
  - Vets third-party dependencies for security and quality
  - Maintains audit records

### Dependency Cleanup
- **`cargo-udeps`**: Find unused dependencies
  - Identifies crates that can be removed

- **`cargo-machete`**: Alternative unused dependency finder
  - Faster and more user-friendly than cargo-udeps

### Release & Versioning
- **`cargo-release`**: Automate version bumps and publishing
  - Handles semantic versioning, tagging, and crate publication
  - Command: `cargo release --no-publish` (for dry-run)

### Performance & Profiling
- **`hyperfine`**: CLI benchmarking tool
  - Compares performance across commits
  - Useful for optimization work

- **`flamegraph`**: Generate performance profiles
  - Visualize where time is spent
  - Essential for tuning Argon2id KDF and crypto operations

### Project Management
- **`just`**: Justfile task runner
  - Better than Make for Rust projects
  - Portable across platforms
  - Install: `cargo install just`

### Changelog Generation
- **`git-cliff`**: Generate changelogs from conventional commits
  - Parses commit messages and creates structured release notes
  - Install: `cargo install git-cliff`

---

## Justfile Template

Create a `justfile` at the project root with the following recipes:

```just
# Default recipe
default: check test

# Build the project
build:
    cargo build --release

# Run all tests
test:
    cargo test --workspace

# Run tests for a specific package
test-package package:
    cargo test --package {{package}}

# Run tests with backtrace for debugging
test-verbose:
    RUST_BACKTRACE=full cargo test --workspace -- --nocapture

# Format code
fmt:
    cargo fmt --all

# Check formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Run clippy linter with all pedantic checks
clippy:
    cargo clippy --workspace -- -D warnings -D clippy::pedantic

# Run all checks: fmt, clippy, and clippy::pedantic
check: fmt-check clippy
    cargo check --workspace

# Generate code coverage report
coverage:
    cargo llvm-cov --html --open

# Run fuzz testing on a specific target
fuzz target:
    cargo +nightly fuzz run {{target}} -- -max_len=1024 -timeout=10

# Run all security audits: cargo deny + cargo vet
audit:
    cargo deny check
    cargo vet

# Run automated security checks
security-check:
    cargo deny check advisories
    cargo audit

# Check for unused dependencies
unused-deps:
    cargo machete

# Perform mutation testing
mutants:
    cargo mutants --no-copy-target

# Bump version, tag, build, and sign release
release version:
    cargo release --tag-name v{{version}} --no-publish

# Clean build artifacts
clean:
    cargo clean

# Install all development tools
install-tools:
    cargo install cargo-watch
    cargo install cargo-llvm-cov
    cargo install cargo-deny
    cargo install cargo-vet
    cargo install cargo-expand
    cargo install cargo-machete
    cargo install cargo-release
    cargo install hyperfine
    cargo install flamegraph
    cargo install git-cliff
    cargo install just

# Run benchmarks
bench:
    cargo bench --workspace

# Profile with flamegraph (requires linux-perf)
profile target:
    cargo flamegraph --bin {{target}}

# Run formatter and clippy as pre-commit checks
pre-commit: fmt-check clippy
    @echo "✓ Pre-commit checks passed"

# Full CI-like check before committing
pre-push: check test coverage unused-deps security-check
    @echo "✓ All pre-push checks passed"
```

---

## Pre-commit Hook

Create `.git/hooks/pre-commit` with execute permissions (`chmod +x .git/hooks/pre-commit`):

```bash
#!/bin/bash
set -e

echo "Running pre-commit checks..."

# Format check
echo "Checking code formatting..."
if ! cargo fmt --all -- --check; then
    echo "❌ Code formatting failed. Run 'cargo fmt --all' to fix."
    exit 1
fi

# Clippy check
echo "Running clippy..."
if ! cargo clippy --workspace -- -D warnings -D clippy::pedantic; then
    echo "❌ Clippy checks failed. Fix warnings above."
    exit 1
fi

echo "✓ Pre-commit checks passed"
exit 0
```

Or use a Python-based pre-commit framework (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all --
        language: system
        pass_filenames: false
        stages: [commit]

      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace -- -D warnings -D clippy::pedantic
        language: system
        pass_filenames: false
        stages: [commit]
```

---

## Editor Setup

### VS Code Configuration

Create or update `.vscode/settings.json`:

```json
{
  "[rust]": {
    "editor.formatOnSave": true,
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  },
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.checkOnSave.extraArgs": [
    "--all-targets",
    "--",
    "-D",
    "warnings",
    "-D",
    "clippy::pedantic"
  ],
  "rust-analyzer.inlayHints.enable": true,
  "rust-analyzer.inlayHints.typeHints.enable": true,
  "rust-analyzer.inlayHints.lifetimeElisionHints.enable": "all",
  "rust-analyzer.hover.documentation.enable": true,
  "editor.rulers": [100, 120],
  "files.exclude": {
    "**/target": true,
    "**/.git": true
  }
}
```

### Recommended Extensions

Install these VS Code extensions for optimal Rust development:

1. **rust-analyzer** (rust-lang.rust-analyzer)
   - Primary Rust language support
   - IntelliSense, debugging, refactoring

2. **crates** (serayuzgur.crates)
   - Inline dependency version management
   - Check for outdated crates

3. **Error Lens** (usernamehw.errorlens)
   - Display errors inline with code
   - Better diagnostic visibility

4. **Test Explorer UI** (hbenl.test-explorer)
   - Run/debug individual tests from the editor
   - View test hierarchy

5. **Even Better TOML** (tamasfe.even-better-toml)
   - TOML syntax highlighting and validation
   - Cargo.toml autocomplete

6. **CodeLLDB** (vadimcn.vscode-lldb)
   - Debugger for Rust
   - Breakpoints, step through code

---

## Claude Code Workflow Tips

### Before Starting Development
1. **Read the Context File**
   - Always start by reading `knowledge/<COMPONENT>/CONTEXT.md`
   - Understand the module's design, invariants, and testing strategy

2. **Understand the Current State**
   - Review existing tests to understand expected behavior
   - Check for TODOs and FIXMEs in the code

### Fast Iteration on Tests
```bash
# Run tests for a specific library package only (fastest)
cargo test --lib -p padlock-core -- <test_name>

# Run all workspace tests before committing
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture
```

### Linting & Quality Checks
```bash
# Full lint suite with pedantic warnings
cargo clippy --workspace -- -D warnings -D clippy::pedantic

# Format code
cargo fmt --all

# Check without modifying
cargo fmt --all -- --check

# Full pre-commit check
cargo check --workspace && cargo clippy --workspace -- -D warnings
```

### Benchmarking During Development
```bash
# Quick benchmark (useful for crypto operations)
cargo bench --workspace

# Profile a specific binary with flamegraph
cargo flamegraph --bin padlock -- <args>

# Compare performance across commits
hyperfine "git show HEAD:src/file.rs" "git show HEAD~1:src/file.rs"
```

### Test-Driven Development Pattern
When implementing a new module:

1. **Scaffold Types & Signatures**
   ```rust
   pub struct NewComponent {
       // fields
   }

   impl NewComponent {
       pub fn new() -> Self { todo!() }
       pub fn process(&mut self, input: &[u8]) -> Result<Vec<u8>> { todo!() }
   }
   ```

2. **Write Tests First**
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_basic_operation() {
           let mut component = NewComponent::new();
           let result = component.process(b"input").unwrap();
           assert_eq!(result, b"expected");
       }
   }
   ```

3. **Implement Logic Until Tests Pass**
   - Run `cargo test --lib -p padlock-core -- <test_name>` frequently
   - Implement incrementally, testing after each meaningful change

4. **Address Linting Issues**
   - Run `cargo clippy` and fix warnings
   - Ensure pedantic lints pass

5. **Measure Coverage**
   - `cargo llvm-cov --html`
   - Identify uncovered branches
   - Add tests for edge cases

6. **For Parser/Codec Components: Fuzz Test**
   - `cargo +nightly fuzz run <target>`
   - Let libFuzzer find edge cases
   - Add regression tests for any crashes found

---

## Recommended Development Cycle

### For Bug Fixes
1. Write a failing test that reproduces the bug
2. Implement the fix
3. Verify the test passes
4. Run `cargo test --workspace`
5. Run `cargo clippy --workspace -- -D warnings`
6. Commit

### For New Features
1. Read the relevant `knowledge/<COMPONENT>/CONTEXT.md`
2. Scaffold types and function signatures with `todo!()` placeholders
3. Write comprehensive tests for expected behavior
4. Implement logic incrementally (TDD approach)
5. `cargo test --lib -p padlock-core -- <test_name>` repeatedly during implementation
6. Run full test suite: `cargo test --workspace`
7. Run linting: `cargo clippy --workspace -- -D warnings -D clippy::pedantic`
8. Generate coverage: `cargo llvm-cov --html` and review uncovered paths
9. For crypto/parsing components: Run fuzzer: `cargo +nightly fuzz run <target>`
10. Update the relevant `knowledge/` CONTEXT.md file with new insights
11. Commit with conventional commit message

### Before Pushing
```bash
just pre-push
```

This runs:
- Format checks
- Clippy (with pedantic)
- Full test suite
- Coverage report
- Unused dependency check
- Security audit

---

## Performance Profiling Workflow

### For Argon2id KDF Tuning
1. Benchmark baseline: `cargo bench --workspace -- argon2`
2. Modify Argon2 parameters in `crypto/kdf.rs`
3. Benchmark again: `cargo bench --workspace -- argon2`
4. Use flamegraph for detailed profiling: `cargo flamegraph --bench argon2`
5. Compare CPU time with previous tuning: `hyperfine "old_binary" "new_binary"`

### For General Performance Investigation
```bash
# Profile a specific operation
cargo flamegraph --bin padlock -- decrypt --file target.enc

# Generate call graph
cargo flamegraph --bin padlock -- --callgraph=dwarf

# Use perf directly for more control
perf record -F 99 --call-graph=dwarf ./target/release/padlock decrypt
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

---

## Dependency Management

### Regular Maintenance
```bash
# Check for outdated dependencies
cargo outdated

# Check for unused dependencies
cargo machete

# Audit for vulnerabilities
cargo deny check advisories
cargo audit

# Vet supply chain security
cargo vet
```

### Adding Dependencies
Before adding a new crate:
1. Check: `cargo vet` can vouch for it or it's well-established
2. Verify license compatibility with Padlock's license
3. Consider size impact on build times
4. Add to Cargo.toml with minimal version specification

---

## Debugging Tips

### View Macro Expansion
```bash
# See what derive macros generate
cargo expand -p padlock-core --lib crypto::kdf

# Expand a specific test
cargo expand -p padlock-core --test crypto_tests
```

### Debug Test Output
```bash
# Show println! and eprintln! output
cargo test -- --nocapture

# Keep test output on success
cargo test -- --nocapture --test-threads=1

# Show Rust backtrace
RUST_BACKTRACE=full cargo test
```

### Profile Memory Usage
```bash
# With valgrind (Linux)
valgrind --leak-check=full ./target/release/padlock

# Or use flamegraph's memory profiling
cargo flamegraph --bin padlock -- --maxrss
```

---

## CI/CD Integration

When setting up GitHub Actions or similar:

```yaml
# Check formatting
cargo fmt --all -- --check

# Run all lints
cargo clippy --workspace -- -D warnings -D clippy::pedantic

# Run tests
cargo test --workspace

# Run security audits
cargo deny check
cargo audit

# Generate and store coverage
cargo llvm-cov --lcov --output-path lcov.info
```

Save the LCOV file for coverage badges and reports.

---

## Quick Reference

| Task | Command |
|------|---------|
| Fast test iteration | `cargo test --lib -p padlock-core -- <test>` |
| Full test suite | `cargo test --workspace` |
| Format code | `cargo fmt --all` |
| Lint with pedantic | `cargo clippy --workspace -- -D warnings -D clippy::pedantic` |
| Coverage report | `cargo llvm-cov --html --open` |
| Fuzz a target | `cargo +nightly fuzz run <target>` |
| Benchmark | `cargo bench --workspace` |
| Profile | `cargo flamegraph --bin <binary>` |
| Check deps | `cargo machete` |
| Security audit | `cargo deny check` |
| Pre-commit check | `just pre-commit` |
| Pre-push check | `just pre-push` |

---

## Notes for Claude Code Development

- Always run `cargo fmt --all` and `cargo clippy` before asking for code review
- Use `cargo test --lib -p padlock-core` for rapid feedback loops during implementation
- When tests fail, check the error message first, then use `RUST_BACKTRACE=1` for more context
- Coverage gaps often indicate missing edge case handling—prioritize testing error paths
- Fuzz testing is essential for any code that parses untrusted input
- Keep the knowledge base files updated as you discover implementation details or gotchas

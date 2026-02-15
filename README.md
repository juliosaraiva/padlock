# Padlock

Encrypted credential manager for developers.

[![CI](https://github.com/padlock-dev/padlock/actions/workflows/ci.yml/badge.svg)](https://github.com/padlock-dev/padlock/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)
![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange)

## What Is Padlock

Padlock replaces scattered `.env` files, plaintext SSH keys, and API tokens with a single encrypted vault managed from the terminal. Store credentials, SSH keys, TOTP seeds, `.netrc` entries, and arbitrary binary secrets in one place.

It includes a built-in SSH agent daemon that serves vault keys to SSH clients and supports Git commit and tag signing via SSH keys -- no GPG required.

Padlock uses XChaCha20-Poly1305 for authenticated encryption, Argon2id for key derivation, and HKDF-SHA-256 for the key hierarchy. All secrets are zeroed from memory after use. The CLI binary is compiled with `#![forbid(unsafe_code)]`. Written in Rust.

## Features

- **Vault management** -- init, lock, unlock, status
- **5 secret types** -- credentials, SSH keys, TOTP seeds, `.netrc` entries, binary blobs
- **SSH agent daemon** -- serves vault SSH keys to `ssh`, `scp`, `git`, etc.
- **Git commit/tag signing** -- configure Git to sign with vault SSH keys
- **Password generation** -- configurable length and character sets with strength estimation
- **TOTP code generation** -- RFC 6238 time-based one-time passwords
- **Secret injection** -- `padlock exec VAR=entry -- cmd` injects secrets as environment variables
- **Tamper-evident audit log** -- tracks all vault operations
- **JSON output mode** -- `--json` flag on all commands for scripting
- **Shell completions** -- bash, zsh, fish

## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/padlock-dev/padlock/releases).

**macOS (Apple Silicon):**
```bash
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-aarch64-apple-darwin
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-aarch64-apple-darwin.sha256
sha256sum -c padlock-aarch64-apple-darwin.sha256
chmod +x padlock-aarch64-apple-darwin
sudo mv padlock-aarch64-apple-darwin /usr/local/bin/padlock
```

**macOS (Intel):**
```bash
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-x86_64-apple-darwin
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-x86_64-apple-darwin.sha256
sha256sum -c padlock-x86_64-apple-darwin.sha256
chmod +x padlock-x86_64-apple-darwin
sudo mv padlock-x86_64-apple-darwin /usr/local/bin/padlock
```

**Linux (x86_64):**
```bash
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-x86_64-unknown-linux-gnu
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-x86_64-unknown-linux-gnu.sha256
sha256sum -c padlock-x86_64-unknown-linux-gnu.sha256
chmod +x padlock-x86_64-unknown-linux-gnu
sudo mv padlock-x86_64-unknown-linux-gnu /usr/local/bin/padlock
```

**Linux (ARM64):**
```bash
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-aarch64-unknown-linux-gnu
curl -LO https://github.com/padlock-dev/padlock/releases/latest/download/padlock-aarch64-unknown-linux-gnu.sha256
sha256sum -c padlock-aarch64-unknown-linux-gnu.sha256
chmod +x padlock-aarch64-unknown-linux-gnu
sudo mv padlock-aarch64-unknown-linux-gnu /usr/local/bin/padlock
```

### From Source

Requires Rust 1.75 or later.

```bash
git clone https://github.com/padlock-dev/padlock.git
cd padlock
cargo install --path crates/padlock-cli
```

> `cargo install padlock-cli` will be available once the crate is published to crates.io.

### Verify Installation

```bash
padlock --version
```

## Shell Completions

```bash
# Bash
padlock completions bash > ~/.local/share/bash-completion/completions/padlock

# Zsh
padlock completions zsh > "${fpath[1]}/_padlock"

# Fish
padlock completions fish > ~/.config/fish/completions/padlock.fish
```

## Quick Start

```bash
# Create a new vault (prompts for passphrase)
padlock init

# Store a credential
padlock set github -u myuser -p "ghp_xxxxxxxxxxxx"

# Retrieve it
padlock get github

# Print only the password
padlock get github -p

# Generate a random password (default 24 chars)
padlock generate --length 32

# List all entries
padlock ls

# Search by name or tag
padlock search api
```

## Usage

### SSH Agent

Start the agent daemon, point your shell at its socket, then SSH as usual:

```bash
padlock agent start
eval "$(padlock agent shell-env)"
padlock agent list
ssh user@host
padlock agent stop
```

Run `padlock agent start --foreground` to keep the agent in the foreground for debugging.

### Git Signing

Configure Git to sign commits with an SSH key from your vault:

```bash
padlock git setup --global --key my-signing-key
git commit -m "signed commit"
padlock git verify HEAD
padlock git allowed-signers --output ~/.padlock/allowed_signers
```

### TOTP

Generate a one-time code from a TOTP entry:

```bash
padlock totp generate my-2fa-entry
```

### Secret Injection

Run a command with secrets injected as environment variables:

```bash
padlock exec DB_PASS=database-creds API_KEY=stripe-key -- ./deploy.sh
```

Each `VAR=entry_name` pair resolves the entry and sets the environment variable for the child process.

### Audit Log

View vault activity with optional filters:

```bash
padlock audit
padlock audit --since 24h
padlock audit --since 7d --action entry-read
padlock audit --entry <uuid>
```

### Configuration

Settings are stored in `~/.padlock/config.toml`:

```bash
padlock config list
padlock config get session.duration
padlock config set session.duration 4h
```

Available keys: `session.duration`, `session.max_sessions`, `session.auto_session`.

## Configuration Reference

| Setting | Description | Default location / value |
|---------|-------------|--------------------------|
| Vault file | Encrypted vault | `~/.padlock/vault.padlock` |
| Config file | TOML configuration | `~/.padlock/config.toml` |
| `PADLOCK_VAULT` | Override vault path | env var |
| `PADLOCK_SESSION` | Session token (hex) | env var |

## Security Model

- **XChaCha20-Poly1305** AEAD encryption (24-byte nonces)
- **Argon2id** key derivation (RFC 9106)
- **HKDF-SHA-256** key hierarchy: passphrase -> PDK -> KEK -> DEK
- **`secrecy::Secret<T>`** + **`zeroize`** for all secret values
- **`mlock`** for key material memory pages
- **Constant-time comparisons** via `subtle::ConstantTimeEq`
- **0600 file permissions** on vault, socket, and session token
- **Tamper-evident audit log** (HMAC chain)
- **`#![forbid(unsafe_code)]`** in the CLI crate

See [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md) for the full security design.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Vault is locked |
| 3 | Entry not found |
| 4 | Wrong passphrase |
| 5 | Integrity check failed (HMAC mismatch) |
| 10 | SSH agent not running |

## Building from Source

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings -D clippy::pedantic
cargo fmt --check --all
```

## Contributing

- Follow the commit convention: `<type>(<scope>): <description>`
  - Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `security`
  - Scopes: `crypto`, `vault`, `entries`, `cli`, `agent`, `signing`, `sync`, `ci`, `deps`
- 95% test coverage minimum (`cargo llvm-cov`)
- Clippy pedantic and rustfmt clean

## License

Licensed under either of [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or [MIT License](http://opensource.org/licenses/MIT), at your option.

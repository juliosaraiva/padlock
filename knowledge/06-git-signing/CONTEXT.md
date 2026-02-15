# Git Signing Implementation Context

## Overview

The Git Signing module enables signing of Git commits and tags using SSH keys stored in the Padlock vault. It integrates with Git's SSH signing capability to provide a seamless, secure signing experience without exposing private keys to Git itself.

## Purpose

Implement Git signing support that:
- Signs commits and tags using SSH keys from the vault
- Integrates with Git's `gpg.format=ssh` feature
- Provides automatic Git configuration management
- Manages trusted signers (allowed_signers files)
- Verifies commit and tag signatures
- Supports per-repository key selection policies
- Logs all signing operations for audit trails
- Provides rate limiting to detect abuse

## How Git SSH Signing Works

The signing flow leverages Git's native SSH signing support:

### Traditional GPG Signing Flow
```
User: git commit -S
  ↓
Git: calls gpg --sign
  ↓
GPG: has keys, signs, returns signature
  ↓
Commit created with signature
```

### Git SSH Signing Flow (v1 scope)
```
User: git commit -S
  ↓
Git: calls ssh-keygen -Y sign
  ↓
ssh-keygen: connects to SSH_AUTH_SOCK (Padlock agent)
  ↓
Padlock agent: signs using key from vault
  ↓
ssh-keygen: returns signature
  ↓
Commit created with signature
```

### Key Insight

Git doesn't directly invoke the agent. Instead:
1. Git uses `ssh-keygen -Y sign` (from OpenSSH)
2. ssh-keygen connects to the socket at `SSH_AUTH_SOCK`
3. Padlock's SSH agent handles the signing request
4. ssh-keygen formats the signature for Git
5. Git stores the signature in the commit

Therefore, **Git signing works automatically once the SSH agent is running**.

## Scope: v1 Features

In v1, we implement SSH signing only:

- **Supported**: SSH key signing (Ed25519, ECDSA, RSA)
- **Deferred to v2+**: GPG signing (requires GPG infrastructure)
- **Deferred to v2+**: X.509 certificate signing (requires PKI setup)

## Git Configuration

Git uses several configuration variables to enable SSH signing:

### Core Settings

```ini
# Use SSH for signing (not GPG)
[gpg]
  format = ssh

# Path to public key (used by ssh-keygen)
[user]
  signingKey = /path/to/id_ed25519.pub

# Location of allowed_signers file (for verification)
[gpg "ssh"]
  allowedSignersFile = ~/.padlock/allowed_signers

# Sign commits by default
[commit]
  gpgSign = true

# Sign tags by default
[tag]
  gpgSign = true
```

### Per-Repository Override

Users can override global settings per-repository:

```bash
cd /path/to/repo
git config user.signingKey ~/.padlock/keys/work_rsa.pub
git config commit.gpgSign true
```

### gitconfig includeIf

Advanced users can use conditional includes:

```ini
# In ~/.gitconfig
[includeIf "gitdir:~/work/"]
  path = ~/.gitconfig-work

# In ~/.gitconfig-work
[user]
  signingKey = ~/.padlock/keys/work.pub
[commit]
  gpgSign = true
```

## Padlock Commands

### `padlock git setup`

Configure Git to use Padlock for signing:

```bash
padlock git setup [--global|--local] [--key KEY_ID]
```

**Behavior:**
1. Optional: Auto-detect signing key
   - If `--key` provided, use that key
   - Else, offer interactive selection from vault keys
   - Else, use first Ed25519 key
2. Configure global or local git config:
   - Set `gpg.format = ssh`
   - Set `user.signingKey = <public key path>`
   - Set `gpg.ssh.allowedSignersFile`
   - Set `commit.gpgSign = true` (optional, user choice)
   - Set `tag.gpgSign = true` (optional, user choice)
3. Create `~/.padlock/allowed_signers` if needed (initially empty)
4. Output summary of changes
5. Log operation with key used

**Output Example:**
```
Git signing configured successfully!
  Format: SSH
  Key: work_ed25519 (Ed25519)
  Allowed signers: ~/.padlock/allowed_signers

Configure auto-signing with:
  git config commit.gpgSign true
```

**Flags:**
- `--global`: Apply to global `~/.gitconfig`
- `--local`: Apply to current repository's `.git/config` (default)
- `--key KEY_ID`: Use specific key by ID or name

### `padlock git allowed-signers`

Export trusted public keys to `allowed_signers` file format:

```bash
padlock git allowed-signers [--output FILE] [--add EMAIL] [--remove EMAIL] [--list]
```

**Behavior:**
1. Read vault entries with git-related tags
2. Extract public keys
3. Format in OpenSSH allowed_signers format:
   ```
   user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1...
   ```
4. Write to `~/.padlock/allowed_signers`
5. Log operation

**Flags:**
- `--output FILE`: Write to specific file (default: `~/.padlock/allowed_signers`)
- `--add EMAIL`: Add new entry for email
- `--remove EMAIL`: Remove entry for email
- `--list`: Show current entries without writing

**Use Case:**

After generating SSH keys, administrators create an `allowed_signers` file for teams:

```bash
# Alice exports her key
padlock git allowed-signers --add alice@company.com

# Bob does the same
padlock git allowed-signers --add bob@company.com

# The file now contains both public keys
cat ~/.padlock/allowed_signers
# user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1...
# bob@company.com ssh-ed25519 AAAAC3NzaC1lZDI1...
```

### `padlock git verify`

Verify a commit or tag signature:

```bash
padlock git verify [--commit HASH] [--tag TAG] [--file FILE]
```

**Behavior:**
1. Extract signature from commit/tag object
2. Verify signature using allowed_signers file
3. Output validity and key details
4. Log verification attempt

**Output Example:**
```
✓ Signature valid
  Signer: alice@company.com
  Key: Ed25519 (AAAAC3NzaC1lZDI1...)
  Date: 2024-02-15 10:30:45 UTC
```

**Flags:**
- `--commit HASH`: Verify specific commit (default: HEAD)
- `--tag TAG`: Verify specific tag
- `--file FILE`: Verify signature in detached file

## Key Selection Policy

When signing, the agent needs to know which key to use. Selection is determined in order:

### 1. Per-Repository Configuration

Highest priority. If the repository has configured `user.signingKey`:

```bash
git config user.signingKey
```

The SSH agent uses the key at this path. If it's a vault key, the agent retrieves it.

### 2. Key Tagging System

Keys in the vault can be tagged for specific purposes:

```
Entry: "GitHub SSH Key"
Tags: [git, work, ssh]

Entry: "Personal GitLab Key"
Tags: [git, personal, ssh]
```

When signing, if multiple keys are available:
- Filter to keys with `git` and `ssh` tags
- Filter to keys with matching context tags (if set)
- Use highest-priority key

### 3. Global Configuration

Fallback to global git config:

```bash
git config --global user.signingKey
```

### 4. Interactive Selection

If multiple keys available and no explicit configuration:

```
Multiple signing keys found. Choose one:
1) work_ed25519 (Ed25519) - last used 2 days ago
2) github_personal (Ed25519) - created 1 year ago
3) legacy_rsa (RSA-4096) - created 3 years ago

Select key [1]:
```

### 5. Default Key

If only one key available with git/ssh tags, use it automatically.

## Audit Logging

Every signing operation is logged with:

```json
{
  "timestamp": "2024-02-15T10:30:45.123Z",
  "operation": "sign_commit",
  "key_id": "work_ed25519",
  "key_type": "Ed25519",
  "key_fingerprint": "SHA256:AAAABBBB...",
  "data_hash": "abc123def456",
  "repository": "/home/user/myproject",
  "source": "git commit",
  "status": "success",
  "duration_ms": 125
}
```

**Logged Information:**
- Timestamp (ISO 8601 UTC)
- Operation type (sign_commit, sign_tag, verify_commit, etc.)
- Key ID and type used
- Hash of data being signed (for audit trail)
- Repository path (if applicable)
- Source (git commit, ssh-keygen, direct API call)
- Status (success, failure, denied)
- Operation duration in milliseconds

**Log Storage:**

Logs stored in `~/.padlock/logs/signing.log` (or per config):

```
[2024-02-15T10:30:45.123Z] SIGN_COMMIT | work_ed25519 | /home/user/myproject | abc123def456
[2024-02-15T10:31:12.456Z] SIGN_TAG | github_personal | /home/user/project2 | xyz789...
[2024-02-15T10:32:00.789Z] VERIFY_COMMIT | /home/user/project | valid
```

**Sensitivity:**
- Logs do NOT contain private key material
- Logs do NOT contain full signature data
- Logs contain key fingerprints and operation metadata only

## Rate Limiting

Optional rate limiting to detect automated abuse:

```toml
[signing]
rate_limit_enabled = true
max_signs_per_minute = 60
max_signs_per_hour = 1000
rate_limit_action = "warn"  # "warn" or "block"
```

**Behavior:**

1. **Per-key rate limiting**: Track signatures per key, not globally
2. **Window**: Sliding window (per-minute, per-hour)
3. **Action on limit exceeded**:
   - `"warn"`: Log warning, continue signing
   - `"block"`: Refuse signature, return error
4. **Reset**: Counters reset on timeout
5. **Alerts**: Send alert if limit exceeded (admin notification)

**Use Case:**

Detects if an attacker gains access to the agent and starts signing many commits programmatically:

```
[2024-02-15T12:00:00Z] RATE_LIMIT_EXCEEDED | work_ed25519 | 75 signs in 60 sec (limit: 60)
```

## Module Structure

The Git signing implementation is organized into:

### `signing/mod.rs`
- Module root and public API
- Exports main types and functions
- Command implementations: `setup()`, `allowed_signers()`, `verify()`
- Integration with SSH agent

### `signing/ssh.rs`
- SSH signing operations
- Integration with SSH agent (via SSH_AUTH_SOCK)
- Signature formatting for Git
- Public key extraction
- Verification using allowed_signers

### `signing/git_config.rs`
- Git configuration management
- Read/write `.git/config` and `~/.gitconfig`
- Detect current configuration
- Generate configuration recommendations

### `signing/allowed_signers.rs`
- Parsing and writing allowed_signers format
- Email-to-public-key mapping
- Validation of OpenSSH wire format keys
- File locking and atomic writes

## Dependencies (Internal Modules)

This module depends on:

1. **ssh_agent module** - Used for signing operations
   - Connects to `SSH_AUTH_SOCK`
   - Requests signatures

2. **entries module** - Access to stored keys
   - Query keys by tag (git, ssh)
   - Get key metadata and public keys
   - Retrieve key entry details

3. **vault module** - Access to vault data
   - Master password verification (for certain operations)
   - Vault state sync

4. **logging module** - Audit trail
   - Log all operations
   - Timestamp, key usage, verification

5. **config module** - Application configuration
   - Rate limiting settings
   - Log location
   - Default behaviors

## External Crates

### Git Configuration Management

- **git2** (>=0.13) or **gix** (>=0.60) - Alternative
  - Detect Git repository
  - Read/write Git configuration
  - Extract commit/tag objects

  Alternative: Use `git` command line directly via subprocess

- **ssh-key** (>=0.6)
  - Parse and validate OpenSSH public keys
  - Handle different key formats

### File Operations

- **tokio::fs** - Async file operations
- **tempfile** (>=3.8) - Atomic writes with temp files
- **flate2** (optional) - Compression for log files

## Testing Strategy

### End-to-End Repository Testing

**Test: Setup Command**
- Create temporary Git repository
- Run `padlock git setup --key [test_key]`
- Verify git config is written correctly
- Verify allowed_signers file is created
- Verify settings are applied

**Test: Actual Commit Signing**
```bash
# Initialize temp repo
mkdir /tmp/test-repo && cd /tmp/test-repo && git init

# Configure
padlock git setup --global --key test_ed25519

# Create commit
echo "test" > test.txt
git add test.txt
git commit -m "Test commit"

# Verify signature exists
git log --show-signature
git verify-commit HEAD  # May need custom implementation
```

**Test: Tag Signing**
```bash
# Sign a tag
git tag -s -m "Test tag" v1.0.0

# Verify signature
git verify-tag v1.0.0
```

### Key Selection Testing

**Test: Per-repo config takes precedence**
- Set global signing key A
- Set repo-specific signing key B
- Sign commit
- Verify key B was used

**Test: Interactive selection**
- Create multiple test keys with git tags
- Remove git config (force interactive mode)
- Mock user input to select specific key
- Verify correct key was used

**Test: Default key**
- Create single git/ssh-tagged key
- Remove all config
- Sign commit
- Verify key was selected automatically

### Verification Testing

**Test: Verify valid signature**
- Create commit with known key
- Verify signature against allowed_signers file
- Confirm "valid" response

**Test: Reject invalid signature**
- Tamper with commit data (in test)
- Attempt verification
- Confirm "invalid" response

**Test: Reject unsigned commit**
- Create unsigned commit
- Attempt verification
- Confirm "unsigned" response

### Configuration Testing

**Test: Detect existing config**
- Set up repo with manual git config
- Run `padlock git setup`
- Verify it detects and preserves existing settings
- Verify non-conflicting settings coexist

**Test: Global vs Local**
- Set global config
- Override with local config
- Verify local takes precedence

### Audit Logging Testing

**Test: Log entry creation**
- Perform signing operation
- Check log file for entry
- Verify all fields are present
- Verify no sensitive data leaked

**Test: Log rotation**
- Perform many operations
- Verify logs don't grow unbounded
- Verify rotation/cleanup works

### Rate Limiting Testing

**Test: Normal operation within limit**
- Perform operations at normal rate
- Verify all succeed

**Test: Exceed rate limit**
- Perform rapid operations exceeding limit
- Verify action matches config (warn or block)
- Verify log contains rate limit event

## Integration Points

### With SSH Agent

The signing module relies on the SSH agent to actually perform signing:

1. When `padlock git setup` is called:
   - Ensure SSH agent is running
   - Start agent if needed
   - Verify can connect to SSH_AUTH_SOCK

2. When signing happens:
   - Git calls `ssh-keygen -Y sign`
   - ssh-keygen connects to agent socket
   - Agent returns signature
   - No explicit Padlock integration needed at this layer

### With Git

Integration is indirect through Git configuration and ssh-keygen:

1. User runs `git commit -S`
2. Git invokes `ssh-keygen -Y sign` with configured key
3. ssh-keygen uses SSH_AUTH_SOCK (Padlock agent)
4. Agent handles signature

### With Vault

When exporting allowed_signers:
- Query vault for entries with git+ssh tags
- Extract public keys
- Map to email addresses (from entry metadata or tags)
- Write allowed_signers file

## Configuration Example

```toml
# In ~/.padlock/config.toml
[signing]
enabled = true
log_all_operations = true
log_path = "~/.padlock/logs/signing.log"
rate_limit_enabled = true
max_signs_per_minute = 60
max_signs_per_hour = 1000
rate_limit_action = "warn"  # or "block"

[git]
auto_setup_gpg_format = true
default_git_tags = ["git", "ssh"]
allowed_signers_path = "~/.padlock/allowed_signers"
interactive_key_selection = true
```

## Future Enhancements (v2+)

These are planned but out of v1 scope:

1. **GPG Signing**: Full GPG key management
2. **X.509 Signing**: Certificate-based signing
3. **Signature Verification UI**: GUI for verification results
4. **Team Key Management**: Share keys within teams securely
5. **Compliance Reports**: Generate signing audit reports
6. **Webhook Integration**: Notify on signing events

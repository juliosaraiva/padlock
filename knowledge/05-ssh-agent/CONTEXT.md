# SSH Agent Implementation Context

## Overview

The SSH Agent module implements the OpenSSH SSH agent protocol over a Unix domain socket. This allows Padlock to act as a credential agent for SSH authentication and signing operations, securely managing private keys without exposing them to external processes.

## Purpose

Implement a fully functional SSH agent compatible with OpenSSH that:
- Manages SSH private keys from the Padlock vault
- Handles SSH authentication requests (signing)
- Enforces per-key security policies (lifetimes, confirmations)
- Provides agent lifecycle management (startup, shutdown, signal handling)
- Integrates with shell environments via `SSH_AUTH_SOCK` environment variable
- Supports advanced features like agent forwarding and key constraints

## OpenSSH Protocol Specification

### Message Types (with Protocol Codes)

The SSH agent protocol uses fixed-size message types identified by numeric codes:

- **REQUEST_IDENTITIES (11)**: Client requests list of available public keys
- **IDENTITIES_ANSWER (12)**: Agent responds with available public keys and constraints
- **SIGN_REQUEST (13)**: Client requests a signature over data using a specific key
- **SIGN_RESPONSE (14)**: Agent returns the signature
- **ADD_IDENTITY (17)**: Client requests to add a private key to the agent
- **ADD_ID_CONSTRAINED (25)**: Client requests to add a key with constraints (lifetime, confirm)
- **REMOVE_IDENTITY (18)**: Client requests removal of a specific key
- **REMOVE_ALL_IDENTITIES (19)**: Client requests removal of all keys
- **EXTENSION (27)**: Extension message for protocol extensions (e.g., ssh-agent-forwarding)
- **SUCCESS (6)**: Generic success response
- **FAILURE (5)**: Generic failure response

### Message Format

All protocol messages follow this structure:

```
[uint32: total_length][byte: message_type][payload...]
```

- **Length field**: Big-endian uint32 containing the length of message_type + payload (NOT including the 4-byte length field itself)
- **Message type**: Single byte identifying the message
- **Payload**: Variable-length data specific to the message type

Example:
```
Length (4 bytes): 0x00000005
Type (1 byte): 11 (REQUEST_IDENTITIES)
Payload: empty
```

### Message Payload Formats

**IDENTITIES_ANSWER (12):**
- uint32: number of keys
- For each key:
  - string: public key (OpenSSH wire format)
  - string: comment
  - uint32: constraint count (0 or more)
    - byte: constraint type
    - constraint-specific data

**SIGN_REQUEST (13):**
- string: public key blob
- string: data to sign
- uint32: flags (bit 0 = rsa-sha2-256, bit 1 = rsa-sha2-512)

**SIGN_RESPONSE (14):**
- string: signature blob (algorithm identifier + signature bytes)

**ADD_IDENTITY (17):**
- string: key type
- string: public key
- string: private key
- string: comment
- uint32: constraint count
  - constraint data

**ADD_ID_CONSTRAINED (25):**
- Same as ADD_IDENTITY but constraints are expected

**REMOVE_IDENTITY (18):**
- string: public key blob

**EXTENSION (27):**
- string: extension name
- string: extension data

## Agent Lifecycle Management

### Startup

1. **Socket Creation**
   - Create Unix domain socket at `~/.padlock/agent.sock`
   - Set permissions to `0600` (read/write owner only) to prevent unauthorized access
   - Ensure parent directory exists and is readable

2. **PID File**
   - Write process ID to `~/.padlock/agent.pid`
   - Used by shell integration to detect running agent
   - Allows clean restart/shutdown operations

3. **Tokio Event Loop**
   - Initialize tokio runtime (likely multi-threaded for concurrent connections)
   - Bind UnixListener to socket
   - Spawn tasks to handle incoming connections
   - Each connection handled in its own async task

4. **Signal Handlers**
   - Install SIGTERM handler: graceful shutdown, close socket, save vault state
   - Install SIGINT handler (Ctrl+C): same as SIGTERM
   - Use tokio::signal for async signal handling

5. **Initialization Output**
   - Print socket path and PID to stdout/stderr
   - Shell integration can capture and use these values
   - May output shell export commands (e.g., `export SSH_AUTH_SOCK=...`)

### Shutdown

1. Unregister signal handlers
2. Flush any pending operations
3. Sync vault to disk if modified
4. Close socket gracefully
5. Remove PID file
6. Exit with code 0

### Connection Handling

For each incoming connection:
1. Accept connection
2. Spawn async task to handle messages
3. Read length-prefixed messages in a loop
4. Dispatch to handler based on message type
5. Write responses back to client
6. Close connection on client disconnect or protocol error

## Key Management Policies

### Per-Key Lifetime Timeout

Keys can be added with optional lifetime constraints:

- **Lifetime specification**: uint32 seconds (0 = no lifetime)
- **Enforcement**: Track when key was added; refuse to use after lifetime expires
- **Removal**: Automatically remove key when lifetime expires (lazy cleanup on next use)
- **User notification**: Log expired key usage attempts

### Confirm-Before-Use

Keys can require explicit user confirmation before use:

- **Constraint flag**: SSH_AGENT_CONSTRAIN_CONFIRM (value TBD)
- **Confirmation flow**: When key is used, prompt user before returning signature
- **Timeout**: Confirmation prompt should timeout after ~30 seconds
- **Logging**: Log all confirmation requests and responses

### Auto-Lock

The agent itself can enter a locked state, requiring re-authentication:

- **Default timeout**: 15 minutes of inactivity
- **Configuration**: Customizable via config file
- **Lock behavior**: When locked, all key operations are refused with FAILURE
- **Unlock method**: User enters master password (integration with vault module)
- **Activity tracking**: Reset inactivity timer on any successful operation

### Agent Forwarding Extensions

Support SSH agent forwarding with security constraints:

- **Extension message type**: 27 (EXTENSION)
- **Extension names**: "session-bind", "query-extensions"
- **Forwarding constraints**: Track which remote hosts can use the agent
- **Future**: Restrict key usage to specific remote hosts

## Confirmation Flow

When a key is marked as requiring confirmation before use:

### Terminal Prompt (Primary)

```
User prompt (via terminal): "Allow sign with key [KEY_ID]? (y/n)"
```

Implementation:
- Spawn process to display prompt
- Open `/dev/tty` for interactive user input
- Wait for user response (Y or N)
- Timeout after 30 seconds → deny
- Log response

### SSH_ASKPASS Fallback

If terminal is not available (e.g., running via SSH without TTY):

```
Environment variable: SSH_ASKPASS=/path/to/askpass/program
Message: "Allow sign with key [KEY_ID] for [process_name]?"
```

Implementation:
- Check if SSH_ASKPASS is set
- Spawn subprocess with DISPLAY set appropriately
- Pass prompt message via stdin or command argument
- Timeout after 30 seconds
- Log response

### Future: Platform Authentication

Planned for future versions:
- **macOS**: Touch ID confirmation
- **Linux**: systemd user service integration with polkit
- **Windows**: Windows Hello (if Windows support added)

## Shell Integration

Users enable the agent by setting the `SSH_AUTH_SOCK` environment variable:

```bash
export SSH_AUTH_SOCK=~/.padlock/agent.sock
```

Typical shell integration methods:

1. **Auto-start script** (in `.bashrc` / `.zshrc`)
   ```bash
   if [ ! -S "$HOME/.padlock/agent.sock" ]; then
     padlock agent start
   fi
   export SSH_AUTH_SOCK="$HOME/.padlock/agent.sock"
   ```

2. **Padlock command**
   ```bash
   eval "$(padlock agent env)"
   ```
   Returns: `export SSH_AUTH_SOCK=/path/to/socket`

3. **Systemd user service** (advanced users)
   ```ini
   [Service]
   ExecStart=/usr/bin/padlock agent daemon
   StandardOutput=journal
   StandardError=journal
   ```

## Supported SSH Key Types

The agent supports the following SSH key types:

### Ed25519
- **Curve**: Twisted Edwards Curve 1937
- **Key size**: 32 bytes (256 bits)
- **Signature size**: 64 bytes
- **Status**: Preferred, widely supported
- **Crate**: `ed25519-dalek`

### ECDSA
- **P-256 (prime256v1)**
  - **Key size**: 32 bytes
  - **Signature size**: 64 bytes (2x 32 bytes r,s)
  - **Status**: Well-supported

- **P-384 (secp384r1)**
  - **Key size**: 48 bytes
  - **Signature size**: 96 bytes (2x 48 bytes r,s)
  - **Status**: Well-supported, preferred for high-security scenarios

- **Crate**: `p256`, `p384` (from RustCrypto)

### RSA
- **2048-bit**
  - **Key size**: 2048 bits
  - **Status**: Supported, older systems

- **4096-bit**
  - **Key size**: 4096 bits
  - **Status**: Supported, recommended for RSA

- **Signature algorithm**: PKCS#1 v1.5 with SHA-256 (or SHA-512 per SSH_AGENT_RSA_SHA2 flags)
- **Crate**: `rsa`, `sha2`

## Module Structure

The SSH agent implementation is organized into the following module files:

### `ssh_agent/mod.rs`
- Module root and public API
- Exports main types and functions
- Re-exports from submodules
- Optional: `ssh_agent_tests.rs` for integration tests

### `ssh_agent/protocol.rs`
- Message type constants (REQUEST_IDENTITIES, etc.)
- Message parsing and serialization
- Data types for protocol messages
- Validation logic for message structure

### `ssh_agent/handler.rs`
- Main request dispatcher
- Per-message handler implementations
- Policy enforcement logic
- Response generation

### `ssh_agent/daemon.rs`
- Agent lifecycle management
- Socket creation and cleanup
- Signal handling
- Connection accept loop
- PID file management

### `ssh_agent/keys.rs`
- Key type conversions
- OpenSSH wire format serialization/deserialization
- Public key extraction from private keys
- Key constraint application logic

## External Crates

### Core Dependencies

- **tokio** (>=1.40)
  - `tokio::net::UnixListener` - Accept connections on Unix socket
  - `tokio::net::UnixStream` - Handle individual client connections
  - `tokio::signal` - Handle SIGTERM, SIGINT asynchronously
  - `tokio::fs` - Async file operations

- **ssh-key** (>=0.6)
  - Parse and represent SSH key formats
  - Support for Ed25519, ECDSA, RSA types
  - OpenSSH wire format handling

- **ed25519-dalek** (>=2.1)
  - Ed25519 key operations
  - Signing and verification

- **p256** (>=0.13)
  - ECDSA P-256 support
  - Signature generation

- **p384** (>=0.13)
  - ECDSA P-384 support
  - Signature generation

- **rsa** (>=0.9)
  - RSA signing operations
  - PKCS#1 v1.5 padding

- **sha2** (>=0.10)
  - SHA-256 and SHA-512 for RSA signatures
  - Hashing data before signing

- **bytes** (>=1.5)
  - Efficient buffer management
  - BytesMut for mutable buffers
  - Zero-copy operations

- **uuid** (>=1.6, optional)
  - Generate unique key identifiers
  - Useful for logging and debugging

## Security Considerations

### Private Key Handling

1. **Decryption Window**: Private keys are decrypted from vault storage **only when needed for signing**
2. **Immediate Zeroing**: After signing operation completes, private key bytes are **immediately overwritten with zeros**
3. **Memory Protection**: Use `zeroize` crate for sensitive data
4. **No Key Caching**: Keys are NOT cached in memory; each operation fetches from encrypted vault
5. **Vault Integration**: Keys remain encrypted at rest in the vault module

### Socket Security

1. **Permissions**: Socket file created with `0600` (owner read/write only)
2. **Directory Permissions**: `~/.padlock` directory should be `0700` (owner only)
3. **Access Control**: Only owner of the process can connect to the socket
4. **No World-Readable**: Never create socket with group or world-readable permissions

### Connection Security

1. **No Authentication**: Socket doesn't require additional auth (assumes file-based access control)
2. **Process Isolation**: Each connection is handled in separate async task
3. **Timeout**: Long-running operations should timeout to prevent resource exhaustion
4. **Error Messages**: Never expose sensitive information in error responses

### Confirmation Security

1. **User Verification**: All user confirmations must be in-process (not over network)
2. **No Auto-Accept**: Never default to approval if confirmation fails
3. **Logging**: All confirmation attempts logged for audit trail

## Testing Strategy

### Protocol Conformance Testing

- **Test**: Connect with `ssh-add -l` (REQUEST_IDENTITIES)
  - Verify correct response format
  - Verify key list is returned
  - Verify comment field is populated

- **Test**: Sign with `ssh-keygen -Y sign -n user@hostname -f [key]`
  - Verify signature is returned
  - Verify signature is valid with `ssh-keygen -Y verify`
  - Test with Ed25519, ECDSA, RSA keys

### Concurrent Connection Testing

- **Test**: Multiple clients connecting simultaneously
  - Verify no data corruption
  - Verify each client receives correct responses
  - Verify locking/synchronization works

- **Test**: High-frequency requests
  - Multiple sign requests in rapid succession
  - Verify no dropped messages

### Agent Restart Testing

- **Test**: Stop and start agent
  - Verify socket cleanup
  - Verify PID file removal/creation
  - Verify no lingering processes

- **Test**: Ungraceful termination (SIGKILL)
  - Verify socket is usable again (may need cleanup)
  - Verify state is consistent with vault

### Key Constraint Testing

- **Test**: Lifetime expiration
  - Add key with lifetime
  - Wait for expiration
  - Verify key is refused/removed

- **Test**: Confirm-before-use
  - Add key with confirm constraint
  - Verify prompt appears
  - Test approval and denial flows

- **Test**: Auto-lock
  - Verify lock after timeout
  - Verify unlock with master password
  - Verify inactivity timer reset

### Error Handling Testing

- **Test**: Malformed messages
  - Invalid length field
  - Invalid message type
  - Truncated payload

- **Test**: Invalid operations
  - Sign with unknown key
  - Remove non-existent key
  - Invalid constraint data

## Dependencies (Internal Modules)

This module depends on:

1. **crypto module** - Key derivation, encryption, decryption
2. **vault module** - Access to stored private keys, master password verification
3. **entries module** - Access to credential entries, metadata, tags
4. **logging module** - Audit logging of operations
5. **config module** - Agent settings (timeouts, policies)

## Configuration

Agent behavior can be configured via `~/.padlock/config.toml`:

```toml
[agent]
socket_path = "~/.padlock/agent.sock"
auto_lock_timeout_secs = 900  # 15 minutes
confirmation_timeout_secs = 30
log_all_operations = true
allowed_hosts = []  # Empty = all (for forwarding)
```

## Shell Environment Variables

The agent respects and uses:

- `SSH_AUTH_SOCK`: Path to socket (set by user)
- `SSH_ASKPASS`: Program to use for confirmations
- `DISPLAY`: For SSH_ASKPASS (X11 systems)
- `HOME`: To locate `~/.padlock/` directory
- `PADLOCK_AGENT_SOCK`: Alternative to SSH_AUTH_SOCK (Padlock-specific)

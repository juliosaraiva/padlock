//! CLI command definitions and implementations.
//!
//! Each subcommand is implemented in its own module. The top-level
//! `Cli` struct and `Commands` enum define the command tree.

pub mod agent;
pub mod audit;
pub mod completions;
pub mod config;
pub mod exec;
pub mod generate;
pub mod get;
pub mod git;
pub mod init;
pub mod lock;
pub mod ls;
pub mod rm;
pub mod search;
pub mod set;
pub mod status;
pub mod totp;
pub mod unlock;

use std::io::{Read as IoRead, Write as IoWrite};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use padlock_core::crypto::secret_buf::SecretBuf;
use padlock_core::session::protocol::{
    self, build_extension_message, CreateSessionRequest, CreateSessionResponse,
    ResumeSessionRequest, ResumeSessionResponse, SSH_AGENT_EXTENSION_RESPONSE,
    PROTOCOL_VERSION,
};
use padlock_core::session::transit::{
    transit_decrypt, TransitKeyPair, X25519_PUBKEY_SIZE,
};
use padlock_core::session::types::{SessionAlgorithm, SessionDuration, SESSION_TOKEN_SIZE};
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;

/// Padlock -- encrypted credential manager for developers.
#[derive(Parser)]
#[command(name = "padlock")]
#[command(version, about = "Encrypted credential manager for developers")]
pub struct Cli {
    /// Path to the vault file.
    #[arg(long, env = "PADLOCK_VAULT", default_value = "~/.padlock/vault.padlock")]
    pub vault_path: String,

    /// Output in JSON format.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress non-essential output.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands.
#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault.
    Init(init::InitCmd),
    /// Unlock the vault.
    Unlock(unlock::UnlockCmd),
    /// Lock the vault.
    Lock(lock::LockCmd),
    /// Retrieve an entry by name.
    Get(get::GetCmd),
    /// Create or update an entry.
    Set(set::SetCmd),
    /// Delete an entry.
    Rm(rm::RmCmd),
    /// List all entries.
    Ls(ls::LsCmd),
    /// Search entries by name or tag.
    Search(search::SearchCmd),
    /// Generate a random password.
    Generate(generate::GenerateCmd),
    /// Show vault status.
    Status(status::StatusCmd),
    /// SSH agent management.
    Agent(agent::AgentCmd),
    /// Git signing operations.
    Git(git::GitCmd),
    /// Generate shell completions.
    Completions(completions::CompletionsCmd),
    /// Generate TOTP codes.
    Totp(totp::TotpCmd),
    /// Run a command with secrets as environment variables.
    Exec(exec::ExecCmd),
    /// View the vault audit log.
    Audit(audit::AuditCmd),
    /// Manage configuration.
    Config(config::ConfigCmd),
}

/// Resolve the vault path, expanding ~ to the home directory.
pub fn resolve_vault_path(path: &str) -> PathBuf {
    if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Prompt for the vault passphrase.
pub fn prompt_passphrase(prompt: &str) -> anyhow::Result<String> {
    rpassword::prompt_password(prompt).map_err(|e| anyhow::anyhow!("failed to read passphrase: {e}"))
}

/// Get the padlock directory from the vault path.
fn padlock_dir(vault_path: &str) -> PathBuf {
    let path = resolve_vault_path(vault_path);
    path.parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~/.padlock"))
}

/// Get the session token file path.
fn session_token_path(vault_path: &str) -> PathBuf {
    padlock_dir(vault_path).join("session.token")
}

/// Get the agent socket path.
fn agent_socket_path_for_session(vault_path: &str) -> PathBuf {
    padlock_dir(vault_path).join("agent.sock")
}

/// Read a session token from the environment or token file.
///
/// Lookup order: PADLOCK_SESSION env var -> ~/.padlock/session.token file
fn read_session_token(vault_path: &str) -> Option<[u8; SESSION_TOKEN_SIZE]> {
    // Check environment variable first
    if let Ok(hex_str) = std::env::var("PADLOCK_SESSION") {
        if let Some(bytes) = hex_decode_32(&hex_str) {
            return Some(bytes);
        }
    }

    // Check token file
    let path = session_token_path(vault_path);
    if let Ok(hex_str) = std::fs::read_to_string(&path) {
        if let Some(bytes) = hex_decode_32(hex_str.trim()) {
            return Some(bytes);
        }
    }

    None
}

/// Save a session token to the token file with 0o600 permissions.
fn save_session_token(vault_path: &str, token: &[u8]) -> anyhow::Result<()> {
    let path = session_token_path(vault_path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let hex = hex_encode(token);
    std::fs::write(&path, &hex)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Delete the session token file.
pub fn delete_session_token(vault_path: &str) {
    let path = session_token_path(vault_path);
    let _ = std::fs::remove_file(path);
}

/// Try to resume a session from the daemon.
///
/// Uses ephemeral X25519 transit encryption for the response path
/// (daemon -> CLI) to protect the KEK in transit.
///
/// Returns (KEK, MACKEY) if successful, or None if no valid session.
fn try_resume_session(vault_path: &str) -> Option<(SecretBuf, SecretBuf)> {
    let token = read_session_token(vault_path)?;
    let socket = agent_socket_path_for_session(vault_path);

    if !socket.exists() {
        return None;
    }

    // Generate ephemeral keypair for transit encryption (response path)
    let keypair = TransitKeyPair::generate();
    let our_pubkey = keypair.public_key_bytes();

    let req = ResumeSessionRequest {
        token: token.to_vec(),
        ephemeral_pubkey: our_pubkey.to_vec(),
    };
    let session_payload = protocol::build_resume_request(&req).ok()?;
    let message = build_extension_message(&session_payload);

    let mut stream = std::os::unix::net::UnixStream::connect(&socket).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    stream.write_all(&message).ok()?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 256 * 1024 {
        return None;
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).ok()?;

    if resp_buf.is_empty() || resp_buf[0] != SSH_AGENT_EXTENSION_RESPONSE {
        return None;
    }

    let ext_payload = &resp_buf[1..];
    if ext_payload.is_empty() || ext_payload[0] != PROTOCOL_VERSION {
        return None;
    }

    let resp_body = &ext_payload[1..];
    let resume_resp: ResumeSessionResponse = rmp_serde::from_slice(resp_body).ok()?;

    // Derive transit key from responder's public key via X25519 DH
    let responder_pk: [u8; X25519_PUBKEY_SIZE] = resume_resp.responder_pubkey.try_into().ok()?;
    let transit_key = keypair.derive_transit_key(&responder_pk).ok()?;

    // Decrypt KEK and MACKEY using transit key
    let kek_nonce: [u8; 24] = resume_resp.kek_nonce.try_into().ok()?;
    let kek_bytes = transit_decrypt(&transit_key, &kek_nonce, &resume_resp.encrypted_kek).ok()?;

    let mackey_nonce: [u8; 24] = resume_resp.mackey_nonce.try_into().ok()?;
    let mackey_bytes =
        transit_decrypt(&transit_key, &mackey_nonce, &resume_resp.encrypted_mackey).ok()?;

    Some((
        SecretBuf::from_bytes(&kek_bytes),
        SecretBuf::from_bytes(&mackey_bytes),
    ))
}

/// Send CreateSession to the daemon to cache KEK and MACKEY.
///
/// For CreateSession, KEK and MACKEY bytes are sent directly over the
/// Unix socket. The socket is secured by filesystem permissions (0o600),
/// restricting access to the same user. The daemon immediately wraps
/// the keys with a random SEK upon receipt. Transit encryption (ephemeral
/// X25519) is used only for the ResumeSession response path (daemon->CLI).
///
/// Returns the session token on success.
fn create_daemon_session(
    vault_path: &str,
    kek: &SecretBuf,
    mackey: &SecretBuf,
    vault_id: &[u8; 16],
    duration: SessionDuration,
) -> Option<Vec<u8>> {
    let socket = agent_socket_path_for_session(vault_path);
    if !socket.exists() {
        return None;
    }

    let req = CreateSessionRequest {
        algorithm: SessionAlgorithm::XChaCha20Poly1305HkdfSha256.to_byte(),
        encrypted_kek: kek.to_vec(),
        kek_nonce: vec![0u8; 24],
        encrypted_mackey: mackey.to_vec(),
        mackey_nonce: vec![0u8; 24],
        ephemeral_pubkey: vec![0u8; 32],
        duration: duration.as_label().to_string(),
        vault_id: vault_id.to_vec(),
    };

    let session_payload = protocol::build_create_request(&req).ok()?;
    let message = build_extension_message(&session_payload);

    let mut stream = std::os::unix::net::UnixStream::connect(&socket).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    stream.write_all(&message).ok()?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 256 * 1024 {
        return None;
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).ok()?;

    if resp_buf.is_empty() || resp_buf[0] != SSH_AGENT_EXTENSION_RESPONSE {
        return None;
    }

    let ext_payload = &resp_buf[1..];
    if ext_payload.is_empty() || ext_payload[0] != PROTOCOL_VERSION {
        return None;
    }

    let resp_body = &ext_payload[1..];
    let create_resp: CreateSessionResponse = rmp_serde::from_slice(resp_body).ok()?;

    Some(create_resp.token)
}

/// Send DestroySession or DestroyAll to the daemon.
pub fn destroy_daemon_session(vault_path: &str, token: Option<&[u8; SESSION_TOKEN_SIZE]>) {
    let socket = agent_socket_path_for_session(vault_path);
    if !socket.exists() {
        return;
    }

    let session_payload = if let Some(token) = token {
        let req = padlock_core::session::protocol::DestroySessionRequest {
            token: token.to_vec(),
        };
        protocol::build_destroy_request(&req).ok()
    } else {
        Some(protocol::build_destroy_all_request())
    };

    let Some(payload) = session_payload else {
        return;
    };

    let message = build_extension_message(&payload);

    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&socket) {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.write_all(&message);
        // Read and discard response
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_ok() {
            let resp_len = u32::from_be_bytes(len_buf) as usize;
            if resp_len > 0 && resp_len <= 256 * 1024 {
                let mut resp_buf = vec![0u8; resp_len];
                let _ = stream.read_exact(&mut resp_buf);
            }
        }
    }
}

/// Open a vault, trying session cache first, then falling back to passphrase.
///
/// If a session is successfully resumed, returns the vault without prompting.
/// If no valid session exists, prompts for passphrase and optionally creates
/// a session for future use.
pub fn open_vault_with_session(vault_path: &str) -> anyhow::Result<Vault> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path);

    // Try to resume from session cache
    if let Some((kek, mackey)) = try_resume_session(vault_path) {
        match Vault::open_with_keys(kek, mackey, &storage) {
            Ok(vault) => return Ok(vault),
            Err(_) => {
                // Session keys are stale, fall through to passphrase
            }
        }
    }

    // Fall back to passphrase prompt
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let vault = Vault::open(&passphrase, &storage, &KdfParams::production())?;

    // Try to create a session for next time
    if let (Ok(kek), Ok(mackey)) = (vault.kek(), vault.mackey()) {
        let vault_id = vault.header().vault_uuid;
        if let Some(token) = create_daemon_session(
            vault_path,
            kek,
            mackey,
            &vault_id,
            SessionDuration::OneHour,
        ) {
            let _ = save_session_token(vault_path, &token);
        }
    }

    Ok(vault)
}

/// Open a vault mutably, trying session cache first.
pub fn open_vault_mut_with_session(vault_path: &str) -> anyhow::Result<(Vault, FilesystemBackend)> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path);

    // Try to resume from session cache
    if let Some((kek, mackey)) = try_resume_session(vault_path) {
        match Vault::open_with_keys(kek, mackey, &storage) {
            Ok(vault) => return Ok((vault, storage)),
            Err(_) => {
                // Fall through
            }
        }
    }

    let passphrase = prompt_passphrase("Passphrase: ")?;
    let vault = Vault::open(&passphrase, &storage, &KdfParams::production())?;

    // Try to create a session
    if let (Ok(kek), Ok(mackey)) = (vault.kek(), vault.mackey()) {
        let vault_id = vault.header().vault_uuid;
        if let Some(token) = create_daemon_session(
            vault_path,
            kek,
            mackey,
            &vault_id,
            SessionDuration::OneHour,
        ) {
            let _ = save_session_token(vault_path, &token);
        }
    }

    Ok((vault, storage))
}

/// Hex-encode bytes to lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a 32-byte hex string to a fixed-size array.
fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            return None;
        }
        let s = std::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(bytes)
}

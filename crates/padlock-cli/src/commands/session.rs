//! `padlock session` command group for managing active sessions.
//!
//! Provides commands to list, inspect, and destroy daemon sessions
//! without requiring vault unlock.

use std::io::{Read, Write};

use clap::{Args, Subcommand};
use padlock_core::session::protocol::{
    build_extension_message, SessionMessageType, StatusSessionRequest, PROTOCOL_VERSION,
    SSH_AGENT_EXTENSION_RESPONSE,
};
use padlock_core::session::types::SessionInfo;

use super::{agent_socket_path_for_session, delete_session_token, read_session_token};

/// Manage active sessions.
#[derive(Args)]
pub struct SessionCmd {
    /// Session subcommand.
    #[command(subcommand)]
    pub command: SessionSubcommand,
}

/// Available session subcommands.
#[derive(Subcommand)]
pub enum SessionSubcommand {
    /// Show the current session status.
    Status(SessionStatusCmd),
    /// Destroy the current session or all sessions.
    Destroy(SessionDestroyCmd),
}

/// Show session status.
#[derive(Args)]
pub struct SessionStatusCmd {}

/// Destroy sessions.
#[derive(Args)]
pub struct SessionDestroyCmd {
    /// Destroy all sessions (not just the current one).
    #[arg(long)]
    pub all: bool,
}

/// Execute the session command group.
///
/// # Errors
///
/// Returns an error if the session operation fails.
pub fn run(cmd: SessionCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    match cmd.command {
        SessionSubcommand::Status(_) => run_status(vault_path, json),
        SessionSubcommand::Destroy(destroy) => run_destroy(destroy, vault_path, json),
    }
}

/// Query the daemon for session status using the stored token.
fn run_status(vault_path: &str, json: bool) -> anyhow::Result<()> {
    let Some(token) = read_session_token(vault_path) else {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "active": false,
                    "reason": "no session token found",
                }))?
            );
        } else {
            println!("No active session.");
        }
        return Ok(());
    };

    let socket = agent_socket_path_for_session(vault_path);
    if !socket.exists() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "active": false,
                    "reason": "agent not running",
                }))?
            );
        } else {
            println!("No active session (agent not running).");
        }
        return Ok(());
    }

    // Build status request
    let req = StatusSessionRequest {
        token: token.to_vec(),
    };
    let body = rmp_serde::to_vec(&req)?;
    let mut payload = vec![PROTOCOL_VERSION, SessionMessageType::Status as u8];
    payload.extend_from_slice(&body);
    let message = build_extension_message(&payload);

    let mut stream = std::os::unix::net::UnixStream::connect(&socket)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.write_all(&message)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 256 * 1024 {
        anyhow::bail!("invalid response from agent");
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    if resp_buf.is_empty() || resp_buf[0] != SSH_AGENT_EXTENSION_RESPONSE {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "active": false,
                    "reason": "session not found in daemon",
                }))?
            );
        } else {
            println!("No active session (session not found in daemon).");
        }
        return Ok(());
    }

    let ext_payload = &resp_buf[1..];
    if ext_payload.is_empty() || ext_payload[0] != PROTOCOL_VERSION {
        anyhow::bail!("invalid protocol version in response");
    }

    let info_bytes = &ext_payload[1..];
    let info: SessionInfo = rmp_serde::from_slice(info_bytes)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "active": info.valid,
                "session_id": info.id,
                "vault_id": info.vault_id,
                "use_count": info.use_count,
                "idle_timeout_secs": info.idle_timeout_secs,
                "created_at": info.created_at,
            }))?
        );
    } else if info.valid {
        println!("Active session:");
        println!("  Session ID:    {}", info.id);
        println!("  Vault ID:      {}", info.vault_id);
        println!("  Use count:     {}", info.use_count);
        println!("  Idle timeout:  {}s", info.idle_timeout_secs);
        println!("  Created:       {}", info.created_at);
    } else {
        println!("Session exists but is expired.");
        println!("  Session ID: {}", info.id);
    }

    Ok(())
}

/// Destroy the current session or all sessions.
#[allow(clippy::needless_pass_by_value)]
fn run_destroy(cmd: SessionDestroyCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    if cmd.all {
        // Destroy all sessions via the daemon
        super::destroy_daemon_session(vault_path, None);
        delete_session_token(vault_path);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "destroyed": "all",
                }))?
            );
        } else {
            println!("All sessions destroyed.");
        }
    } else {
        // Destroy just the current session
        let token = read_session_token(vault_path);
        if let Some(token) = token {
            super::destroy_daemon_session(vault_path, Some(&token));
        }
        delete_session_token(vault_path);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "destroyed": "current",
                }))?
            );
        } else {
            println!("Current session destroyed.");
        }
    }

    Ok(())
}

//! `padlock lock` command implementation.

use clap::Args;

use super::{delete_session_token, destroy_daemon_session};

/// Lock the vault, clearing any cached state.
#[derive(Args)]
pub struct LockCmd {}

/// Execute the lock command.
///
/// Destroys all active sessions in the daemon, deletes the session
/// token file, and signals the user to unset the `PADLOCK_SESSION`
/// environment variable if set.
///
/// # Errors
///
/// Returns an error if locking fails.
pub fn run(_cmd: LockCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let path = super::resolve_vault_path(vault_path);

    // Destroy all daemon sessions
    destroy_daemon_session(vault_path, None);

    // Delete the session token file
    delete_session_token(vault_path);

    let agent_sock = path
        .parent()
        .map(|p| p.join("agent.sock"))
        .unwrap_or_default();

    let agent_was_running = agent_sock.exists();

    if json {
        let output = serde_json::json!({
            "status": "locked",
            "sessions_cleared": true,
            "agent_notified": agent_was_running,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Vault locked.");
        println!("Session cache cleared.");
        if std::env::var("PADLOCK_SESSION").is_ok() {
            println!("Run: unset PADLOCK_SESSION");
        }
        if agent_was_running {
            println!("Note: SSH agent is running. Use `padlock agent stop` to stop it.");
        }
    }

    Ok(())
}

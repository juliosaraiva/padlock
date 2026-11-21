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
    let socket = super::agent_socket_path_for_session(vault_path);
    let agent_was_running = match std::fs::symlink_metadata(socket) {
        Ok(_) => {
            destroy_daemon_session(vault_path, None)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    delete_session_token(vault_path);

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

//! `padlock unlock` command implementation.

use clap::Args;
use padlock_core::traits::storage::StorageBackend;
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;

use super::{prompt_passphrase, resolve_vault_path};

/// Unlock the vault by verifying the passphrase.
#[derive(Args)]
pub struct UnlockCmd {}

/// Execute the unlock command.
///
/// # Errors
///
/// Returns an error if vault unlock fails.
pub fn run(_cmd: UnlockCmd, vault_path: &str, json: bool, no_session: bool) -> anyhow::Result<()> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path.clone());

    if !storage.vault_exists()? {
        anyhow::bail!(
            "vault not found at {}. Run `padlock init` first.",
            path.display()
        );
    }

    let passphrase = prompt_passphrase("Passphrase: ")?;
    let vault = Vault::open(&passphrase, &storage, &KdfParams::production())?;

    // Verify the vault opened successfully (passphrase was correct)
    let entry_count = vault.index().active_count();

    // Create a session for subsequent commands (respecting config + --no-session)
    let mut session_created = false;
    if !no_session {
        let cfg = super::config::load_config(vault_path).unwrap_or_default();
        if cfg.session.auto_session {
            super::ensure_daemon_running(vault_path);
            if let (Ok(kek), Ok(mackey)) = (vault.kek(), vault.mackey()) {
                let vault_id = vault.header().vault_uuid;
                let duration = cfg.session.parsed_duration();
                let idle_secs = cfg.session.parsed_idle_timeout().as_secs();
                if let Some(token) = super::create_daemon_session(
                    vault_path, kek, mackey, &vault_id, duration, idle_secs,
                ) {
                    let _ = super::save_session_token(vault_path, &token);
                    session_created = true;
                }
            }
        }
    }

    if json {
        let output = serde_json::json!({
            "status": "unlocked",
            "entry_count": entry_count,
            "session_created": session_created,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Vault unlocked successfully.");
        println!("Entries: {entry_count}");
        if session_created {
            println!("Session created. Subsequent commands will not require passphrase.");
        }
    }

    Ok(())
}

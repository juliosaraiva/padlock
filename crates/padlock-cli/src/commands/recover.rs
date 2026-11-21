//! `padlock recover` command implementation.
//!
//! Recovers a vault using a recovery key when the passphrase is forgotten.
//! After recovery, forces the user to set a new passphrase.

use clap::Args;
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;

use super::{prompt_passphrase, resolve_vault_path};

/// Recover a vault using a recovery key.
#[derive(Args)]
pub struct RecoverCmd {
    /// Path to the vault file.
    #[arg(
        long,
        env = "PADLOCK_VAULT",
        default_value = "~/.padlock/vault.padlock"
    )]
    vault_path: String,
}

/// Execute the recover command.
///
/// # Errors
///
/// Returns an error if vault recovery fails.
#[allow(clippy::needless_pass_by_value)]
pub fn run(cmd: RecoverCmd) -> anyhow::Result<()> {
    let path = resolve_vault_path(&cmd.vault_path);
    if !path.exists() {
        anyhow::bail!("vault not found at {}", path.display());
    }

    let storage = FilesystemBackend::new(path);

    let recovery_key = prompt_passphrase("Recovery key: ")?;
    let recovery_key = recovery_key.trim();

    let mut vault = Vault::recover(recovery_key, &storage)
        .map_err(|e| anyhow::anyhow!("recovery failed: {e}"))?;

    println!("Recovery successful. You must now set a new passphrase.");

    let new_passphrase = prompt_passphrase("Enter new passphrase: ")?;
    let confirm = prompt_passphrase("Confirm passphrase: ")?;

    if new_passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    if new_passphrase.len() < 8 {
        anyhow::bail!("passphrase must be at least 8 characters");
    }

    vault.change_passphrase(&new_passphrase, &storage, &KdfParams::production())?;

    println!("Passphrase updated. Vault is now accessible with the new passphrase.");
    println!("Note: Recovery has been invalidated by the passphrase change.");
    println!("Run `padlock recovery enable` to generate a new recovery key.");

    Ok(())
}

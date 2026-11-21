//! `padlock recover` command implementation.
//!
//! Recovers a vault using a recovery key when the passphrase is forgotten.
//! After recovery, forces the user to set a new passphrase.

use anyhow::Context;
use clap::Args;
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;
use zeroize::Zeroizing;

use super::{prompt_passphrase, resolve_vault_path};

/// Recover a vault using a recovery key.
#[derive(Args)]
pub struct RecoverCmd {
    /// Path to the vault file.
    #[arg(long)]
    vault_path: Option<String>,
}

/// Execute the recover command.
///
/// # Errors
///
/// Returns an error if vault recovery fails.
pub fn run(cmd: &RecoverCmd, vault_path: &str) -> anyhow::Result<()> {
    let path = resolve_vault_path(cmd.vault_path.as_deref().unwrap_or(vault_path));
    if !path.exists() {
        anyhow::bail!("vault not found at {}", path.display());
    }

    let storage = FilesystemBackend::new(path);

    let mut vault = {
        let recovery_key = Zeroizing::new(prompt_passphrase("Recovery key: ")?);
        Vault::recover(recovery_key.trim(), &storage).context("recovery failed")?
    };

    println!("Recovery successful. You must now set a new passphrase.");

    let new_passphrase = Zeroizing::new(prompt_passphrase("Enter new passphrase: ")?);
    let confirm = Zeroizing::new(prompt_passphrase("Confirm passphrase: ")?);

    if *new_passphrase != *confirm {
        anyhow::bail!("passphrases do not match");
    }

    drop(confirm);

    if new_passphrase.len() < 8 {
        anyhow::bail!("passphrase must be at least 8 characters");
    }

    vault.change_passphrase(&new_passphrase, &storage, &KdfParams::production())?;

    println!("Passphrase updated. Vault is now accessible with the new passphrase.");
    println!("Note: Recovery has been invalidated by the passphrase change.");
    println!("Run `padlock recovery enable` to generate a new recovery key.");

    Ok(())
}

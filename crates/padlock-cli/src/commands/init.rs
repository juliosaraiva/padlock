//! `padlock init` command implementation.

use clap::Args;
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;

use super::{prompt_passphrase, resolve_vault_path};

/// Initialize a new vault.
#[derive(Args)]
pub struct InitCmd {
    /// Path to the vault file.
    #[arg(long, env = "PADLOCK_VAULT", default_value = "~/.padlock/vault.padlock")]
    vault_path: String,
}

/// Execute the init command.
pub fn run(cmd: InitCmd) -> anyhow::Result<()> {
    let path = resolve_vault_path(&cmd.vault_path);

    if path.exists() {
        anyhow::bail!("vault already exists at {}", path.display());
    }

    let passphrase = prompt_passphrase("Enter new vault passphrase: ")?;
    let confirm = prompt_passphrase("Confirm passphrase: ")?;

    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    if passphrase.len() < 8 {
        anyhow::bail!("passphrase must be at least 8 characters");
    }

    // Create parent directory
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let storage = FilesystemBackend::new(path.clone());
    Vault::init(&passphrase, &storage, &KdfParams::production())?;

    println!("Vault initialized at {}", path.display());
    Ok(())
}

//! `padlock status` command implementation.

use clap::Args;
use padlock_core::vault::storage::FilesystemBackend;
use padlock_core::traits::storage::StorageBackend;

use super::resolve_vault_path;
use crate::output::OutputFormatter;

/// Show vault status.
#[derive(Args)]
pub struct StatusCmd {}

/// Execute the status command.
pub fn run(vault_path: &str, fmt: &OutputFormatter) -> anyhow::Result<()> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path.clone());
    let exists = storage.vault_exists()?;

    if fmt.is_json() {
        let output = serde_json::json!({
            "vault_path": path.display().to_string(),
            "exists": exists,
        });
        fmt.json(&output);
    } else if fmt.is_quiet() {
        if exists {
            println!("locked");
        } else {
            println!("uninitialized");
        }
    } else {
        fmt.key_value("Vault path", &path.display().to_string());
        if exists {
            fmt.key_value("Status", "exists (locked)");
        } else {
            fmt.key_value("Status", "not initialized");
            println!("Run `padlock init` to create a new vault.");
        }
    }

    Ok(())
}

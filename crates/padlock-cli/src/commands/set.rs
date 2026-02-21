//! `padlock set` command implementation.

use clap::Args;
use padlock_core::entries::crud::create_entry;
use padlock_core::entries::types::EntryData;

use super::{open_vault_mut_with_session, prompt_passphrase};

/// Create or update an entry.
#[derive(Args)]
pub struct SetCmd {
    /// Entry name.
    name: String,

    /// Username for credential entries.
    #[arg(short, long)]
    username: Option<String>,

    /// Password (will prompt if not provided).
    #[arg(short, long)]
    password: Option<String>,

    /// URL for credential entries.
    #[arg(long)]
    url: Option<String>,

    /// Tags (comma-separated).
    #[arg(short, long)]
    tags: Option<String>,

    /// Notes.
    #[arg(long)]
    notes: Option<String>,
}

/// Execute the set command.
///
/// # Errors
///
/// Returns an error if vault access or entry creation fails.
pub fn run(cmd: SetCmd, vault_path: &str, no_session: bool) -> anyhow::Result<()> {
    let (mut vault, storage) = open_vault_mut_with_session(vault_path, no_session)?;

    let password = match cmd.password {
        Some(p) => p,
        None => prompt_passphrase("Entry password: ")?,
    };

    let tags: Vec<String> = cmd
        .tags
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let data = EntryData::Credential {
        username: cmd.username.unwrap_or_default(),
        password,
        url: cmd.url,
        notes: cmd.notes,
    };

    let entry = create_entry(&mut vault, cmd.name, data, tags)?;
    vault.write_to_storage(&storage)?;

    println!("Created entry '{}' ({})", entry.name, entry.id);
    Ok(())
}

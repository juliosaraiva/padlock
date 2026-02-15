//! `padlock rm` command implementation.

use clap::Args;
use padlock_core::entries::crud::{delete_entry, search_by_name};

use super::open_vault_mut_with_session;

/// Delete an entry.
#[derive(Args)]
pub struct RmCmd {
    /// Entry name to delete.
    name: String,

    /// Skip confirmation prompt.
    #[arg(short, long)]
    force: bool,
}

/// Execute the rm command.
pub fn run(cmd: RmCmd, vault_path: &str) -> anyhow::Result<()> {
    let (mut vault, storage) = open_vault_mut_with_session(vault_path)?;

    let entries = search_by_name(&vault, &cmd.name)?;
    if entries.is_empty() {
        anyhow::bail!("no entry found matching '{}'", cmd.name);
    }

    let entry = &entries[0];
    if !cmd.force {
        eprint!("Delete entry '{}'? [y/N] ", entry.name);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    delete_entry(&mut vault, &entry.id)?;
    vault.write_to_storage(&storage)?;

    println!("Deleted entry '{}'", entry.name);
    Ok(())
}

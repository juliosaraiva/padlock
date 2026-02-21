//! `padlock ls` command implementation.

use clap::Args;
use colored::Colorize;
use padlock_core::entries::crud::list_entries;

use super::open_vault_with_session;
use crate::output::OutputFormatter;

/// List all entries.
#[derive(Args)]
pub struct LsCmd {}

/// Execute the ls command.
pub fn run(
    _cmd: LsCmd,
    vault_path: &str,
    fmt: &OutputFormatter,
    no_session: bool,
) -> anyhow::Result<()> {
    let vault = open_vault_with_session(vault_path, no_session)?;

    let entries = list_entries(&vault)?;

    if fmt.is_json() {
        let items: Vec<_> = entries
            .iter()
            .map(|(id, name)| serde_json::json!({"id": id.to_string(), "name": name}))
            .collect();
        fmt.json_list(&items);
    } else if fmt.is_quiet() {
        for (_id, name) in &entries {
            println!("{name}");
        }
    } else if entries.is_empty() {
        fmt.success("No entries in vault.");
    } else {
        fmt.table_header(&["ID", "NAME"]);
        for (id, name) in &entries {
            let id_str = id.to_string();
            fmt.table_row(&[&id_str, name]);
        }
        println!(
            "\n{} {} total.",
            entries.len().to_string().bold(),
            if entries.len() == 1 {
                "entry"
            } else {
                "entries"
            }
        );
    }

    Ok(())
}

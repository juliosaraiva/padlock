//! `padlock search` command implementation.

use clap::Args;
use colored::Colorize;
use padlock_core::entries::crud::{search_by_name, search_by_tag};

use super::open_vault_with_session;
use crate::output::OutputFormatter;

/// Search entries by name or tag.
#[derive(Args)]
pub struct SearchCmd {
    /// Search query.
    query: String,

    /// Search by tag instead of name.
    #[arg(short, long)]
    tag: bool,
}

/// Execute the search command.
pub fn run(
    cmd: SearchCmd,
    vault_path: &str,
    fmt: &OutputFormatter,
    no_session: bool,
) -> anyhow::Result<()> {
    let vault = open_vault_with_session(vault_path, no_session)?;

    let entries = if cmd.tag {
        search_by_tag(&vault, &cmd.query)?
    } else {
        search_by_name(&vault, &cmd.query)?
    };

    if fmt.is_json() {
        let items: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id.to_string(),
                    "name": e.name,
                    "type": e.entry_type().to_string(),
                })
            })
            .collect();
        fmt.json_list(&items);
    } else if fmt.is_quiet() {
        for e in &entries {
            println!("{}", e.name);
        }
    } else if entries.is_empty() {
        fmt.success("No entries found.");
    } else {
        fmt.table_header(&["ID", "NAME", "TYPE"]);
        for e in &entries {
            let id_str = e.id.to_string();
            let type_str = e.entry_type().to_string();
            fmt.table_row(&[&id_str, &e.name, &type_str]);
        }
        println!(
            "\n{} {}.",
            entries.len().to_string().bold(),
            if entries.len() == 1 {
                "result"
            } else {
                "results"
            }
        );
    }

    Ok(())
}

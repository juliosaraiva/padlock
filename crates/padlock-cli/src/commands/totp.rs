//! `padlock totp` command implementation.

use clap::{Args, Subcommand};
use padlock_core::entries::crud::search_by_name;
use padlock_core::entries::EntryData;
use padlock_core::generate::generate_totp_code;

use super::open_vault_with_session;

/// TOTP operations.
#[derive(Args)]
pub struct TotpCmd {
    /// TOTP subcommand.
    #[command(subcommand)]
    pub command: TotpSubcommand,
}

/// Available TOTP subcommands.
#[derive(Subcommand)]
pub enum TotpSubcommand {
    /// Generate a TOTP code for an entry.
    Generate(TotpGenerateCmd),
}

/// Generate a TOTP code from a vault entry.
#[derive(Args)]
pub struct TotpGenerateCmd {
    /// Name of the TOTP entry.
    name: String,
}

/// Execute the totp command.
pub fn run(cmd: TotpCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    match cmd.command {
        TotpSubcommand::Generate(gen) => run_generate(gen, vault_path, json),
    }
}

/// Execute the totp generate subcommand.
fn run_generate(cmd: TotpGenerateCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let vault = open_vault_with_session(vault_path)?;

    let entries = search_by_name(&vault, &cmd.name)?;
    if entries.is_empty() {
        anyhow::bail!("no entry found matching '{}'", cmd.name);
    }

    let entry = &entries[0];
    match &entry.data {
        EntryData::TOTP {
            secret,
            algorithm,
            digits,
            period,
            ..
        } => {
            let (code, remaining) = generate_totp_code(secret, algorithm, *digits, *period)?;

            if json {
                let output = serde_json::json!({
                    "code": code,
                    "expires_in": remaining,
                    "period": period,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{code} (expires in {remaining}s)");
            }
        }
        _ => anyhow::bail!("entry '{}' is not a TOTP entry", cmd.name),
    }

    Ok(())
}

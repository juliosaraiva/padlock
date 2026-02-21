//! `padlock get` command implementation.

use clap::Args;
use padlock_core::entries::crud::search_by_name;

use super::open_vault_with_session;
use crate::output::OutputFormatter;

/// Retrieve an entry by name.
#[derive(Args)]
pub struct GetCmd {
    /// Entry name or UUID to retrieve.
    name: String,

    /// Only print the password/secret value.
    #[arg(short, long)]
    password_only: bool,
}

/// Execute the get command.
///
/// # Errors
///
/// Returns an error if vault access or entry lookup fails.
#[allow(clippy::needless_pass_by_value)]
pub fn run(
    cmd: GetCmd,
    vault_path: &str,
    fmt: &OutputFormatter,
    no_session: bool,
) -> anyhow::Result<()> {
    let vault = open_vault_with_session(vault_path, no_session)?;

    // Try UUID parse first, then search by name
    let entries = search_by_name(&vault, &cmd.name)?;

    if entries.is_empty() {
        anyhow::bail!("no entry found matching '{}'", cmd.name);
    }

    let entry = &entries[0];

    if fmt.is_json() {
        let output = serde_json::json!({
            "id": entry.id.to_string(),
            "name": entry.name,
            "type": entry.entry_type().to_string(),
            "version": entry.version,
            "created_at": entry.created_at,
            "modified_at": entry.modified_at,
            "tags": entry.tags,
        });
        fmt.json(&output);
    } else if cmd.password_only || fmt.is_quiet() {
        match &entry.data {
            padlock_core::entries::EntryData::Credential { password, .. }
            | padlock_core::entries::EntryData::Netrc { password, .. } => {
                print!("{password}");
            }
            _ => anyhow::bail!("entry type does not have a password field"),
        }
    } else {
        fmt.key_value("Name", &entry.name);
        fmt.key_value("Type", &entry.entry_type().to_string());
        fmt.key_value("ID", &entry.id.to_string());
        fmt.key_value("Version", &entry.version.to_string());
        if !entry.tags.is_empty() {
            fmt.key_value("Tags", &entry.tags.join(", "));
        }
        match &entry.data {
            padlock_core::entries::EntryData::Credential {
                username,
                password,
                url,
                notes,
            } => {
                fmt.key_value("Username", username);
                fmt.key_value("Password", password);
                if let Some(u) = url {
                    fmt.key_value("URL", u);
                }
                if let Some(n) = notes {
                    fmt.key_value("Notes", n);
                }
            }
            padlock_core::entries::EntryData::SSHKey {
                key_type,
                public_key,
                comment,
                ..
            } => {
                fmt.key_value("Key Type", &format!("{key_type:?}"));
                fmt.key_value("Public Key", public_key);
                if let Some(c) = comment {
                    fmt.key_value("Comment", c);
                }
            }
            padlock_core::entries::EntryData::TOTP {
                account_name,
                issuer,
                digits,
                period,
                ..
            } => {
                fmt.key_value("Account", account_name);
                if let Some(i) = issuer {
                    fmt.key_value("Issuer", i);
                }
                fmt.key_value("Digits", &digits.to_string());
                fmt.key_value("Period", &format!("{period}s"));
            }
            padlock_core::entries::EntryData::Binary {
                content_type,
                filename,
                ..
            } => {
                if let Some(f) = filename {
                    fmt.key_value("Filename", f);
                }
                if let Some(ct) = content_type {
                    fmt.key_value("Type", ct);
                }
            }
            padlock_core::entries::EntryData::Netrc { machine, login, .. } => {
                fmt.key_value("Machine", machine);
                fmt.key_value("Login", login);
            }
        }
    }

    Ok(())
}

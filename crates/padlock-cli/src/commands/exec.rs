//! `padlock exec` command implementation.
//!
//! Spawns a child process with secrets injected as environment variables.

use std::process::Command;

use clap::Args;
use padlock_core::entries::crud::search_by_name;
use padlock_core::entries::EntryData;

use super::open_vault_with_session;

/// Run a command with secrets injected as environment variables.
#[derive(Args)]
pub struct ExecCmd {
    /// Variable assignments in the form VAR=entry_name.
    #[arg(required = true, num_args = 1..)]
    assignments: Vec<String>,

    /// Command to execute (after --).
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

/// Execute the exec command.
pub fn run(cmd: ExecCmd, vault_path: &str) -> anyhow::Result<()> {
    // Parse VAR=entry_name pairs
    let mut mappings = Vec::new();
    for assignment in &cmd.assignments {
        let (var, entry_name) = assignment
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid assignment '{assignment}': expected VAR=entry_name"))?;

        if var.is_empty() {
            anyhow::bail!("empty variable name in assignment '{assignment}'");
        }

        mappings.push((var.to_string(), entry_name.to_string()));
    }

    if cmd.command.is_empty() {
        anyhow::bail!("no command specified after --");
    }

    let vault = open_vault_with_session(vault_path)?;

    // Resolve each entry and extract the secret value
    let mut env_vars = Vec::new();
    for (var, entry_name) in &mappings {
        let entries = search_by_name(&vault, entry_name)?;
        if entries.is_empty() {
            anyhow::bail!("no entry found matching '{entry_name}'");
        }

        let entry = &entries[0];
        let secret = extract_secret(&entry.data, entry_name)?;
        env_vars.push((var.clone(), secret));
    }

    // Spawn child process
    let program = &cmd.command[0];
    let args = &cmd.command[1..];

    let status = Command::new(program)
        .args(args)
        .envs(env_vars)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to execute '{program}': {e}"))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Extract the secret value from an entry as a string.
fn extract_secret(data: &EntryData, name: &str) -> anyhow::Result<String> {
    match data {
        EntryData::Credential { password, .. } => Ok(password.clone()),
        EntryData::TOTP { secret, .. } => Ok(secret.clone()),
        EntryData::SSHKey { private_key, .. } => Ok(private_key.clone()),
        EntryData::Netrc { password, .. } => Ok(password.clone()),
        EntryData::Binary { data, .. } => {
            String::from_utf8(data.clone())
                .map_err(|_| anyhow::anyhow!("entry '{name}' contains non-UTF-8 binary data"))
        }
    }
}

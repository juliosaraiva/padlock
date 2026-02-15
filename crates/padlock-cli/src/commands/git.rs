//! `padlock git` command group for Git SSH signing management.
//!
//! Provides commands to configure Git for SSH signing, manage
//! allowed signers files, and verify commit signatures.

use clap::{Args, Subcommand};
use padlock_core::entries::crud::{list_entries, read_entry};
use padlock_core::entries::EntryData;
use padlock_core::signing::git_config::{self, GitConfigScope};
use padlock_core::signing::{generate_allowed_signers, AllowedSigner};
use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;

use super::{prompt_passphrase, resolve_vault_path};

/// Git signing management commands.
#[derive(Args)]
pub struct GitCmd {
    /// Git subcommand.
    #[command(subcommand)]
    pub command: GitSubcommand,
}

/// Available git subcommands.
#[derive(Subcommand)]
pub enum GitSubcommand {
    /// Configure Git for SSH signing.
    Setup(GitSetupCmd),
    /// Verify a commit signature.
    Verify(GitVerifyCmd),
    /// Manage the allowed-signers file.
    AllowedSigners(GitAllowedSignersCmd),
}

/// Configure Git for SSH signing.
#[derive(Args)]
pub struct GitSetupCmd {
    /// Apply to global Git config.
    #[arg(long)]
    pub global: bool,

    /// SSH key name or ID to use for signing.
    #[arg(long)]
    pub key: Option<String>,
}

/// Verify a commit signature.
#[derive(Args)]
pub struct GitVerifyCmd {
    /// Commit hash to verify (default: HEAD).
    #[arg(default_value = "HEAD")]
    pub commit: String,
}

/// Manage the allowed-signers file.
#[derive(Args)]
pub struct GitAllowedSignersCmd {
    /// Output file path (default: ~/.padlock/allowed_signers).
    #[arg(long)]
    pub output: Option<String>,

    /// Only list current entries, do not write.
    #[arg(long)]
    pub list: bool,
}

/// Execute the git command group.
pub fn run(cmd: GitCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    match cmd.command {
        GitSubcommand::Setup(setup) => run_setup(setup, vault_path, json),
        GitSubcommand::Verify(verify) => run_verify(verify, json),
        GitSubcommand::AllowedSigners(as_cmd) => run_allowed_signers(as_cmd, vault_path, json),
    }
}

/// Run `padlock git setup`.
fn run_setup(cmd: GitSetupCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path.clone());
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let vault = Vault::open(&passphrase, &storage, &KdfParams::production())?;

    // Find SSH keys in the vault
    let entries = list_entries(&vault)?;
    let mut ssh_keys = Vec::new();

    for (entry_id, name) in &entries {
        if let Ok(entry) = read_entry(&vault, entry_id) {
            if let EntryData::SSHKey { public_key, key_type, comment, .. } = &entry.data {
                ssh_keys.push((name.clone(), public_key.clone(), format!("{key_type:?}"), comment.clone()));
            }
        }
    }

    if ssh_keys.is_empty() {
        anyhow::bail!("no SSH keys found in vault. Add one with `padlock set --type ssh-key`.");
    }

    // Select key
    let selected = if let Some(ref key_name) = cmd.key {
        ssh_keys
            .iter()
            .find(|(name, ..)| name == key_name)
            .ok_or_else(|| anyhow::anyhow!("SSH key '{key_name}' not found in vault"))?
    } else {
        &ssh_keys[0]
    };

    let (key_name, public_key, key_type, _comment) = selected;

    // Write public key to file
    let padlock_dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("~/.padlock"));
    let keys_dir = padlock_dir.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    let pub_key_path = keys_dir.join(format!("{key_name}.pub"));
    std::fs::write(&pub_key_path, public_key)?;

    // Set up allowed signers file
    let allowed_signers_path = padlock_dir.join("allowed_signers");

    // Configure Git
    let scope = if cmd.global {
        GitConfigScope::Global
    } else {
        GitConfigScope::Local
    };

    let changes = git_config::setup_git_ssh_signing(
        scope,
        &pub_key_path.display().to_string(),
        &allowed_signers_path.display().to_string(),
    )?;

    if json {
        let output = serde_json::json!({
            "status": "configured",
            "scope": if cmd.global { "global" } else { "local" },
            "key_name": key_name,
            "key_type": key_type,
            "public_key_path": pub_key_path.display().to_string(),
            "allowed_signers_path": allowed_signers_path.display().to_string(),
            "changes": changes,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Git signing configured successfully!");
        println!("  Scope:           {}", if cmd.global { "global" } else { "local" });
        println!("  Key:             {key_name} ({key_type})");
        println!("  Public key:      {}", pub_key_path.display());
        println!("  Allowed signers: {}", allowed_signers_path.display());
        println!();
        println!("Changes applied:");
        for change in &changes {
            println!("  {change}");
        }
    }

    Ok(())
}

/// Run `padlock git verify`.
fn run_verify(cmd: GitVerifyCmd, json: bool) -> anyhow::Result<()> {
    let result = git_config::verify_commit(&cmd.commit)?;

    match result {
        padlock_core::signing::VerifyResult::Valid { fingerprint } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "commit": cmd.commit,
                        "fingerprint": fingerprint,
                    }))?
                );
            } else {
                println!("Signature valid.");
                println!("  Commit:      {}", cmd.commit);
                println!("  Fingerprint: {fingerprint}");
            }
        }
        padlock_core::signing::VerifyResult::Invalid { reason } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": false,
                        "commit": cmd.commit,
                        "reason": reason,
                    }))?
                );
            } else {
                println!("Signature invalid.");
                println!("  Commit: {}", cmd.commit);
                println!("  Reason: {reason}");
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Run `padlock git allowed-signers`.
fn run_allowed_signers(
    cmd: GitAllowedSignersCmd,
    vault_path: &str,
    json: bool,
) -> anyhow::Result<()> {
    let path = resolve_vault_path(vault_path);
    let storage = FilesystemBackend::new(path.clone());
    let passphrase = prompt_passphrase("Passphrase: ")?;
    let vault = Vault::open(&passphrase, &storage, &KdfParams::production())?;

    // Find SSH keys with git/ssh tags
    let entries = list_entries(&vault)?;
    let mut signers = Vec::new();

    for (entry_id, _name) in &entries {
        if let Ok(entry) = read_entry(&vault, entry_id) {
            if let EntryData::SSHKey { public_key, .. } = &entry.data {
                // Use entry name as principal, or email from tags
                let principal = entry
                    .tags
                    .iter()
                    .find(|t| t.contains('@'))
                    .cloned()
                    .unwrap_or_else(|| entry.name.clone());

                signers.push(AllowedSigner {
                    principal,
                    public_key: public_key.clone(),
                });
            }
        }
    }

    let content = generate_allowed_signers(&signers);

    if cmd.list {
        if json {
            let entries: Vec<_> = signers
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "principal": s.principal,
                        "public_key": s.public_key,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "signers": entries }))?);
        } else if signers.is_empty() {
            println!("No SSH keys found in vault.");
        } else {
            println!("{content}");
        }
        return Ok(());
    }

    // Write to file
    let output_path = if let Some(ref out) = cmd.output {
        std::path::PathBuf::from(out)
    } else {
        path.parent()
            .map(|p| p.join("allowed_signers"))
            .unwrap_or_else(|| std::path::PathBuf::from("allowed_signers"))
    };

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, format!("{content}\n"))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "written",
                "path": output_path.display().to_string(),
                "signer_count": signers.len(),
            }))?
        );
    } else {
        println!(
            "Allowed signers file written to {} ({} keys).",
            output_path.display(),
            signers.len()
        );
    }

    Ok(())
}

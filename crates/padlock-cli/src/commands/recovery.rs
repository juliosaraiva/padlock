//! `padlock recovery` command group implementation.
//!
//! Manages vault recovery key: enable, disable, and status.

use clap::{Args, Subcommand};
use padlock_core::vault::format::parse_header;
use padlock_core::vault::storage::FilesystemBackend;

use super::{open_vault_mut_with_session, resolve_vault_path};

/// Manage vault recovery key.
#[derive(Args)]
pub struct RecoveryCmd {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: RecoveryCommands,
}

/// Recovery subcommands.
#[derive(Subcommand)]
pub enum RecoveryCommands {
    /// Enable recovery and display the recovery key.
    Enable(RecoveryEnableCmd),
    /// Disable recovery.
    Disable(RecoveryDisableCmd),
    /// Show whether recovery is enabled.
    Status(RecoveryStatusCmd),
}

/// Enable recovery key for the vault.
#[derive(Args)]
pub struct RecoveryEnableCmd {}

/// Disable recovery key for the vault.
#[derive(Args)]
pub struct RecoveryDisableCmd {}

/// Show recovery status for the vault.
#[derive(Args)]
pub struct RecoveryStatusCmd {}

/// Execute the recovery command group.
pub fn run(cmd: RecoveryCmd, vault_path: &str, no_session: bool) -> anyhow::Result<()> {
    match cmd.command {
        RecoveryCommands::Enable(_) => run_enable(vault_path, no_session),
        RecoveryCommands::Disable(_) => run_disable(vault_path, no_session),
        RecoveryCommands::Status(_) => run_status(vault_path),
    }
}

fn run_enable(vault_path: &str, no_session: bool) -> anyhow::Result<()> {
    let (mut vault, storage) = open_vault_mut_with_session(vault_path, no_session)?;

    let key = vault.enable_recovery(&storage)?;

    println!("Recovery key enabled.");
    println!();
    println!("IMPORTANT: Save this recovery key in a secure location.");
    println!("It will NOT be shown again.");
    println!();
    println!("  {key}");
    println!();
    println!("If you forget your passphrase, run `padlock recover` and enter this key.");
    println!("Changing your passphrase will invalidate this recovery key.");

    Ok(())
}

fn run_disable(vault_path: &str, no_session: bool) -> anyhow::Result<()> {
    let (mut vault, storage) = open_vault_mut_with_session(vault_path, no_session)?;

    vault.disable_recovery(&storage)?;

    println!("Recovery key disabled.");
    Ok(())
}

fn run_status(vault_path: &str) -> anyhow::Result<()> {
    let path = resolve_vault_path(vault_path);
    if !path.exists() {
        anyhow::bail!("vault not found at {}", path.display());
    }

    let storage = FilesystemBackend::new(path);
    let data = padlock_core::traits::storage::StorageBackend::read_vault(&storage)?;
    let header = parse_header(&data)?;

    if header.recovery_enabled() {
        println!("Recovery: enabled");
    } else {
        println!("Recovery: not enabled");
    }

    Ok(())
}

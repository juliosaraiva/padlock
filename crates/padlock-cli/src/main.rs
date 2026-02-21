//! Padlock CLI -- command-line interface for the Padlock credential manager.
//!
//! This binary crate provides the user-facing CLI for all vault operations.
//! It is a thin adapter over `padlock-core`, implementing the `clap` command
//! structure and wiring core traits to concrete implementations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commands;
pub mod output;

use clap::Parser;
use commands::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        let exit_code = determine_exit_code(&e);
        eprintln!("error: {e}");
        std::process::exit(exit_code);
    }
}

/// Determine the exit code from an anyhow error by downcasting to
/// `padlock_core::error::Error` variants.
fn determine_exit_code(err: &anyhow::Error) -> i32 {
    if let Some(core_err) = err.downcast_ref::<padlock_core::error::Error>() {
        match core_err {
            padlock_core::error::Error::Vault(vault_err) => match vault_err {
                padlock_core::error::VaultError::Locked => 2,
                padlock_core::error::VaultError::WrongPassphrase => 4,
                padlock_core::error::VaultError::HmacMismatch => 5,
                padlock_core::error::VaultError::RecoveryNotEnabled => 6,
                _ => 1,
            },
            padlock_core::error::Error::Entry(entry_err) => match entry_err {
                padlock_core::error::EntryError::NotFound { .. } => 3,
                _ => 1,
            },
            padlock_core::error::Error::Agent(agent_err) => match agent_err {
                padlock_core::error::AgentError::NotRunning => 10,
                _ => 1,
            },
            _ => 1,
        }
    } else {
        1
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let fmt = output::OutputFormatter::new(cli.json, cli.quiet, cli.no_color);
    let ns = cli.no_session;

    match cli.command {
        Commands::Init(cmd) => commands::init::run(cmd),
        Commands::Unlock(cmd) => commands::unlock::run(cmd, &cli.vault_path, cli.json, ns),
        Commands::Lock(cmd) => commands::lock::run(cmd, &cli.vault_path, cli.json),
        Commands::Get(cmd) => commands::get::run(cmd, &cli.vault_path, &fmt, ns),
        Commands::Set(cmd) => commands::set::run(cmd, &cli.vault_path, ns),
        Commands::Rm(cmd) => commands::rm::run(cmd, &cli.vault_path, ns),
        Commands::Ls(cmd) => commands::ls::run(cmd, &cli.vault_path, &fmt, ns),
        Commands::Search(cmd) => commands::search::run(cmd, &cli.vault_path, &fmt, ns),
        Commands::Generate(cmd) => commands::generate::run(cmd, cli.json),
        Commands::Status(_) => commands::status::run(&cli.vault_path, &fmt),
        Commands::Agent(cmd) => commands::agent::run(cmd, &cli.vault_path, cli.json),
        Commands::Git(cmd) => commands::git::run(cmd, &cli.vault_path, cli.json),
        Commands::Completions(cmd) => commands::completions::run(cmd),
        Commands::Totp(cmd) => commands::totp::run(cmd, &cli.vault_path, cli.json, ns),
        Commands::Exec(cmd) => commands::exec::run(cmd, &cli.vault_path, ns),
        Commands::Audit(cmd) => commands::audit::run(cmd, &cli.vault_path, &fmt),
        Commands::Config(cmd) => commands::config::run(cmd, &cli.vault_path, cli.json),
        Commands::Session(cmd) => commands::session::run(cmd, &cli.vault_path, cli.json),
        Commands::Recover(cmd) => commands::recover::run(cmd),
        Commands::Recovery(cmd) => commands::recovery::run(cmd, &cli.vault_path, ns),
    }
}

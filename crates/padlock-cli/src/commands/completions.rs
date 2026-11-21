//! Shell completion script generation.
//!
//! Outputs shell completion scripts for bash, zsh, fish, and `PowerShell`
//! to stdout. Users source the output in their shell config.

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::aot::{self, Generator};

use super::Cli;

/// Generate shell completions for padlock.
#[derive(Debug, Args)]
pub struct CompletionsCmd {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: ShellType,
}

/// Supported shell types for completion generation.
#[derive(Debug, Clone, ValueEnum)]
pub enum ShellType {
    /// Bash shell.
    Bash,
    /// Zsh shell.
    Zsh,
    /// Fish shell.
    Fish,
    /// `PowerShell`.
    #[value(name = "powershell")]
    PowerShell,
}

/// Run the completions command.
///
/// # Errors
///
/// This function does not currently return errors but is typed for consistency.
#[allow(clippy::needless_pass_by_value)]
pub fn run(cmd: CompletionsCmd) -> anyhow::Result<()> {
    let cli_cmd = Cli::command();

    match cmd.shell {
        ShellType::Bash => aot::Bash.generate(&cli_cmd, &mut std::io::stdout()),
        ShellType::Zsh => aot::Zsh.generate(&cli_cmd, &mut std::io::stdout()),
        ShellType::Fish => aot::Fish.generate(&cli_cmd, &mut std::io::stdout()),
        ShellType::PowerShell => {
            aot::PowerShell.generate(&cli_cmd, &mut std::io::stdout());
        }
    }

    Ok(())
}

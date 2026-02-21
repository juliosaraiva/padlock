//! `padlock generate` command implementation.

use clap::Args;
use padlock_core::generate::{estimate_strength, generate_password, PasswordPolicy};

/// Generate a random password.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
pub struct GenerateCmd {
    /// Password length.
    #[arg(short, long, default_value = "24")]
    length: usize,

    /// Exclude uppercase letters.
    #[arg(long)]
    no_uppercase: bool,

    /// Exclude lowercase letters.
    #[arg(long)]
    no_lowercase: bool,

    /// Exclude digits.
    #[arg(long)]
    no_digits: bool,

    /// Exclude symbols.
    #[arg(long)]
    no_symbols: bool,
}

/// Execute the generate command.
///
/// # Errors
///
/// Returns an error if password generation fails.
#[allow(clippy::needless_pass_by_value)]
pub fn run(cmd: GenerateCmd, json: bool) -> anyhow::Result<()> {
    let policy = PasswordPolicy {
        length: cmd.length,
        uppercase: !cmd.no_uppercase,
        lowercase: !cmd.no_lowercase,
        digits: !cmd.no_digits,
        symbols: !cmd.no_symbols,
    };

    let password = generate_password(&policy);
    let strength = estimate_strength(&password);

    if json {
        let output = serde_json::json!({
            "password": password,
            "length": password.len(),
            "strength": strength,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{password}");
        let label = match strength {
            0 => "very weak",
            1 => "weak",
            2 => "fair",
            3 => "strong",
            _ => "very strong",
        };
        eprintln!("Strength: {label} ({strength}/4)");
    }

    Ok(())
}

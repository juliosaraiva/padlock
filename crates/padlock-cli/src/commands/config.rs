//! `padlock config` command implementation.
//!
//! Read and write configuration values in `~/.padlock/config.toml`.

use clap::{Args, Subcommand};
use padlock_core::config::Config;

use super::padlock_dir;

/// Manage configuration.
#[derive(Args)]
pub struct ConfigCmd {
    /// Config subcommand.
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

/// Available config subcommands.
#[derive(Subcommand)]
pub enum ConfigSubcommand {
    /// Get a configuration value.
    Get(ConfigGetCmd),
    /// Set a configuration value.
    Set(ConfigSetCmd),
    /// List all configuration values.
    List(ConfigListCmd),
}

/// Get a single configuration value by key.
#[derive(Args)]
pub struct ConfigGetCmd {
    /// Configuration key (e.g., session.duration).
    key: String,
}

/// Set a configuration value.
#[derive(Args)]
pub struct ConfigSetCmd {
    /// Configuration key (e.g., session.duration).
    key: String,
    /// Value to set.
    value: String,
}

/// List all configuration values.
#[derive(Args)]
pub struct ConfigListCmd;

/// Execute the config command.
///
/// # Errors
///
/// Returns an error if the config operation fails.
pub fn run(cmd: ConfigCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    match cmd.command {
        ConfigSubcommand::Get(get) => run_get(get, vault_path, json),
        ConfigSubcommand::Set(set) => run_set(set, vault_path),
        ConfigSubcommand::List(list) => run_list(list, vault_path, json),
    }
}

/// Path to config.toml.
fn config_path(vault_path: &str) -> std::path::PathBuf {
    padlock_dir(vault_path).join("config.toml")
}

/// Load config from file, returning defaults if not found.
pub(crate) fn load_config(vault_path: &str) -> anyhow::Result<Config> {
    let path = config_path(vault_path);
    if path.exists() {
        let contents = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

/// Save config to file.
fn save_config(vault_path: &str, config: &Config) -> anyhow::Result<()> {
    let path = config_path(vault_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&path, contents)?;
    Ok(())
}

/// Look up a config value by dotted key path.
fn get_value(config: &Config, key: &str) -> anyhow::Result<String> {
    match key {
        "session.duration" => Ok(config.session.duration.clone()),
        "session.idle_timeout" => Ok(config.session.idle_timeout.clone()),
        "session.max_sessions" => Ok(config.session.max_sessions.to_string()),
        "session.auto_session" => Ok(config.session.auto_session.to_string()),
        _ => anyhow::bail!("unknown configuration key: {key}"),
    }
}

/// Set a config value by dotted key path.
fn set_value(config: &mut Config, key: &str, value: &str) -> anyhow::Result<()> {
    match key {
        "session.duration" => {
            config.session.duration = value.to_string();
        }
        "session.idle_timeout" => {
            config.session.idle_timeout = value.to_string();
        }
        "session.max_sessions" => {
            config.session.max_sessions = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid integer value: {value}"))?;
        }
        "session.auto_session" => {
            config.session.auto_session = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid boolean value: {value}"))?;
        }
        _ => anyhow::bail!("unknown configuration key: {key}"),
    }
    Ok(())
}

/// All known configuration keys.
const CONFIG_KEYS: &[&str] = &[
    "session.duration",
    "session.idle_timeout",
    "session.max_sessions",
    "session.auto_session",
];

#[allow(clippy::needless_pass_by_value)]
fn run_get(cmd: ConfigGetCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let config = load_config(vault_path)?;
    let value = get_value(&config, &cmd.key)?;

    if json {
        let output = serde_json::json!({
            "key": cmd.key,
            "value": value,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{value}");
    }

    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn run_set(cmd: ConfigSetCmd, vault_path: &str) -> anyhow::Result<()> {
    let mut config = load_config(vault_path)?;
    set_value(&mut config, &cmd.key, &cmd.value)?;
    save_config(vault_path, &config)?;
    Ok(())
}

fn run_list(_cmd: ConfigListCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let config = load_config(vault_path)?;

    if json {
        let mut entries = serde_json::Map::new();
        for key in CONFIG_KEYS {
            if let Ok(value) = get_value(&config, key) {
                entries.insert((*key).to_string(), serde_json::Value::String(value));
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(entries))?
        );
    } else {
        for key in CONFIG_KEYS {
            if let Ok(value) = get_value(&config, key) {
                println!("{key} = {value}");
            }
        }
    }

    Ok(())
}

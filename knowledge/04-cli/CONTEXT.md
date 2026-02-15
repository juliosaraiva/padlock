# CLI Interface Context — Padlock Command-Line Interface

## Overview

The Padlock CLI is a thin, user-facing wrapper over `padlock-core` that provides command-line access to vault operations. It implements platform-specific concerns (terminal interaction, clipboard, shell integration) while delegating cryptographic and storage logic to the core library.

## Command Architecture

The command tree uses `clap` derive macros for declarative parsing. Top-level subcommands are:

```rust
#[derive(Parser)]
#[command(name = "padlock")]
#[command(about = "Encrypted credential manager")]
pub enum Commands {
    /// Initialize a new vault
    Init(InitCmd),

    /// Unlock vault (derive KEK from passphrase)
    Unlock(UnlockCmd),

    /// Lock vault (erase decryption key from memory)
    Lock(LockCmd),

    /// Show vault and lock status
    Status(StatusCmd),

    /// Retrieve an entry by name or ID
    Get(GetCmd),

    /// Create or update an entry
    Set(SetCmd),

    /// Delete an entry
    Rm(RmCmd),

    /// List all entries
    Ls(LsCmd),

    /// Search entries by name/tag/type
    Search(SearchCmd),

    /// Generate strong passwords or other secrets
    Generate(GenerateCmd),

    /// SSH key management
    #[command(subcommand)]
    Ssh(SshCmd),

    /// Certificate management
    Cert(CertCmd),

    /// TOTP/2FA management
    Totp(TotpCmd),

    /// Git credential helper integration
    Git(GitCmd),

    /// SSH/credential agent (background service)
    Agent(AgentCmd),

    /// Synchronize vault across devices
    Sync(SyncCmd),

    /// Audit and compliance reporting
    Audit(AuditCmd),

    /// Export vault to portable format
    Export(ExportCmd),

    /// Import entries from external sources
    Import(ImportCmd),

    /// Configuration management
    Config(ConfigCmd),

    /// Generate shell completions
    Completions(CompletionsCmd),
}
```

## Output Modes

All commands respect output format flags:

```rust
#[derive(Args)]
pub struct OutputOpts {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Suppress output
    #[arg(short, long)]
    pub quiet: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}
```

Output behavior:
- **Human-readable (default):** Formatted tables, colored output, progress indicators
- **--json:** Machine-parseable JSON, one result per line (JSONL) for lists
- **--quiet/-q:** Only exit code returned, no stdout
- **--no-color:** ANSI color codes stripped from output

Example implementations:

```rust
// Human output
println!("Entry: {}", style(&entry.name).cyan().bold());
println!("Type:  {}", entry.entry_data.type_str());

// JSON output
println!("{}", serde_json::to_string(&json!({
    "id": entry.id,
    "name": entry.name,
    "type": entry.entry_data.type_str(),
}))?);

// Quiet mode
if !opts.quiet {
    println!("Created: {}", entry.id);
}
```

## Exit Codes

Standardized exit codes enable scripting and integration:

```rust
pub mod exit_codes {
    pub const SUCCESS: i32 = 0;           // Operation succeeded
    pub const GENERAL_ERROR: i32 = 1;     // Unspecified error
    pub const VAULT_LOCKED: i32 = 2;      // Vault is locked, unlock required
    pub const NOT_FOUND: i32 = 3;         // Entry/resource not found
    pub const AUTH_FAILED: i32 = 4;       // Authentication failed (wrong passphrase)
    pub const INTEGRITY_ERROR: i32 = 5;   // Vault data corrupted or tampered
    pub const SYNC_CONFLICT: i32 = 6;     // Sync conflict detected (merge needed)
    pub const AGENT_NOT_RUNNING: i32 = 10; // SSH/credential agent unavailable
}
```

Usage pattern:

```rust
fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match execute_command(args) {
        Ok(result) => {
            println!("{}", result);
            std::process::exit(exit_codes::SUCCESS);
        }
        Err(Error::VaultLocked) => {
            eprintln!("Error: Vault is locked");
            std::process::exit(exit_codes::VAULT_LOCKED);
        }
        Err(Error::NotFound(_)) => {
            std::process::exit(exit_codes::NOT_FOUND);
        }
        // ... handle other error types
    }
}
```

## Clipboard Integration

Secrets retrieved via `get` command are copied to clipboard with automatic expiration:

```rust
#[derive(Args)]
pub struct GetCmd {
    /// Entry name or ID
    pub name_or_id: String,

    /// Copy to clipboard (default: true)
    #[arg(short, long, default_value_t = true)]
    pub copy: bool,

    /// Clipboard timeout in seconds
    #[arg(long, default_value = "45")]
    pub clip_timeout: u64,

    #[command(flatten)]
    pub output: OutputOpts,
}

impl GetCmd {
    pub fn execute(self) -> Result<()> {
        let vault = Vault::load()?;
        let entry = vault.get_entry(&self.name_or_id)?;

        let secret = match &entry.entry_data {
            EntryData::Credential { password, .. } => password.as_str(),
            EntryData::SSHKey { private_key, .. } => private_key.as_str(),
            // ...
        };

        if self.copy {
            let mut clipboard = arboard::Clipboard::new()?;
            clipboard.set_text(secret.to_string())?;

            // Schedule clipboard wipe
            let clip_timeout = self.clip_timeout;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(clip_timeout));
                if let Ok(mut clip) = arboard::Clipboard::new() {
                    let _ = clip.clear();
                }
            });

            if !self.output.quiet {
                println!("Secret copied to clipboard (expires in {}s)",
                         self.clip_timeout);
            }
        } else if !self.output.quiet {
            println!("{}", secret);
        }

        Ok(())
    }
}
```

Clipboard behavior:
- Only copy if `--copy` flag is set (default: true)
- Configurable timeout (default: 45 seconds, --clip-timeout)
- Background thread clears clipboard after timeout
- Never displays secret to terminal by default (use `--copy=false` for stdout)
- Zeroized after wipe (no memory leaks)

## Environment Variable Injection

The `exec` subcommand injects secrets as environment variables without shell history:

```rust
#[derive(Args)]
pub struct ExecCmd {
    /// Variables to inject (VAR=entry_name format)
    #[arg(value_name = "VAR=ENTRY")]
    pub vars: Vec<String>,

    /// Command to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,

    /// Don't actually execute, just print env vars
    #[arg(long)]
    pub dry_run: bool,
}

impl ExecCmd {
    pub fn execute(self) -> Result<()> {
        let vault = Vault::load()?;

        let mut env_vars = std::env::vars().collect::<HashMap<_, _>>();

        for var_spec in self.vars {
            let (var_name, entry_name) = var_spec.split_once('=')
                .ok_or(anyhow!("Format: VAR=entry_name"))?;

            let entry = vault.get_entry(entry_name)?;
            let secret = match &entry.entry_data {
                EntryData::Credential { password, .. } => password.as_str().to_string(),
                EntryData::SSHKey { private_key, .. } => private_key.as_str().to_string(),
                _ => bail!("Entry type cannot be used as environment variable"),
            };

            env_vars.insert(var_name.to_string(), secret);
        }

        if self.dry_run {
            for (k, v) in &env_vars {
                println!("{}={}", k, v);
            }
            return Ok(());
        }

        // Execute command with injected environment
        let mut cmd = std::process::Command::new(&self.command[0]);
        cmd.args(&self.command[1..]);

        for (k, v) in env_vars {
            cmd.env(&k, &v);
        }

        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
```

Usage examples:

```bash
# Inject DB_PASSWORD from vault entry
padlock exec DB_PASSWORD=prod_db_pass -- psql -U user -d database

# Dry-run to see environment variables
padlock exec --dry-run DB_PASS=credentials API_KEY=github_token -- env | grep -E '^(DB_|API_)'

# Multiple variables
padlock exec SLACK_TOKEN=slack_bot GITHUB_TOKEN=github_cli -- deploy.sh
```

Advantages:
- Secrets never appear in shell history (no `echo $SECRET`)
- Injected via process environment, not command line
- Child process inherits environment, no subprocess coordination needed
- Secrets are zeroized when parent process exits

## Process Substitution and .netrc Format

For tools like `curl`, `wget`, `git`, Padlock can generate `.netrc` format output:

```rust
#[derive(Args)]
pub struct GetCmd {
    // ... other fields ...

    /// Output in .netrc format (for curl --netrc-file)
    #[arg(long)]
    pub netrc_format: bool,
}

impl GetCmd {
    pub fn execute(self) -> Result<()> {
        let vault = Vault::load()?;
        let entry = vault.get_entry(&self.name_or_id)?;

        if self.netrc_format {
            match &entry.entry_data {
                EntryData::Netrc {
                    machine, login, password, account, ..
                } => {
                    let mut output = format!("machine {}\nlogin {}\npassword {}\n",
                        machine, login, password);
                    if let Some(acc) = account {
                        output.push_str(&format!("account {}\n", acc));
                    }
                    println!("{}", output);
                }
                EntryData::Credential { url, username, password, .. } => {
                    if let Some(url_str) = url {
                        let machine = url_str.parse::<url::Url>()?
                            .host_str()
                            .ok_or(anyhow!("Invalid URL"))?
                            .to_string();
                        println!("machine {}\nlogin {}\npassword {}\n",
                            machine, username, password);
                    } else {
                        bail!("Credential entry requires URL for netrc format");
                    }
                }
                _ => bail!("Entry type cannot be converted to netrc format"),
            }
            return Ok(());
        }

        // ... normal get logic ...
    }
}
```

Usage with curl:

```bash
# Generate .netrc file from vault
padlock get example_credentials --netrc-format > /tmp/.netrc
chmod 600 /tmp/.netrc

# Use with curl
curl --netrc-file /tmp/.netrc https://api.example.com/data

# Or as process substitution (bash/zsh)
curl --netrc-file <(padlock get example_credentials --netrc-format) https://api.example.com/data
```

## Shell Completions

Completions are generated for bash, zsh, and fish with dynamic completion of entry names, tags, and keys:

```rust
#[derive(Args)]
pub struct CompletionsCmd {
    /// Shell type
    #[arg(value_enum)]
    pub shell: Shell,
}

#[derive(ValueEnum, Clone)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionsCmd {
    pub fn execute(self) -> Result<()> {
        use clap_complete::generate;
        use std::io;

        let mut cmd = Args::command();
        let name = cmd.get_name().to_string();

        match self.shell {
            Shell::Bash => generate(clap_complete::shells::Bash, &mut cmd, &name, &mut io::stdout()),
            Shell::Zsh => generate(clap_complete::shells::Zsh, &mut cmd, &name, &mut io::stdout()),
            Shell::Fish => generate(clap_complete::shells::Fish, &mut cmd, &name, &mut io::stdout()),
        };

        Ok(())
    }
}

// Dynamic completion function (called by shell)
fn complete_entry_names(partial: &str) -> Vec<String> {
    let vault = Vault::load().ok()?;
    vault.list_entries()
        .ok()?
        .iter()
        .filter(|e| e.name.starts_with(partial))
        .map(|e| e.name.clone())
        .collect()
}

fn complete_tags(partial: &str) -> Vec<String> {
    let vault = Vault::load().ok()?;
    vault.list_all_tags()
        .ok()?
        .iter()
        .filter(|t| t.starts_with(partial))
        .cloned()
        .collect()
}
```

Installation:

```bash
# Bash: add to ~/.bashrc
eval "$(padlock completions bash)"

# Zsh: add to ~/.zshrc
eval "$(padlock completions zsh)"

# Fish: add to ~/.config/fish/config.fish
padlock completions fish | source
```

## Configuration File

User preferences are stored in `~/.padlock/config.toml`:

```toml
[vault]
# Vault location (default: ~/.padlock/vault)
path = "~/.padlock/vault"

# Clipboard timeout (seconds)
clip_timeout = 45

# Enable entry history by default
enable_history = true

[display]
# Default output format: human, json, quiet
output = "human"

# Disable colors
no_color = false

# Default table format for lists
list_format = "compact"  # or "detailed"

[behavior]
# Require confirmation before deleting entries
confirm_delete = true

# Automatically lock vault on terminal close (if agent)
auto_lock_on_exit = true

# Timeout to auto-lock (minutes, 0 = never)
inactivity_timeout = 0

[ssh]
# Path to SSH agent socket
agent_socket = "~/.padlock/ssh-agent.sock"

# Load SSH keys on unlock
auto_load_keys = true

[git]
# Git credential helper enabled
enabled = true

# Timeout for git credential responses
timeout = 5

[sync]
# Enable auto-sync
enabled = false

# Sync interval (minutes)
interval = 60

# Sync server URL
server = "https://sync.example.com"

# Device ID (generated on init)
device_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Config parsing:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub vault: VaultConfig,
    pub display: DisplayConfig,
    pub behavior: BehaviorConfig,
    pub ssh: SshConfig,
    pub git: GitConfig,
    pub sync: SyncConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .unwrap()
            .join("padlock/config.toml");

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(config_path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = dirs::config_dir()
            .unwrap()
            .join("padlock");

        std::fs::create_dir_all(&config_path)?;

        let content = toml::to_string_pretty(self)?;
        std::fs::write(config_path.join("config.toml"), content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: VaultConfig::default(),
            display: DisplayConfig::default(),
            behavior: BehaviorConfig::default(),
            ssh: SshConfig::default(),
            git: GitConfig::default(),
            sync: SyncConfig::default(),
        }
    }
}
```

## Passphrase Input

Passphrases are read from the terminal (never stdin) using the `rpassword` crate:

```rust
use rpassword::prompt_password;

pub fn read_passphrase(prompt: &str) -> Result<String> {
    prompt_password(prompt).map_err(Into::into)
}

pub fn read_passphrase_twice(prompt: &str) -> Result<String> {
    loop {
        let pass1 = prompt_password(prompt)?;
        let pass2 = prompt_password("Confirm passphrase: ")?;

        if pass1 == pass2 {
            return Ok(pass1);
        }

        eprintln!("Passphrases do not match. Try again.");
    }
}

// Usage in init command
let passphrase = read_passphrase_twice("Enter passphrase for new vault: ")?;
vault.init(&passphrase)?;
```

Key points:
- Reads directly from `/dev/tty` (terminal) via `rpassword`
- Does not echo input to terminal
- Never reads from stdin (allows piping other input to CLI)
- Supports confirmation (read twice for new passphrases)
- Passphrase string is zeroized after use

## Module Structure

The CLI is organized as:

```
cli/
├── main.rs              # Entry point, argument parsing, dispatch
├── commands/
│   ├── mod.rs           # Command trait, common utilities
│   ├── init.rs          # Initialize new vault
│   ├── vault.rs         # unlock, lock, status
│   ├── entries.rs       # get, set, rm, ls, search
│   ├── generate.rs      # Password/secret generation
│   ├── ssh/
│   │   ├── mod.rs
│   │   ├── add.rs       # Add SSH key to vault
│   │   ├── list.rs      # List SSH keys
│   │   ├── export.rs    # Export public key
│   │   └── agent.rs     # SSH agent integration
│   ├── totp.rs          # TOTP generation and management
│   ├── cert.rs          # Certificate import and export
│   ├── git.rs           # Git credential helper
│   ├── agent.rs         # Background agent process
│   ├── sync.rs          # Multi-device sync
│   ├── audit.rs         # Audit and compliance
│   ├── export.rs        # Export vault to external format
│   ├── import.rs        # Import from external sources
│   ├── config.rs        # Configuration management
│   └── completions.rs   # Shell completion generation
├── output.rs            # Formatted output, --json, --quiet
├── config.rs            # Config file loading
└── ui.rs                # Terminal UI helpers, colors, tables
```

### main.rs
```rust
use clap::Parser;

mod commands;
mod config;
mod output;
mod ui;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Init(cmd) => cmd.execute(),
        Commands::Unlock(cmd) => cmd.execute(),
        Commands::Get(cmd) => cmd.execute(),
        // ... dispatch to command modules
    }
}
```

### commands/mod.rs
```rust
pub mod init;
pub mod vault;
pub mod entries;
// ...

pub use init::InitCmd;
pub use vault::{UnlockCmd, LockCmd, StatusCmd};
// ...

#[derive(Parser)]
pub enum Commands {
    Init(InitCmd),
    Unlock(UnlockCmd),
    Lock(LockCmd),
    Status(StatusCmd),
    #[command(subcommand)]
    Get(GetCmd),
    // ...
}

pub trait Command {
    fn execute(self) -> anyhow::Result<()>;
}
```

### output.rs
```rust
use colored::*;
use serde_json::json;

pub struct OutputFormatter {
    json: bool,
    quiet: bool,
    no_color: bool,
}

impl OutputFormatter {
    pub fn print_entry(&self, entry: &Entry) -> anyhow::Result<()> {
        if self.json {
            println!("{}", serde_json::to_string(&entry)?);
        } else if !self.quiet {
            println!("Name: {}", entry.name.cyan().bold());
            println!("Type: {}", entry.entry_data.type_str().green());
            // ...
        }
        Ok(())
    }

    pub fn print_table(&self, entries: &[Entry]) -> anyhow::Result<()> {
        if self.json {
            for entry in entries {
                println!("{}", serde_json::to_string(&entry)?);
            }
        } else if !self.quiet {
            // Use prettytable or similar
            let mut table = Table::new();
            table.add_row(row!["Name", "Type", "Modified", "Tags"]);
            for entry in entries {
                table.add_row(row![
                    entry.name,
                    entry.entry_data.type_str(),
                    entry.modified_at,
                    entry.tags.join(", ")
                ]);
            }
            println!("{}", table);
        }
        Ok(())
    }
}
```

## Trait Implementations

The CLI implements two `padlock-core` traits:

### StorageBackend
```rust
pub struct FileSystemBackend {
    vault_path: PathBuf,
}

impl StorageBackend for FileSystemBackend {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        std::fs::read(self.vault_path.join(path))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(self.vault_path.parent().unwrap())?;
        std::fs::write(self.vault_path.join(path), data)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    fn exists(&self, path: &str) -> bool {
        self.vault_path.join(path).exists()
    }
}
```

### UserConfirmation
```rust
pub struct TerminalConfirmation;

impl UserConfirmation for TerminalConfirmation {
    fn confirm(&self, prompt: &str) -> Result<bool> {
        print!("{} (y/n): ", prompt);
        std::io::stdout().flush()?;

        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;

        Ok(response.trim().to_lowercase() == "y")
    }
}
```

## Dependencies

External crates:
- `clap`: Command-line argument parsing (derive API)
- `anyhow`: Error handling and propagation
- `colored`: Terminal color output (respects --no-color)
- `rpassword`: Terminal passphrase input without echo
- `arboard`: Clipboard access for secret copying
- `toml`: Config file parsing
- `serde`: Serialization framework
- `prettytable-rs`: Formatted table output
- `dirs`: Standard directory paths (`~/.config`, `~/.local`, etc.)
- `url`: URL parsing for netrc conversion
- `uuid`: Identifier generation
- `serde_json`: JSON output formatting

Dev dependencies:
- `assert_cmd`: Integration testing (execute CLI)
- `predicates`: Test assertions for command output
- `tempfile`: Temporary test vault directories

## Testing Strategy

### Integration Tests

Test entire CLI workflows using `assert_cmd`:

```rust
#[test]
fn test_init_and_unlock() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault");

    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.env("PADLOCK_VAULT", &vault_path)
       .arg("init")
       .write_stdin("mypassphrase\nmypassphrase\n")
       .assert().success()
       .stdout(predicates::str::contains("Vault initialized"));

    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.env("PADLOCK_VAULT", &vault_path)
       .arg("status")
       .assert()
       .failure()
       .code(exit_codes::VAULT_LOCKED);

    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.env("PADLOCK_VAULT", &vault_path)
       .arg("unlock")
       .write_stdin("mypassphrase\n")
       .assert().success();
}

#[test]
fn test_get_and_copy_to_clipboard() {
    let vault = test_vault_with_entry(/* ... */);

    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("get")
       .arg("my_credential")
       .arg("--copy")
       .arg("--clip-timeout")
       .arg("5")
       .assert().success()
       .stdout(predicates::str::contains("copied to clipboard"));
}

#[test]
fn test_exit_codes() {
    // Test vault locked (exit code 2)
    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("get").arg("nonexistent")
       .assert().code(exit_codes::VAULT_LOCKED);

    // Test not found (exit code 3)
    setup_vault();
    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("get").arg("nonexistent")
       .assert().code(exit_codes::NOT_FOUND);
}

#[test]
fn test_json_output() {
    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("ls")
       .arg("--json")
       .assert().success()
       .stdout(predicates::str::contains("\"id\""));
}

#[test]
fn test_quiet_mode() {
    let mut cmd = Command::cargo_bin("padlock").unwrap();
    cmd.arg("get")
       .arg("credential")
       .arg("--quiet")
       .assert().success()
       .stdout("");  // No output in quiet mode
}
```

### Command-Specific Tests

- **init**: Creates vault, validates passphrase confirmation
- **unlock**: Loads existing vault, rejects invalid passphrase
- **get**: Retrieves entry, copies to clipboard, respects timeout
- **set**: Creates/updates entry, validates required fields
- **rm**: Deletes entry, requires confirmation if enabled
- **ls**: Lists all entries in table format
- **search**: Finds entries by name/tag, returns matches only
- **exec**: Injects environment variables, executes child process
- **completions**: Generates completion scripts for each shell

## Performance Considerations

- Lazy loading: Vault only decrypted on first access command
- Clipboard wipe thread: Non-blocking, doesn't delay command return
- Config caching: Load once per CLI invocation
- Tab completion: Loaded only when shell requests completion
- Large vaults: Streaming output for list/search (doesn't load all entries to memory)

## Security Considerations

- Passphrase never echoed to terminal (via `rpassword`)
- Environment variable injection avoids shell history exposure
- Clipboard wipe on timeout (even if process crashes, timeout still fires)
- No secrets logged to stdout unless explicitly requested
- Config file contains no secrets (only paths and preferences)
- Process memory zeroized on exit (via padlock-core zeroize derives)
- Agent process runs with restricted file permissions (0600)

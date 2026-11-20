//! `padlock set` command implementation.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};

use clap::Args;
use padlock_core::entries::crud::create_entry;
use padlock_core::entries::types::EntryData;
use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions, Termios};
use zeroize::Zeroizing;

use super::open_vault_mut_with_session;

const MAX_PASSWORD_BYTES: usize = 512;

/// Create or update an entry.
#[derive(Args)]
pub struct SetCmd {
    /// Entry name.
    name: String,

    /// Username for credential entries.
    #[arg(short, long)]
    username: Option<String>,

    /// Read up to 512 UTF-8 bytes through EOF from non-terminal stdin. Keeps whitespace.
    #[arg(long)]
    password_stdin: bool,

    /// URL for credential entries.
    #[arg(long)]
    url: Option<String>,

    /// Tags (comma-separated).
    #[arg(short, long)]
    tags: Option<String>,

    /// Notes.
    #[arg(long)]
    notes: Option<String>,
}

// Identify set before Clap parses values or builds diagnostics.
pub(crate) fn set_arguments(args: &[OsString]) -> Option<&[OsString]> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_encoded_bytes() {
            b"--vault-path" => {
                args.next();
            }
            value if value.starts_with(b"--vault-path=") => {}
            b"--json" | b"--quiet" | b"--no-color" | b"--no-session" => {}
            b"set" => return Some(args.as_slice()),
            _ => return None,
        }
    }
    None
}

// After --, Clap treats these spellings as positional entry names.
pub(crate) fn contains_password_option(args: &[OsString]) -> bool {
    args.iter().take_while(|arg| *arg != "--").any(|arg| {
        let arg = arg.as_encoded_bytes();
        arg == b"--password"
            || arg.starts_with(b"--password=")
            || arg.starts_with(b"-p")
            || arg.starts_with(b"--password-stdin=")
    })
}

struct HiddenTerminal {
    tty: File,
    original: Termios,
}

impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        let _ = tcsetattr(&self.tty, OptionalActions::Flush, &self.original);
    }
}

fn prompt_entry_password() -> anyhow::Result<String> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let original = tcgetattr(&tty)?;
    let mut hidden = original.clone();
    // Retain line editing and the newline delimiter while suppressing echo.
    hidden
        .local_modes
        .insert(LocalModes::ICANON | LocalModes::ECHONL);
    hidden.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&tty, OptionalActions::Flush, &hidden)?;
    let mut terminal = HiddenTerminal { tty, original };
    terminal.tty.write_all(b"Entry password: ")?;
    read_entry_password(&mut terminal.tty, true)
}

fn read_entry_password(reader: &mut impl Read, terminal_line: bool) -> anyhow::Result<String> {
    // Bound both paths. Allow one extra byte to distinguish the exact limit
    // from overflow and a terminal newline to complete a full-length line.
    let mut bytes = Zeroizing::new(vec![0; MAX_PASSWORD_BYTES + 2]);
    let mut len = 0;
    while len < bytes.len() {
        match reader.read(&mut bytes[len..]) {
            Ok(0) => break,
            Ok(count) => {
                len += count;
                if terminal_line {
                    if let Some(line) = bytes[..len].strip_suffix(b"\n") {
                        return decode_password(line);
                    }
                    if len <= MAX_PASSWORD_BYTES {
                        anyhow::bail!("entry password input ended before Enter");
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
        if len > MAX_PASSWORD_BYTES {
            anyhow::bail!("entry password exceeds 512 bytes");
        }
    }
    if terminal_line {
        anyhow::bail!("entry password input ended before Enter");
    }
    decode_password(&bytes[..len])
}

fn decode_password(bytes: &[u8]) -> anyhow::Result<String> {
    if bytes.len() > MAX_PASSWORD_BYTES {
        anyhow::bail!("entry password exceeds 512 bytes");
    }
    let password = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("entry password must be valid UTF-8"))?;
    Ok(password.to_owned())
}

/// Execute the set command.
///
/// # Errors
///
/// Returns an error if vault access or entry creation fails.
pub fn run(cmd: SetCmd, vault_path: &str, no_session: bool) -> anyhow::Result<()> {
    let mut password = Zeroizing::new(if cmd.password_stdin {
        let stdin = io::stdin();
        if stdin.is_terminal() {
            anyhow::bail!("--password-stdin requires redirected input");
        }
        let mut input = File::from(rustix::io::dup(stdin)?);
        read_entry_password(&mut input, false)?
    } else {
        prompt_entry_password()?
    });
    let (mut vault, storage) = open_vault_mut_with_session(vault_path, no_session)?;

    let tags: Vec<String> = cmd
        .tags
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let data = EntryData::Credential {
        username: cmd.username.unwrap_or_default(),
        password: std::mem::take(&mut *password),
        url: cmd.url,
        notes: cmd.notes,
    };

    let entry = create_entry(&mut vault, cmd.name, data, tags)?;
    vault.write_to_storage(&storage)?;

    println!("Created entry '{}' ({})", entry.name, entry.id);
    Ok(())
}

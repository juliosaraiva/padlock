//! `padlock set` command implementation.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use padlock_core::entries::crud::create_entry;
use padlock_core::entries::types::EntryData;
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions, Termios};
use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP};
use signal_hook::{flag, low_level};
use zeroize::{Zeroize, Zeroizing};

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
    forward_signals: Arc<AtomicBool>,
}

impl HiddenTerminal {
    fn restore(&self) -> rustix::io::Result<()> {
        tcsetattr(&self.tty, OptionalActions::Flush, &self.original)?;
        self.forward_signals.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        if !self.forward_signals.load(Ordering::SeqCst) {
            let _ = self.restore();
        }
    }
}

fn prompt_entry_password() -> anyhow::Result<String> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let original = tcgetattr(&tty)?;
    let mut hidden = original.clone();
    // Retain canonical editing and the newline delimiter while suppressing echo.
    hidden
        .local_modes
        .insert(LocalModes::ICANON | LocalModes::ECHONL);
    hidden.local_modes.remove(LocalModes::ECHO);

    let forward_signals = Arc::new(AtomicBool::new(true));
    let pending = Arc::new(AtomicUsize::new(0));
    for signal in [SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP] {
        // Leave default behavior active outside this one CLI prompt.
        flag::register_conditional_default(signal, Arc::clone(&forward_signals))?;
        flag::register_usize(signal, Arc::clone(&pending), usize::try_from(signal)?)?;
    }
    let mut terminal = HiddenTerminal {
        tty,
        original,
        forward_signals,
    };
    terminal.forward_signals.store(false, Ordering::SeqCst);
    tcsetattr(&terminal.tty, OptionalActions::Flush, &hidden)?;
    terminal.tty.write_all(b"Entry password: ")?;
    // Nonblocking reads let the main thread restore the terminal even when a
    // restarting signal has flushed input and no bytes remain to read.
    fcntl_setfl(
        &terminal.tty,
        fcntl_getfl(&terminal.tty)? | OFlags::NONBLOCK,
    )?;

    let mut bytes = Zeroizing::new([0; MAX_PASSWORD_BYTES + 2]);
    let input = loop {
        if pending.load(Ordering::SeqCst) != 0 {
            break Ok(0);
        }
        match terminal.tty.read(&mut *bytes) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            result => break result,
        }
    };

    terminal.restore()?;
    let signal = i32::try_from(pending.load(Ordering::SeqCst))?;
    if signal != 0 {
        bytes.zeroize();
        // Stop only after restoring echo. When resumed, abort this set rather
        // than accepting a partial password or applying a mutation.
        low_level::emulate_default_handler(signal)?;
        anyhow::bail!("entry password prompt interrupted");
    }

    let bytes = &bytes[..input?];
    if let Some(line) = bytes.strip_suffix(b"\n") {
        return decode_password(line);
    }
    if bytes.len() > MAX_PASSWORD_BYTES {
        anyhow::bail!("entry password exceeds {MAX_PASSWORD_BYTES} bytes");
    }
    anyhow::bail!("entry password input ended before Enter");
}

fn read_entry_password(reader: &mut impl Read) -> anyhow::Result<String> {
    let mut bytes = Zeroizing::new([0; MAX_PASSWORD_BYTES + 1]);
    let mut len = 0;
    while len < bytes.len() {
        match reader.read(&mut bytes[len..]) {
            Ok(0) => break,
            Ok(count) => len += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
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
        read_entry_password(&mut input)?
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

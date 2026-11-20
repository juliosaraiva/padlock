//! Exercise real CLI streams and the terminal line discipline.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;
use rustix::fs::{fcntl_setfl, OFlags};
use rustix::io::{fcntl_setfd, FdFlags};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};

const CLI: &str = env!("CARGO_BIN_EXE_padlock");
const PASSPHRASE: &[u8] = b"test-vault-passphrase\n";
const SENTINEL: &str = "sentinel-entry-password";

#[test]
#[ignore = "subprocess harness for the CLI tests"]
fn attach_test_tty() {
    // Exec the real CLI after acquiring a controlling terminal. Its output
    // files exclude the test harness banner and keep stderr separate.
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::env::var_os("PADLOCK_TEST_TTY").unwrap())
        .unwrap();
    rustix::process::setsid().unwrap();
    rustix::process::ioctl_tiocsctty(&tty).unwrap();
    let args: Vec<String> =
        serde_json::from_str(&std::env::var("PADLOCK_TEST_ARGS").unwrap()).unwrap();
    let error = Command::new(CLI)
        .args(args)
        .stdout(File::create(std::env::var_os("PADLOCK_TEST_STDOUT").unwrap()).unwrap())
        .stderr(File::create(std::env::var_os("PADLOCK_TEST_STDERR").unwrap()).unwrap())
        .exec();
    panic!("failed to exec CLI: {error}");
}

fn read_tty(master: &mut File, transcript: &mut Vec<u8>) {
    let mut buf = [0; 1024];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => transcript.extend_from_slice(&buf[..len]),
            Err(err) if err.kind() == ErrorKind::WouldBlock => break,
            Err(err) => panic!("failed to read PTY: {err}"),
        }
    }
}

fn run_cli(
    vault: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    exchanges: &[(&[u8], &[u8])],
) -> (Output, Vec<u8>) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    fcntl_setfd(&master, FdFlags::CLOEXEC).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap().into_string().unwrap();
    let _slave = rustix::fs::open(
        name.as_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
    let mut master = File::from(master);
    let output_dir = tempfile::tempdir().unwrap();
    let stdout = output_dir.path().join("stdout");
    let stderr = output_dir.path().join("stderr");
    let mut cli_args = vec!["--vault-path", vault.to_str().unwrap(), "--no-session"];
    cli_args.extend_from_slice(args);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "attach_test_tty"])
        .env("PADLOCK_TEST_TTY", name)
        .env(
            "PADLOCK_TEST_ARGS",
            serde_json::to_string(&cli_args).unwrap(),
        )
        .env("PADLOCK_TEST_STDOUT", &stdout)
        .env("PADLOCK_TEST_STDERR", &stderr)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    if let Some(value) = stdin {
        child.stdin.take().unwrap().write_all(value).unwrap();
    }

    let mut transcript = Vec::new();
    let mut unread = 0;
    let mut exchanges = exchanges.iter().peekable();
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        read_tty(&mut master, &mut transcript);
        if let Some((prompt, input)) = exchanges.peek() {
            if let Some(position) = transcript[unread..]
                .windows(prompt.len())
                .position(|bytes| bytes == *prompt)
            {
                unread += position + prompt.len();
                master.write_all(input).unwrap();
                exchanges.next();
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CLI timed out for {args:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        exchanges.next().is_none(),
        "CLI exited before an expected prompt"
    );
    read_tty(&mut master, &mut transcript);
    (
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        },
        transcript,
    )
}

fn fixture(dir: &Path) -> FilesystemBackend {
    let storage = FilesystemBackend::new(dir.join("fixture.vault"));
    Vault::init("test-vault-passphrase", &storage, &KdfParams::testing()).unwrap();
    storage
}

fn assert_no_echo(output: &Output, transcript: &[u8]) {
    for channel in [&output.stdout, &output.stderr, transcript] {
        assert!(!channel
            .windows(SENTINEL.len())
            .any(|bytes| bytes == SENTINEL.as_bytes()));
    }
}

#[test]
fn legacy_argv_syntax_never_echoes_or_writes() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let original = fs::read(vault).unwrap();
    let snapshots = fs::read_dir(dir.path()).unwrap().count();

    for flags in [
        vec![format!("--password={SENTINEL}")],
        vec![format!("-p{SENTINEL}")],
        vec!["--password".to_owned(), SENTINEL.to_owned()],
        vec!["-p".to_owned(), SENTINEL.to_owned()],
        vec![format!("-p={SENTINEL}")],
        vec![format!("--password-stdin={SENTINEL}")],
    ] {
        let mut args = vec!["set", "example"];
        args.extend(flags.iter().map(String::as_str));
        let (output, transcript) = run_cli(vault, &args, None, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--password-stdin"));
        assert_no_echo(&output, &transcript);
        assert_eq!(fs::read(vault).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), snapshots);
    }
}

#[test]
fn password_input_and_explicit_output_preserve_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let passphrase = (b"Passphrase: ".as_slice(), PASSPHRASE);
    let pipe_secret = format!(" \t{SENTINEL}\r\n  \n");
    let tty_secret = format!(" \t{SENTINEL}  ");
    let tty_line = format!("{tty_secret}\n");

    let (output, transcript) = run_cli(
        vault,
        &["set", "pipe", "--password-stdin"],
        Some(pipe_secret.as_bytes()),
        &[passphrase],
    );
    assert!(output.status.success(), "{output:?}");
    assert_no_echo(&output, &transcript);

    let (output, transcript) = run_cli(
        vault,
        &["set", "prompt"],
        None,
        &[(b"Entry password: ", tty_line.as_bytes()), passphrase],
    );
    assert!(output.status.success(), "{output:?}");
    assert_no_echo(&output, &transcript);

    for args in [
        vec!["get", "pipe"],
        vec!["--quiet", "get", "pipe"],
        vec!["--json", "get", "pipe"],
        vec!["--quiet", "--json", "get", "pipe"],
    ] {
        let (output, transcript) = run_cli(vault, &args, None, &[passphrase]);
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("pipe"));
        assert_no_echo(&output, &transcript);
    }

    let boundary = SENTINEL
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(512)
        .collect::<Vec<_>>();
    let mut boundary_line = boundary.clone();
    boundary_line.push(b'\n');
    let (output, transcript) = run_cli(
        vault,
        &["set", "limit-a", "--password-stdin"],
        Some(&boundary),
        &[passphrase],
    );
    assert!(output.status.success(), "{output:?}");
    assert_no_echo(&output, &transcript);
    let (output, transcript) = run_cli(
        vault,
        &["set", "limit-b"],
        None,
        &[(b"Entry password: ", &boundary_line), passphrase],
    );
    assert!(output.status.success(), "{output:?}");
    assert_no_echo(&output, &transcript);
    for entry in ["limit-a", "limit-b"] {
        let (output, _) = run_cli(vault, &["get", entry, "-p"], None, &[passphrase]);
        assert!(output.status.success());
        assert_eq!(output.stdout, boundary);
    }

    for (entry, password) in [("pipe", pipe_secret), ("prompt", tty_secret)] {
        let (output, _) = run_cli(
            vault,
            &["get", entry, "--password-only"],
            None,
            &[passphrase],
        );
        assert!(output.status.success());
        assert_eq!(output.stdout, password.as_bytes());
    }
    for args in [
        vec!["--json", "get", "pipe", "--password-only"],
        vec!["get", "pipe", "-p", "--quiet", "--json"],
    ] {
        let (output, transcript) = run_cli(vault, &args, None, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert_no_echo(&output, &transcript);
    }
}

#[test]
fn malformed_and_oversize_input_fail_before_vault_write() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let original = fs::read(vault).unwrap();
    let mut invalid = SENTINEL.as_bytes().to_vec();
    invalid.push(0xFF);
    let oversize = SENTINEL
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(513)
        .collect::<Vec<_>>();

    for (input, error) in [
        (invalid.as_slice(), "must be valid UTF-8"),
        (oversize.as_slice(), "exceeds 512 bytes"),
    ] {
        let mut tty_line = input.to_vec();
        tty_line.push(b'\n');
        let results = [
            run_cli(
                vault,
                &["set", "pipe", "--password-stdin"],
                Some(input),
                &[],
            ),
            run_cli(
                vault,
                &["set", "prompt"],
                None,
                &[(b"Entry password: ", &tty_line)],
            ),
        ];
        for (output, transcript) in results {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(error),
                "{output:?}"
            );
            assert_no_echo(&output, &transcript);
            assert_eq!(fs::read(vault).unwrap(), original);
        }
    }
}

#[test]
fn rejected_post_terminator_arguments_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let original = fs::read(vault).unwrap();
    let snapshots = fs::read_dir(dir.path()).unwrap().count();

    for value in [
        format!("--password={SENTINEL}"),
        format!("-p{SENTINEL}"),
        SENTINEL.to_owned(),
    ] {
        let (output, transcript) = run_cli(vault, &["set", "example", "--", &value], None, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert_no_echo(&output, &transcript);
        assert_eq!(fs::read(vault).unwrap(), original);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), snapshots);
    }
}

#[test]
fn password_like_literal_names_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let passphrase = (b"Passphrase: ".as_slice(), PASSPHRASE);

    for name in ["--password=literal-name", "-pliteral-name"] {
        let (output, transcript) = run_cli(
            vault,
            &["set", "--password-stdin", "--", name],
            Some(SENTINEL.as_bytes()),
            &[passphrase],
        );
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains(name));
        assert_no_echo(&output, &transcript);

        let (output, _) = run_cli(
            vault,
            &["get", "--password-only", "--", name],
            None,
            &[passphrase],
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, SENTINEL.as_bytes());
    }
}

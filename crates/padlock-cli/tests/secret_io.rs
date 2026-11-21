//! Exercise real CLI streams and the terminal line discipline.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use padlock_core::vault::lifecycle::{KdfParams, Vault};
use padlock_core::vault::storage::FilesystemBackend;
use rustix::fs::{fcntl_setfl, OFlags};
use rustix::io::{fcntl_setfd, FdFlags};
use rustix::process::{kill_process, waitpid, Pid, Signal, WaitOptions};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
use rustix::termios::{tcgetattr, LocalModes};

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
    run_cli_observed(vault, args, stdin, exchanges, false, |_, _| {})
}

fn run_cli_observed(
    vault: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    exchanges: &[(&[u8], &[u8])],
    session_enabled: bool,
    on_first_input: impl FnOnce(&mut Child, &File),
) -> (Output, Vec<u8>) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    fcntl_setfd(&master, FdFlags::CLOEXEC).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap().into_string().unwrap();
    let slave = rustix::fs::open(
        name.as_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let slave = File::from(slave);
    let original_modes = tcgetattr(&slave).unwrap().local_modes;
    fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
    let mut master = File::from(master);
    let output_dir = tempfile::tempdir().unwrap();
    let stdout = output_dir.path().join("stdout");
    let stderr = output_dir.path().join("stderr");
    let mut cli_args = vec!["--vault-path", vault.to_str().unwrap()];
    if !session_enabled {
        cli_args.push("--no-session");
    }
    cli_args.extend_from_slice(args);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "attach_test_tty"])
        .env("HOME", output_dir.path())
        .env_remove("PADLOCK_SESSION")
        .env_remove("PADLOCK_VAULT")
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

    let mut on_first_input = Some(on_first_input);
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
                if let Some(observe) = on_first_input.take() {
                    observe(&mut child, &slave);
                }
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
    assert_eq!(tcgetattr(&master).unwrap().local_modes, original_modes);
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

#[test]
fn interrupt_restores_terminal_and_leaves_vault_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let original = fs::read(vault).unwrap();
    let partial = format!("{SENTINEL}\x03");

    let (output, transcript) = run_cli(
        vault,
        &["set", "interrupt"],
        None,
        &[(b"Entry password: ", partial.as_bytes())],
    );
    assert_eq!(output.status.signal(), Some(signal_hook::consts::SIGINT));
    assert_no_echo(&output, &transcript);
    assert_eq!(fs::read(vault).unwrap(), original);
}

#[test]
fn suspend_restores_echo_before_stopping_and_cancels_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let vault = storage.vault_path();
    let original = fs::read(vault).unwrap();
    let partial = format!("{SENTINEL}\x1a");

    let (output, transcript) = run_cli_observed(
        vault,
        &["set", "suspend"],
        None,
        &[(b"Entry password: ", partial.as_bytes())],
        false,
        |child, tty| {
            let pid = Pid::from_child(child);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some((_, status)) =
                    waitpid(Some(pid), WaitOptions::UNTRACED | WaitOptions::NOHANG).unwrap()
                {
                    assert!(status.stopped(), "expected the CLI to suspend");
                    let modes = tcgetattr(tty).unwrap().local_modes;
                    kill_process(pid, Signal::CONT).unwrap();
                    assert!(modes.contains(LocalModes::ECHO | LocalModes::ICANON));
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("CLI did not suspend");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        },
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("prompt interrupted"));
    assert_no_echo(&output, &transcript);
    assert_eq!(fs::read(vault).unwrap(), original);
}

#[test]
fn recover_uses_selected_vault_and_preserves_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let (out, _) = run_cli(
        &dir.path().join("fixture.vault"),
        &["recover"],
        None,
        &[(b"Recovery key:", b"unused-synthetic-key\n")],
    );
    assert_eq!(out.status.code(), Some(6));
    assert_eq!(out.stdout, [] as [u8; 0]);
}

#[test]
fn recovery_json_rejected_before_prompt_or_write() {
    use padlock_core::traits::storage::StorageBackend;
    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let before = storage.read_vault().unwrap();
    for args in [
        &["--json", "recover"][..],
        &["--json", "recovery", "status"],
        &["--json", "recovery", "enable"],
        &["--json", "recovery", "disable"],
    ] {
        let (out, transcript) = run_cli(&dir.path().join("fixture.vault"), args, None, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(out.stdout, [] as [u8; 0]);
        assert!(String::from_utf8_lossy(&out.stderr).contains("--json"));
        assert_eq!(transcript, [] as [u8; 0]);
        assert_eq!(storage.read_vault().unwrap(), before);
    }
}

#[test]
fn session_revocation_requires_positive_ack_in_both_scopes() {
    use padlock_core::session::protocol::{serialize_session_response, SessionResponse};
    use padlock_core::ssh_agent::{protocol::serialize_response, AgentResponse};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let ack = serialize_response(&AgentResponse::ExtensionResponse {
        payload: serialize_session_response(&SessionResponse::Success).unwrap(),
    });
    let refused = serialize_response(&AgentResponse::Failure);
    let malformed = [0, 0, 0, 2, 6, 0];
    for all in [false, true] {
        for reply in [Some(ack.as_slice()), Some(&refused), Some(&malformed), None] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).unwrap();
            let token = dir.path().join("session.token");
            fs::write(&token, "a1".repeat(32)).unwrap();
            let vault = dir.path().join("fixture.vault");
            std::thread::scope(|scope| {
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let server = scope.spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut size = [0u8; 4];
                    stream.read_exact(&mut size).unwrap();
                    let mut request = vec![0; u32::from_be_bytes(size) as usize];
                    stream.read_exact(&mut request).unwrap();
                    if let Some(bytes) = reply {
                        stream.write_all(bytes).unwrap();
                    } else {
                        let _ = done_rx.recv_timeout(Duration::from_secs(10));
                    }
                });
                let mut args = vec!["--json", "session", "destroy"];
                if all {
                    args.push("--all");
                }
                let out = Command::new(CLI)
                    .arg("--vault-path")
                    .arg(vault)
                    .args(args)
                    .env_remove("PADLOCK_SESSION")
                    .output()
                    .unwrap();
                let _ = done_tx.send(());
                server.join().unwrap();
                let expected = reply == Some(ack.as_slice());
                assert_eq!(out.status.success(), expected);
                assert_eq!(token.exists(), !expected);
                if expected {
                    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                    assert_eq!(result["destroyed"], if all { "all" } else { "current" });
                } else {
                    assert_eq!(out.stdout, [] as [u8; 0]);
                    assert_ne!(out.stderr, [] as [u8; 0]);
                }
            });
        }
    }
}

#[test]
fn unlock_skips_unsafe_session_socket() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (out, _) = run_cli_observed(
        &dir.path().join("fixture.vault"),
        &["--json", "unlock"],
        None,
        &[(b"Passphrase:", PASSPHRASE)],
        true,
        |_, _| {},
    );
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["session_created"], false);
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(!dir.path().join("session.token").exists());
}

#[test]
fn recovery_output_round_trips_and_mismatch_preserves_vault() {
    use padlock_core::traits::storage::StorageBackend;

    let dir = tempfile::tempdir().unwrap();
    let storage = fixture(dir.path());
    let path = dir.path().join("fixture.vault");
    let (out, _) = run_cli(
        &path,
        &["recovery", "enable"],
        None,
        &[(b"Passphrase:", PASSPHRASE)],
    );
    assert!(out.status.success());
    assert_eq!(out.stderr, [] as [u8; 0]);
    let prose = String::from_utf8(out.stdout).unwrap();
    let key = prose
        .lines()
        .find_map(|line| line.strip_prefix("  "))
        .unwrap();
    assert_eq!(key.split('-').count(), 8);
    assert!(key.split('-').all(|group| group.len() == 8
        && group
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())));
    assert!(Vault::recover(key, &storage).is_ok());
    let key_input = format!("{key}\n");
    let before = storage.read_vault().unwrap();
    let (out, _) = run_cli(
        &path,
        &["recover"],
        None,
        &[
            (b"Recovery key:", key_input.as_bytes()),
            (b"Enter new passphrase:", b"new-test-passphrase\n"),
            (b"Confirm passphrase:", b"different-test-passphrase\n"),
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("passphrases do not match"));
    assert_eq!(storage.read_vault().unwrap(), before);
}

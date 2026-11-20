//! Exercise agent ownership through real CLI processes and disposable Unix sockets.

use std::fs;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{geteuid, kill_process, setsid, Pid, Signal};
use serde_json::Value;
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_padlock");

struct Fixture {
    directory: TempDir,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("padlock-own-")
            .tempdir_in("/tmp")
            .unwrap();
        let vault = directory.path().join("test.vault");
        Self { directory, vault }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(CLI);
        command
            .arg("--vault-path")
            .arg(&self.vault)
            .arg("--json")
            .env_remove("PADLOCK_SESSION")
            .stdin(Stdio::null());
        command
    }

    fn agent(&self, action: &str) -> Output {
        self.cli().args(["agent", action]).output().unwrap()
    }

    fn pid(&self) -> u32 {
        fs::read_to_string(self.path("agent.pid"))
            .unwrap()
            .parse()
            .unwrap()
    }

    fn ready(&self) -> (u64, u64) {
        let socket = self.path("agent.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if UnixStream::connect(&socket).is_ok() && self.path("agent.pid").is_file() {
                let meta = fs::symlink_metadata(&socket).unwrap();
                assert!(meta.file_type().is_socket());
                assert_eq!(meta.mode() & 0o777, 0o600);
                assert_eq!(meta.uid(), geteuid().as_raw());
                if fs::read_to_string(self.path("agent.pid"))
                    .is_ok_and(|pid| pid.parse::<u32>().is_ok())
                {
                    return (meta.dev(), meta.ino());
                }
            }
            assert!(Instant::now() < deadline, "daemon did not become ready");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn assert_clean(&self) {
        assert!(!self.path("agent.sock").exists());
        assert!(!self.path("agent.pid").exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if UnixStream::connect(self.path("agent.sock")).is_ok() {
            let _ = self.agent("stop");
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn json(output: &Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "subprocess wrapper to run the CLI without a controlling terminal"]
fn autostart_without_a_terminal() {
    setsid().unwrap();
    let error = Command::new(CLI)
        .arg("--vault-path")
        .arg(std::env::var_os("PADLOCK_TEST_OWNERSHIP_VAULT").unwrap())
        .args(["get", "unused"])
        .env_remove("PADLOCK_SESSION")
        .stdin(Stdio::null())
        .exec();
    panic!("exec: {error}");
}

#[test]
fn concurrent_autostart_and_explicit_starts_share_one_agent() {
    let fixture = Fixture::new();
    let autostart = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "autostart_without_a_terminal"])
        .env("PADLOCK_TEST_OWNERSHIP_VAULT", &fixture.vault)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let starts: Vec<_> = (0..6)
        .map(|_| {
            fixture
                .cli()
                .args(["agent", "start"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let identity = fixture.ready();
    let pid = fixture.pid();
    let automatic = autostart.wait_with_output().unwrap();
    assert!(!automatic.status.success());
    assert!(String::from_utf8_lossy(&automatic.stderr).contains("failed to read passphrase"));
    for start in starts {
        let result = json(&start.wait_with_output().unwrap());
        assert_eq!(result["pid"], pid);
    }
    assert_eq!(fixture.pid(), pid);
    assert_eq!(fixture.ready(), identity);
    assert_eq!(json(&fixture.agent("stop"))["status"], "stopped");
    fixture.assert_clean();
}

#[test]
fn stale_pid_never_signals_an_unrelated_process_and_stale_socket_recovers() {
    let fixture = Fixture::new();
    let mut unrelated = ChildGuard(Command::new("sleep").arg("30").spawn().unwrap());
    let old_pid = unrelated.0.id();
    fs::write(fixture.path("agent.pid"), old_pid.to_string()).unwrap();

    assert_eq!(json(&fixture.agent("stop"))["status"], "not_running");
    assert!(unrelated.0.try_wait().unwrap().is_none());
    let stale = fixture.path("agent.sock");
    drop(UnixListener::bind(&stale).unwrap());
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(json(&fixture.agent("stop"))["status"], "not_running");
    assert!(unrelated.0.try_wait().unwrap().is_none());
    assert_eq!(json(&fixture.agent("start"))["status"], "started");
    fixture.ready();
    assert_ne!(fixture.pid(), old_pid);
    assert!(unrelated.0.try_wait().unwrap().is_none());

    // Even a PID artifact replaced while a real agent is listening is not a
    // signal target. Keep it on a distinct inode and verify stop preserves it.
    fs::rename(fixture.path("agent.pid"), fixture.path("original.pid")).unwrap();
    fs::write(fixture.path("agent.pid"), old_pid.to_string()).unwrap();
    assert_eq!(json(&fixture.agent("stop"))["status"], "stopped");
    assert!(unrelated.0.try_wait().unwrap().is_none());
    assert_eq!(
        fs::read_to_string(fixture.path("agent.pid")).unwrap(),
        old_pid.to_string()
    );
    assert!(!stale.exists());
}

#[test]
fn foreground_interrupt_removes_only_the_original_socket_and_pid() {
    let fixture = Fixture::new();
    let start = || {
        ChildGuard(
            fixture
                .cli()
                .args(["agent", "start", "--foreground"])
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let mut daemon = start();
    fixture.ready();
    kill_process(Pid::from_child(&daemon.0), Signal::INT).unwrap();
    assert!(daemon.0.wait().unwrap().success());
    fixture.assert_clean();

    let mut old = start();
    fixture.ready();
    let path = fixture.path("agent.sock");
    fs::rename(&path, fixture.path("previous.sock")).unwrap();
    let successor = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(fixture.path("agent.pid"), fixture.path("previous.pid")).unwrap();
    fs::write(fixture.path("agent.pid"), "successor-marker").unwrap();
    let inode = fs::symlink_metadata(&path).unwrap().ino();

    kill_process(Pid::from_child(&old.0), Signal::INT).unwrap();
    assert!(old.0.wait().unwrap().success());
    assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
    assert_eq!(
        fs::read_to_string(fixture.path("agent.pid")).unwrap(),
        "successor-marker"
    );
    assert!(UnixStream::connect(path).is_ok());
    drop(successor);
}

#[test]
fn unsafe_socket_paths_are_preserved() {
    let fixture = Fixture::new();
    let socket = fixture.path("agent.sock");
    let file = fixture.path("unrelated");
    for link in [false, true] {
        fs::write(&file, "preserve").unwrap();
        if link {
            symlink(&file, &socket).unwrap();
        } else {
            fs::write(&socket, "preserve").unwrap();
        }
        for action in ["start", "stop"] {
            assert!(!fixture.agent(action).status.success());
        }
        assert_eq!(fs::read_to_string(&file).unwrap(), "preserve");
        assert_eq!(fs::read_to_string(&socket).unwrap(), "preserve");
        assert_eq!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_symlink(),
            link
        );
        fs::remove_file(&socket).unwrap();
    }
    let pid = fixture.path("agent.pid");
    symlink(&file, &pid).unwrap();
    let rejected = fixture
        .cli()
        .args(["agent", "start", "--foreground"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(fs::symlink_metadata(&pid).unwrap().file_type().is_symlink());
    assert_eq!(fs::read_to_string(&file).unwrap(), "preserve");
    assert!(!socket.exists());
    fs::remove_file(pid).unwrap();

    let other = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!fixture.agent("start").status.success());
    assert!(!fixture.agent("stop").status.success());
    assert!(fs::symlink_metadata(&socket)
        .unwrap()
        .file_type()
        .is_socket());
    drop(other);
}

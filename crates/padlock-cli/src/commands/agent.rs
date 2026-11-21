//! `padlock agent` command group for SSH agent management.
//!
//! Provides commands to start, stop, and query the SSH agent daemon
//! that serves vault keys to SSH clients.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use padlock_core::session::manager::SessionStore;
use padlock_core::session::protocol::{build_extension_message, SESSION_EXTENSION_NAME};
use padlock_core::ssh_agent::protocol::{parse_message, serialize_response, AgentMessage};
use padlock_core::ssh_agent::{AgentHandler, AgentResponse};
use padlock_core::traits::session::SessionManager;
use rustix::fs::{access, fcntl_setfl, flock, Access, FlockOperation, Mode, OFlags};
use rustix::io::{fcntl_setfd, FdFlags};
use rustix::net::{connect, socket, AddressFamily, SocketAddrUnix, SocketType};
use rustix::process::{geteuid, umask};
use tokio::sync::Notify;

use super::resolve_vault_path;

/// SSH agent management commands.
#[derive(Args)]
pub struct AgentCmd {
    /// Agent subcommand.
    #[command(subcommand)]
    pub command: AgentSubcommand,
}

/// Available agent subcommands.
#[derive(Subcommand)]
pub enum AgentSubcommand {
    /// Start the SSH agent daemon.
    Start(AgentStartCmd),
    /// Stop a running SSH agent.
    Stop(AgentStopCmd),
    /// Show agent status.
    Status(AgentStatusCmd),
    /// Print shell environment variables for agent integration.
    ShellEnv(AgentShellEnvCmd),
    /// List keys loaded in the running agent.
    List(AgentListCmd),
}

/// Start the SSH agent daemon.
#[derive(Args)]
pub struct AgentStartCmd {
    /// Run in the foreground (do not daemonize).
    #[arg(long)]
    pub foreground: bool,
}

/// Stop a running SSH agent.
#[derive(Args)]
pub struct AgentStopCmd {}

/// Show agent status.
#[derive(Args)]
pub struct AgentStatusCmd {}

/// Print shell environment variables.
#[derive(Args)]
pub struct AgentShellEnvCmd {}

/// List keys loaded in the agent.
#[derive(Args)]
pub struct AgentListCmd {}

/// Get the agent socket path from the vault path.
fn agent_socket_path(vault_path: &str) -> PathBuf {
    let vault = resolve_vault_path(vault_path);
    vault.parent().map_or_else(
        || PathBuf::from("/tmp/padlock-agent.sock"),
        |p| p.join("agent.sock"),
    )
}

/// Get the agent PID file path.
fn agent_pid_path(vault_path: &str) -> PathBuf {
    let vault = resolve_vault_path(vault_path);
    vault.parent().map_or_else(
        || PathBuf::from("/tmp/padlock-agent.pid"),
        |p| p.join("agent.pid"),
    )
}

const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(3);
const STOP_PAYLOAD: &[u8] = b"padlock-agent-stop-v1";

fn socket_metadata(path: &Path) -> io::Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe agent socket",
        ));
    }
    Ok(metadata)
}

/// Connect to an owned session socket and validate the connected peer before any writes.
pub(super) fn connect_session_socket(path: &Path) -> io::Result<UnixStream> {
    let artifact = AgentArtifact::new(path.to_path_buf(), &socket_metadata(path)?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let stream = runtime.block_on(async {
        tokio::time::timeout(AGENT_READY_TIMEOUT, tokio::net::UnixStream::connect(path)).await?
    })?;
    // UID checks trust processes running as this user. The inode check rejects replacement
    // during connect within the supported stable-directory boundary.
    if stream.peer_cred()?.uid() != geteuid().as_raw() || !artifact.matches(&socket_metadata(path)?)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent socket identity changed",
        ));
    }
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    let timeout = Some(Duration::from_secs(5));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    Ok(stream)
}

fn probe_owned_socket(path: &Path) -> io::Result<()> {
    socket_metadata(path)?;
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
    fcntl_setfl(&fd, OFlags::NONBLOCK)?;
    connect(&fd, &SocketAddrUnix::new(path)?)?;
    Ok(())
}

fn missing_or_stale(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

fn checked_owner_file(metadata: &Metadata) -> bool {
    metadata.is_file() && metadata.uid() == geteuid().as_raw() && metadata.nlink() == 1
}

fn read_agent_pid(path: &Path) -> Option<u32> {
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?,
    );
    let metadata = file.metadata().ok()?;
    if !checked_owner_file(&metadata) || metadata.len() > 32 {
        return None;
    }
    let mut value = String::new();
    file.take(32).read_to_string(&mut value).ok()?;
    value.trim().parse().ok()
}

pub(super) fn ensure_background(vault_path: &str) -> io::Result<bool> {
    let socket = agent_socket_path(vault_path);
    let mut child = match probe_owned_socket(&socket) {
        Ok(()) => None,
        Err(error) if missing_or_stale(&error) => Some(
            Command::new(std::env::current_exe()?)
                .args(["--vault-path", vault_path, "agent", "start", "--foreground"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        ),
        Err(error) => return Err(error),
    };
    let pid_path = agent_pid_path(vault_path);
    let deadline = Instant::now() + AGENT_READY_TIMEOUT;
    loop {
        match probe_owned_socket(&socket) {
            Ok(()) => {
                if let Some(pid) = read_agent_pid(&pid_path) {
                    return Ok(child.as_ref().is_some_and(|child| child.id() == pid));
                }
            }
            Err(error)
                if missing_or_stale(&error) || error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error),
        }
        // A losing child can exit before the competing lock holder binds.
        if let Some(child) = &mut child {
            let _ = child.try_wait()?;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "agent did not become ready",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

struct AgentArtifact {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl AgentArtifact {
    fn new(path: PathBuf, metadata: &Metadata) -> Self {
        Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(&self, metadata: &Metadata) -> bool {
        metadata.dev() == self.device && metadata.ino() == self.inode
    }

    fn still_owned(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|metadata| self.matches(&metadata))
    }

    fn cleanup(&self) {
        if self.still_owned() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// A live daemon holds this lock until its PID and socket cleanup is complete.
// The directory must be stable and writable only by trusted principals.
fn take_agent_lock(socket_path: &Path) -> io::Result<File> {
    let lock_path = socket_path.with_file_name("agent.lock");
    let file = File::from(rustix::fs::open(
        lock_path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = file.metadata()?;
    if !checked_owner_file(&metadata) || metadata.mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe agent lock",
        ));
    }
    flock(&file, FlockOperation::NonBlockingLockExclusive)?;
    Ok(file)
}

fn remove_stale_artifacts(socket_path: &Path, pid_path: &Path) -> io::Result<()> {
    let socket = match socket_metadata(socket_path) {
        Ok(metadata) => Some(AgentArtifact::new(socket_path.to_path_buf(), &metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if socket.is_some() {
        match probe_owned_socket(socket_path) {
            Ok(()) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "agent socket is in use",
                ))
            }
            Err(error) if missing_or_stale(&error) => {}
            Err(error) => return Err(error),
        }
    }
    match fs::symlink_metadata(pid_path) {
        Ok(metadata) if checked_owner_file(&metadata) => fs::remove_file(pid_path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe agent PID file",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if socket.as_ref().is_some_and(AgentArtifact::still_owned) {
        fs::remove_file(socket_path)?;
    }
    Ok(())
}

struct OwnedAgentArtifact(AgentArtifact);

impl Drop for OwnedAgentArtifact {
    fn drop(&mut self) {
        self.0.cleanup();
    }
}

/// Execute the agent command group.
///
/// # Errors
///
/// Returns an error if the subcommand fails.
pub fn run(cmd: AgentCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    match cmd.command {
        AgentSubcommand::Start(start) => run_start(start, vault_path, json),
        AgentSubcommand::Stop(_) => run_stop(vault_path, json),
        AgentSubcommand::Status(_) => run_status(vault_path, json),
        AgentSubcommand::ShellEnv(_) => {
            run_shell_env(vault_path);
            Ok(())
        }
        AgentSubcommand::List(_) => run_list(vault_path, json),
    }
}

fn prepare_agent_parent(socket: &Path) -> io::Result<()> {
    let Some(parent) = socket.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(());
    };

    match fs::metadata(parent) {
        Ok(metadata) if metadata.is_dir() => return Ok(access(parent, Access::EXEC_OK)?),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent parent is not a directory",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // Only the new directories get private permissions. Do this before
    // tightening the socket umask, which masks directory search permission.
    let previous = umask(Mode::from_bits_truncate(0o077));
    let created = fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent);
    umask(previous);
    created?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe newly created agent parent",
        ));
    }
    Ok(access(parent, Access::EXEC_OK)?)
}

/// Start the SSH agent daemon.
#[allow(clippy::needless_pass_by_value)]
fn run_start(cmd: AgentStartCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket_path = agent_socket_path(vault_path);
    let pid_path = agent_pid_path(vault_path);
    if cmd.foreground {
        prepare_agent_parent(&socket_path)?;
        // Set owner-only permissions before creating the socket or runtime threads.
        let private = Mode::from_bits_truncate(0o177);
        umask(umask(private) | private);
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(run_agent_foreground(socket_path, pid_path));
    }

    let launched = ensure_background(vault_path)?;
    let pid = read_agent_pid(&pid_path);
    let status = if launched {
        "started"
    } else {
        "already_running"
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "pid": pid,
                "socket": socket_path,
            }))?
        );
    } else {
        if launched {
            println!("Agent started (PID {}).", pid.unwrap_or(0));
            println!("To use, run:");
            println!("  eval \"$(padlock agent shell-env)\"");
        } else {
            println!("Agent is already running.");
        }
        println!("Socket: {}", socket_path.display());
    }
    Ok(())
}

/// Run the agent in the foreground (async).
async fn run_agent_foreground(socket_path: PathBuf, pid_path: PathBuf) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let _lock = take_agent_lock(&socket_path)?;
    remove_stale_artifacts(&socket_path, &pid_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    let _socket = OwnedAgentArtifact(AgentArtifact::new(
        socket_path.clone(),
        &fs::symlink_metadata(&socket_path)?,
    ));
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    let mut pid_file = File::from(rustix::fs::open(
        &pid_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let _pid = OwnedAgentArtifact(AgentArtifact::new(pid_path, &pid_file.metadata()?));
    write!(pid_file, "{}", std::process::id())?;

    // Create session store for caching vault keys
    let session_store = Arc::new(SessionStore::new());

    let handler = std::sync::Arc::new(std::sync::Mutex::new(AgentHandler::with_session_store(
        session_store.clone(),
    )));

    eprintln!("Padlock SSH agent listening on {}", socket_path.display());

    let shutdown = Arc::new(Notify::new());

    // Session sweep timer (60s interval)
    let sweep_store = session_store.clone();
    let mut sweep_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    tokio::select! {
        result = accept_loop(listener, handler, shutdown.clone()) => {
            if let Err(e) = result {
                eprintln!("Agent error: {e}");
            }
        }
        () = async {
            loop {
                sweep_interval.tick().await;
                let _ = sweep_store.sweep_expired();
            }
        } => {}
        _ = interrupt.recv() => {}
        () = shutdown.notified() => {}
    }

    let _ = session_store.destroy_all_sessions();

    Ok(())
}

/// Accept loop for incoming connections.
async fn accept_loop(
    listener: tokio::net::UnixListener,
    handler: std::sync::Arc<std::sync::Mutex<AgentHandler>>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let (mut stream, _) = listener.accept().await?;
        let handler = handler.clone();
        let shutdown = shutdown.clone();

        tokio::spawn(async move {
            loop {
                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;

                if msg_len == 0 || msg_len > 256 * 1024 {
                    break;
                }

                // Read message payload
                let mut msg_buf = zeroize::Zeroizing::new(vec![0u8; msg_len]);
                if stream.read_exact(&mut msg_buf).await.is_err() {
                    break;
                }

                // Parse and handle
                let response = match parse_message(&msg_buf) {
                    Ok(AgentMessage::Extension { name, payload })
                        if name == SESSION_EXTENSION_NAME && payload.as_bytes() == STOP_PAYLOAD =>
                    {
                        if stream
                            .peer_cred()
                            .is_ok_and(|peer| peer.uid() == geteuid().as_raw())
                            && stream
                                .write_all(&serialize_response(&AgentResponse::Success))
                                .await
                                .is_ok()
                        {
                            shutdown.notify_one();
                        }
                        break;
                    }
                    Ok(msg) => {
                        let h = handler.lock().unwrap();
                        h.handle_message(&msg)
                    }
                    Err(_) => AgentResponse::Failure,
                };

                drop(msg_buf);
                let response_bytes = serialize_response(&response);
                if stream.write_all(&response_bytes).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Stop the running agent.
fn run_stop(vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket = agent_socket_path(vault_path);
    let status = if stop_owned_agent(&socket)? {
        "stopped"
    } else {
        "not_running"
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"status": status}))?
        );
    } else if status == "stopped" {
        println!("Agent stopped.");
    } else {
        println!("Agent is not running.");
    }
    Ok(())
}

fn stop_owned_agent(path: &Path) -> anyhow::Result<bool> {
    let metadata = match socket_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if missing_or_stale(&error) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let artifact = AgentArtifact::new(path.to_path_buf(), &metadata);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(AGENT_READY_TIMEOUT, async {
            let mut stream = match tokio::net::UnixStream::connect(path).await {
                Ok(stream) => stream,
                Err(error) if missing_or_stale(&error) => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if stream.peer_cred()?.uid() != geteuid().as_raw() || !artifact.still_owned() {
                anyhow::bail!("agent socket identity changed");
            }
            stream
                .write_all(&build_extension_message(STOP_PAYLOAD))
                .await?;
            let mut response = [0; 5];
            stream.read_exact(&mut response).await?;
            if response.as_slice() != serialize_response(&AgentResponse::Success) {
                anyhow::bail!("agent did not acknowledge shutdown");
            }
            while artifact.still_owned() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok(true)
        })
        .await?
    })
}

/// Show agent status.
fn run_status(vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket_path = agent_socket_path(vault_path);
    let pid_path = agent_pid_path(vault_path);
    let running = probe_owned_socket(&socket_path).is_ok();
    let pid = read_agent_pid(&pid_path);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "running": running,
                "pid": pid,
                "socket": socket_path.display().to_string(),
            }))?
        );
    } else if running {
        println!("Agent is running (PID {}).", pid.unwrap_or(0));
        println!("Socket: {}", socket_path.display());
    } else {
        println!("Agent is not running.");
    }

    Ok(())
}

/// Print shell environment variables for agent integration.
fn run_shell_env(vault_path: &str) {
    let socket_path = agent_socket_path(vault_path);
    println!("export SSH_AUTH_SOCK=\"{}\";", socket_path.display());
}

/// List keys loaded in the running agent.
fn run_list(vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket_path = agent_socket_path(vault_path);

    if !socket_path.exists() {
        anyhow::bail!(
            "agent is not running (no socket at {})",
            socket_path.display()
        );
    }

    // Connect to the agent and send REQUEST_IDENTITIES
    let mut stream = UnixStream::connect(&socket_path)?;

    // Build REQUEST_IDENTITIES message: length(1) + type(11)
    let msg = [0, 0, 0, 1, 11u8];
    stream.write_all(&msg)?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len == 0 || resp_len > 256 * 1024 {
        anyhow::bail!("invalid response from agent");
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    // Parse response - expect IDENTITIES_ANSWER (12)
    if resp_buf.is_empty() || resp_buf[0] != 12 {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "keys": serde_json::Value::Array(vec![]),
                }))?
            );
        } else {
            println!("No keys loaded.");
        }
        return Ok(());
    }

    // Parse key count
    if resp_buf.len() < 5 {
        anyhow::bail!("malformed identities response");
    }
    let key_count = u32::from_be_bytes(resp_buf[1..5].try_into()?) as usize;

    if json {
        let mut keys = Vec::new();
        let mut offset = 5;
        for _ in 0..key_count {
            if offset + 4 > resp_buf.len() {
                break;
            }
            let blob_len = u32::from_be_bytes(resp_buf[offset..offset + 4].try_into()?) as usize;
            offset += 4 + blob_len;
            if offset + 4 > resp_buf.len() {
                break;
            }
            let comment_len = u32::from_be_bytes(resp_buf[offset..offset + 4].try_into()?) as usize;
            offset += 4;
            if offset + comment_len > resp_buf.len() {
                break;
            }
            let comment = String::from_utf8_lossy(&resp_buf[offset..offset + comment_len]);
            offset += comment_len;
            keys.push(serde_json::json!({
                "comment": comment,
            }));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "keys": keys }))?
        );
    } else {
        println!("Loaded keys: {key_count}");
        let mut offset = 5;
        for i in 0..key_count {
            if offset + 4 > resp_buf.len() {
                break;
            }
            let blob_len = u32::from_be_bytes(resp_buf[offset..offset + 4].try_into()?) as usize;
            offset += 4 + blob_len;
            if offset + 4 > resp_buf.len() {
                break;
            }
            let comment_len = u32::from_be_bytes(resp_buf[offset..offset + 4].try_into()?) as usize;
            offset += 4;
            if offset + comment_len > resp_buf.len() {
                break;
            }
            let comment = String::from_utf8_lossy(&resp_buf[offset..offset + comment_len]);
            offset += comment_len;
            println!("  {}. {comment}", i + 1);
        }
    }

    Ok(())
}

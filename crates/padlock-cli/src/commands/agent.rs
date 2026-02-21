//! `padlock agent` command group for SSH agent management.
//!
//! Provides commands to start, stop, and query the SSH agent daemon
//! that serves vault keys to SSH clients.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand};
use padlock_core::session::manager::SessionStore;
use padlock_core::ssh_agent::protocol::{parse_message, serialize_response};
use padlock_core::ssh_agent::{AgentHandler, AgentResponse};
use padlock_core::traits::session::SessionManager;

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
    vault
        .parent().map_or_else(|| PathBuf::from("/tmp/padlock-agent.sock"), |p| p.join("agent.sock"))
}

/// Get the agent PID file path.
fn agent_pid_path(vault_path: &str) -> PathBuf {
    let vault = resolve_vault_path(vault_path);
    vault
        .parent().map_or_else(|| PathBuf::from("/tmp/padlock-agent.pid"), |p| p.join("agent.pid"))
}

/// Check if the agent is running by checking the PID file, process, and socket.
fn is_agent_running(vault_path: &str) -> bool {
    let pid_path = agent_pid_path(vault_path);
    if !pid_path.exists() {
        return false;
    }
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let process_alive = std::process::Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !process_alive {
                return false;
            }
            // Also verify socket is connectable (process could be unrelated
            // or the child may not have bound the socket yet)
            let socket_path = agent_socket_path(vault_path);
            return socket_path.exists()
                && std::os::unix::net::UnixStream::connect(&socket_path).is_ok();
        }
    }
    false
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

/// Start the SSH agent daemon.
#[allow(clippy::needless_pass_by_value)]
fn run_start(cmd: AgentStartCmd, vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket_path = agent_socket_path(vault_path);
    let pid_path = agent_pid_path(vault_path);

    if !cmd.foreground && is_agent_running(vault_path) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "already_running",
                    "socket": socket_path.display().to_string(),
                }))?
            );
        } else {
            println!("Agent is already running.");
            println!("Socket: {}", socket_path.display());
        }
        return Ok(());
    }

    // Remove stale socket if present
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    if cmd.foreground {
        // Run in foreground using tokio
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(run_agent_foreground(
            socket_path.clone(),
            pid_path,
            vault_path.to_string(),
            json,
        ))?;
    } else {
        // Spawn ourselves with --foreground for daemonization
        let exe = std::env::current_exe()?;
        let child = std::process::Command::new(exe)
            .arg("--vault-path")
            .arg(vault_path)
            .arg("agent")
            .arg("start")
            .arg("--foreground")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let pid = child.id();
        std::fs::write(&pid_path, pid.to_string())?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "started",
                    "pid": pid,
                    "socket": socket_path.display().to_string(),
                }))?
            );
        } else {
            println!("Agent started (PID {pid}).");
            println!("Socket: {}", socket_path.display());
            println!();
            println!("To use, run:");
            println!("  eval \"$(padlock agent shell-env)\"");
        }
    }

    Ok(())
}

/// Run the agent in the foreground (async).
async fn run_agent_foreground(
    socket_path: PathBuf,
    pid_path: PathBuf,
    _vault_path: String,
    _json: bool,
) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    // Create parent directory
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Set socket permissions to 0o600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Write PID file
    std::fs::write(&pid_path, std::process::id().to_string())?;

    // Create session store for caching vault keys
    let session_store = Arc::new(SessionStore::new());

    let handler = std::sync::Arc::new(std::sync::Mutex::new(AgentHandler::with_session_store(
        session_store.clone(),
    )));

    eprintln!("Padlock SSH agent listening on {}", socket_path.display());

    // Set up graceful shutdown
    let socket_path_clone = socket_path.clone();
    let pid_path_clone = pid_path.clone();

    // Session sweep timer (60s interval)
    let sweep_store = session_store.clone();
    let mut sweep_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    tokio::select! {
        result = accept_loop(listener, handler) => {
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
        _ = tokio::signal::ctrl_c() => {
            eprintln!("Shutting down agent...");
            let _ = session_store.destroy_all_sessions();
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(&socket_path_clone);
    let _ = std::fs::remove_file(&pid_path_clone);

    Ok(())
}

/// Accept loop for incoming connections.
async fn accept_loop(
    listener: tokio::net::UnixListener,
    handler: std::sync::Arc<std::sync::Mutex<AgentHandler>>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let (mut stream, _) = listener.accept().await?;
        let handler = handler.clone();

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
                let mut msg_buf = vec![0u8; msg_len];
                if stream.read_exact(&mut msg_buf).await.is_err() {
                    break;
                }

                // Parse and handle
                let response = match parse_message(&msg_buf) {
                    Ok(msg) => {
                        let h = handler.lock().unwrap();
                        h.handle_message(&msg)
                    }
                    Err(_) => AgentResponse::Failure,
                };

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
    let pid_path = agent_pid_path(vault_path);
    let socket_path = agent_socket_path(vault_path);

    if !pid_path.exists() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "not_running",
                }))?
            );
        } else {
            println!("Agent is not running.");
        }
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_path)?;
    if let Ok(pid) = pid_str.trim().parse::<u32>() {
        // Send SIGTERM using the kill command (safe, no unsafe blocks)
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Clean up files
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&socket_path);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "stopped",
            }))?
        );
    } else {
        println!("Agent stopped.");
    }

    Ok(())
}

/// Show agent status.
fn run_status(vault_path: &str, json: bool) -> anyhow::Result<()> {
    let socket_path = agent_socket_path(vault_path);
    let pid_path = agent_pid_path(vault_path);
    let running = is_agent_running(vault_path);

    let pid = if pid_path.exists() {
        std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    } else {
        None
    };

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

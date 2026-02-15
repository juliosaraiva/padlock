//! Audit log viewer command.
//!
//! Reads the JSON Lines audit log and displays events with optional
//! filtering by time range, action type, or resource ID.

use clap::Args;
use padlock_core::audit::JsonLinesAuditLog;
use padlock_core::types::{AuditAction, AuditEvent};

use crate::output::OutputFormatter;

/// View the vault audit log.
#[derive(Debug, Args)]
pub struct AuditCmd {
    /// Show events from the last duration (e.g., "1h", "24h", "7d").
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by action type (e.g., "vault-init", "entry-read").
    #[arg(long)]
    pub action: Option<String>,

    /// Filter by resource ID.
    #[arg(long)]
    pub entry: Option<String>,
}

/// Run the audit command.
pub fn run(cmd: AuditCmd, vault_path: &str, fmt: &OutputFormatter) -> anyhow::Result<()> {
    let padlock_dir = super::resolve_vault_path(vault_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".padlock"));

    let audit_path = padlock_dir.join("audit.jsonl");
    let log = JsonLinesAuditLog::new(&audit_path)?;
    let events = log.read_events()?;

    let cutoff = parse_since(&cmd.since)?;
    let action_filter = cmd.action.as_deref().map(parse_action).transpose()?;

    let filtered: Vec<&AuditEvent> = events
        .iter()
        .filter(|e| {
            if let Some(cutoff_ts) = cutoff {
                if e.timestamp.as_epoch_secs() < cutoff_ts {
                    return false;
                }
            }
            if let Some(ref action) = action_filter {
                if &e.action != action {
                    return false;
                }
            }
            if let Some(ref entry_id) = cmd.entry {
                match &e.resource_id {
                    Some(rid) => {
                        if rid != entry_id {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            true
        })
        .collect();

    if fmt.is_json() {
        fmt.json_list(&filtered);
        return Ok(());
    }

    if fmt.is_quiet() {
        for event in &filtered {
            println!("{}", format_action(&event.action));
        }
        return Ok(());
    }

    // Human-readable table output
    if filtered.is_empty() {
        fmt.success("No audit events found matching the filters.");
        return Ok(());
    }

    fmt.table_header(&["TIMESTAMP", "ACTION", "RESULT", "RESOURCE"]);
    for event in &filtered {
        let ts = format_timestamp(event.timestamp.as_epoch_secs());
        let action = format_action(&event.action);
        let result = match event.result {
            padlock_core::types::AuditResult::Success => "ok",
            padlock_core::types::AuditResult::Failure => "FAIL",
        };
        let resource = event.resource_id.as_deref().unwrap_or("-");
        fmt.table_row(&[&ts, &action, result, resource]);
    }

    Ok(())
}

/// Parse a duration string like "1h", "24h", "7d" into an epoch-seconds cutoff.
fn parse_since(since: &Option<String>) -> anyhow::Result<Option<i64>> {
    let since = match since {
        Some(s) => s,
        None => return Ok(None),
    };

    let (num_str, multiplier) = if let Some(n) = since.strip_suffix('d') {
        (n, 86400i64)
    } else if let Some(n) = since.strip_suffix('h') {
        (n, 3600i64)
    } else if let Some(n) = since.strip_suffix('m') {
        (n, 60i64)
    } else {
        return Err(anyhow::anyhow!(
            "invalid duration format '{}': expected e.g. '1h', '24h', '7d'",
            since
        ));
    };

    let num: i64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid number in duration '{}'", since))?;

    let now = chrono::Utc::now().timestamp();
    Ok(Some(now - num * multiplier))
}

/// Parse a CLI action string to an `AuditAction`.
fn parse_action(s: &str) -> anyhow::Result<AuditAction> {
    match s {
        "vault-init" => Ok(AuditAction::VaultInit),
        "vault-unlock" => Ok(AuditAction::VaultUnlock),
        "vault-lock" => Ok(AuditAction::VaultLock),
        "vault-passphrase-change" => Ok(AuditAction::VaultPassphraseChange),
        "entry-create" => Ok(AuditAction::EntryCreate),
        "entry-read" => Ok(AuditAction::EntryRead),
        "entry-update" => Ok(AuditAction::EntryUpdate),
        "entry-delete" => Ok(AuditAction::EntryDelete),
        "ssh-sign" => Ok(AuditAction::SshSign),
        "ssh-list-keys" => Ok(AuditAction::SshListKeys),
        "git-sign" => Ok(AuditAction::GitSign),
        "session-create" => Ok(AuditAction::SessionCreate),
        "session-resume" => Ok(AuditAction::SessionResume),
        "session-destroy" => Ok(AuditAction::SessionDestroy),
        "session-expired" => Ok(AuditAction::SessionExpired),
        "session-invalid-token" => Ok(AuditAction::SessionInvalidToken),
        _ => Err(anyhow::anyhow!(
            "unknown audit action '{}'. Valid actions: vault-init, vault-unlock, vault-lock, \
             vault-passphrase-change, entry-create, entry-read, entry-update, entry-delete, \
             ssh-sign, ssh-list-keys, git-sign, session-create, session-resume, \
             session-destroy, session-expired, session-invalid-token",
            s
        )),
    }
}

/// Format an `AuditAction` as a kebab-case string.
fn format_action(action: &AuditAction) -> &'static str {
    match action {
        AuditAction::VaultInit => "vault-init",
        AuditAction::VaultUnlock => "vault-unlock",
        AuditAction::VaultLock => "vault-lock",
        AuditAction::VaultPassphraseChange => "vault-passphrase-change",
        AuditAction::EntryCreate => "entry-create",
        AuditAction::EntryRead => "entry-read",
        AuditAction::EntryUpdate => "entry-update",
        AuditAction::EntryDelete => "entry-delete",
        AuditAction::SshSign => "ssh-sign",
        AuditAction::SshListKeys => "ssh-list-keys",
        AuditAction::GitSign => "git-sign",
        AuditAction::SessionCreate => "session-create",
        AuditAction::SessionResume => "session-resume",
        AuditAction::SessionDestroy => "session-destroy",
        AuditAction::SessionExpired => "session-expired",
        AuditAction::SessionInvalidToken => "session-invalid-token",
    }
}

/// Format a Unix timestamp as a human-readable datetime string.
fn format_timestamp(epoch_secs: i64) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_opt(epoch_secs, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        _ => epoch_secs.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_since_hours() {
        let result = parse_since(&Some("24h".to_string())).unwrap();
        assert!(result.is_some());
        let cutoff = result.unwrap();
        let now = chrono::Utc::now().timestamp();
        // Should be approximately 24 hours ago
        assert!((now - cutoff - 86400).abs() < 2);
    }

    #[test]
    fn test_parse_since_days() {
        let result = parse_since(&Some("7d".to_string())).unwrap();
        assert!(result.is_some());
        let cutoff = result.unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!((now - cutoff - 604800).abs() < 2);
    }

    #[test]
    fn test_parse_since_minutes() {
        let result = parse_since(&Some("30m".to_string())).unwrap();
        assert!(result.is_some());
        let cutoff = result.unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!((now - cutoff - 1800).abs() < 2);
    }

    #[test]
    fn test_parse_since_none() {
        let result = parse_since(&None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_since_invalid() {
        let result = parse_since(&Some("abc".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_action_valid() {
        assert_eq!(parse_action("vault-init").unwrap(), AuditAction::VaultInit);
        assert_eq!(parse_action("entry-read").unwrap(), AuditAction::EntryRead);
        assert_eq!(parse_action("git-sign").unwrap(), AuditAction::GitSign);
    }

    #[test]
    fn test_parse_action_invalid() {
        assert!(parse_action("unknown-action").is_err());
    }

    #[test]
    fn test_format_action_round_trip() {
        let actions = vec![
            AuditAction::VaultInit,
            AuditAction::EntryRead,
            AuditAction::SshSign,
            AuditAction::SessionCreate,
        ];
        for action in actions {
            let s = format_action(&action);
            let parsed = parse_action(s).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn test_format_timestamp() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let formatted = format_timestamp(1_704_067_200);
        assert_eq!(formatted, "2024-01-01 00:00:00 UTC");
    }
}

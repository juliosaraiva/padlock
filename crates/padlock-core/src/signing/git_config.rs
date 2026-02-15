//! Git configuration management for SSH signing.
//!
//! Provides functions to configure Git for SSH-based commit and tag signing,
//! read existing Git configuration, and verify commit signatures using
//! the `git` and `ssh-keygen` command-line tools.

use crate::error::{Error, SigningError};

/// Scope of a Git configuration change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitConfigScope {
    /// Apply to the global `~/.gitconfig`.
    Global,
    /// Apply to the current repository's `.git/config`.
    Local,
}

impl GitConfigScope {
    /// Return the `git config` flag for this scope.
    #[must_use]
    pub fn flag(&self) -> &str {
        match self {
            Self::Global => "--global",
            Self::Local => "--local",
        }
    }
}

/// Configure Git to use SSH signing.
///
/// Sets the following Git configuration values:
/// - `gpg.format = ssh`
/// - `user.signingKey = <public_key_path>`
/// - `gpg.ssh.allowedSignersFile = <allowed_signers_path>`
/// - `commit.gpgSign = true`
/// - `tag.gpgSign = true`
///
/// # Errors
///
/// Returns an error if `git config` commands fail.
pub fn setup_git_ssh_signing(
    scope: GitConfigScope,
    public_key_path: &str,
    allowed_signers_path: &str,
) -> crate::error::Result<Vec<String>> {
    let flag = scope.flag();
    let mut changes = Vec::new();

    let configs = [
        ("gpg.format", "ssh"),
        ("user.signingKey", public_key_path),
        ("gpg.ssh.allowedSignersFile", allowed_signers_path),
        ("commit.gpgSign", "true"),
        ("tag.gpgSign", "true"),
    ];

    for (key, value) in &configs {
        run_git_config(flag, key, value)?;
        changes.push(format!("{key} = {value}"));
    }

    Ok(changes)
}

/// Run a `git config` command to set a value.
fn run_git_config(scope_flag: &str, key: &str, value: &str) -> crate::error::Result<()> {
    let output = std::process::Command::new("git")
        .arg("config")
        .arg(scope_flag)
        .arg(key)
        .arg(value)
        .output()
        .map_err(|e| Error::Signing(SigningError::Failed(format!("failed to run git config: {e}"))))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Signing(SigningError::Failed(format!(
            "git config {key} failed: {stderr}"
        ))));
    }

    Ok(())
}

/// Read a Git configuration value.
///
/// Returns `None` if the key is not set.
///
/// # Errors
///
/// Returns an error if the `git config` command fails unexpectedly.
pub fn get_git_config(key: &str) -> crate::error::Result<Option<String>> {
    let output = std::process::Command::new("git")
        .arg("config")
        .arg("--get")
        .arg(key)
        .output()
        .map_err(|e| Error::Signing(SigningError::Failed(format!("failed to run git config: {e}"))))?;

    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(Some(value))
    } else {
        // Exit code 1 means the key is not set
        Ok(None)
    }
}

/// Verify a Git commit signature.
///
/// Uses `git verify-commit` to check the signature of the specified commit.
///
/// # Errors
///
/// Returns an error if the `git` command cannot be executed.
pub fn verify_commit(commit_hash: &str) -> crate::error::Result<super::VerifyResult> {
    let output = std::process::Command::new("git")
        .arg("verify-commit")
        .arg("--raw")
        .arg(commit_hash)
        .output()
        .map_err(|e| {
            Error::Signing(SigningError::Failed(format!(
                "failed to run git verify-commit: {e}"
            )))
        })?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        Ok(super::VerifyResult::Valid {
            fingerprint: extract_fingerprint(&combined),
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(super::VerifyResult::Invalid {
            reason: stderr.trim().to_string(),
        })
    }
}

/// Extract a key fingerprint from Git verify output.
fn extract_fingerprint(output: &str) -> String {
    // Look for SHA256:... pattern in the output
    for word in output.split_whitespace() {
        if word.starts_with("SHA256:") {
            return word.to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_config_scope_flags() {
        assert_eq!(GitConfigScope::Global.flag(), "--global");
        assert_eq!(GitConfigScope::Local.flag(), "--local");
    }

    #[test]
    fn test_extract_fingerprint_found() {
        let output = "Good signature by key SHA256:abc123def456 from user@example.com";
        assert_eq!(extract_fingerprint(output), "SHA256:abc123def456");
    }

    #[test]
    fn test_extract_fingerprint_not_found() {
        let output = "Some output without fingerprint";
        assert_eq!(extract_fingerprint(output), "unknown");
    }

    #[test]
    fn test_get_git_config_nonexistent_key() {
        // This should return None for a key that doesn't exist
        let result = get_git_config("padlock.test.nonexistent.key.12345");
        // This may fail if git is not installed, which is fine for CI
        if let Ok(value) = result {
            assert!(value.is_none());
        }
    }
}

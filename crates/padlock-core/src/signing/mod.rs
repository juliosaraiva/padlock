//! Git SSH signing for commits and tags.
//!
//! Implements signature generation and verification for use with Git's
//! SSH signing configuration. This module provides the core signing
//! operations while the CLI handles Git integration plumbing.
//!
//! # Git Configuration
//!
//! ```text
//! git config --global gpg.format ssh
//! git config --global gpg.ssh.program "padlock git sign"
//! git config --global gpg.ssh.allowedSignersFile ~/.config/padlock/allowed_signers
//! ```

pub mod git_config;

use crate::error::{Error, SigningError};

/// Namespace used for Git commit signing in the SSH signature format.
pub const GIT_NAMESPACE: &str = "git";

/// Result of a signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Signature is valid.
    Valid {
        /// The fingerprint of the signing key.
        fingerprint: String,
    },
    /// Signature is invalid.
    Invalid {
        /// Reason for invalidity.
        reason: String,
    },
}

/// An entry in the allowed_signers file.
#[derive(Debug, Clone)]
pub struct AllowedSigner {
    /// Email or identity pattern.
    pub principal: String,
    /// SSH public key.
    pub public_key: String,
}

/// Generate an allowed_signers file content from a list of signers.
///
/// The allowed_signers file is used by Git to verify SSH signatures.
/// Each line has the format: `<principal> <key-type> <base64-key>`
#[must_use]
pub fn generate_allowed_signers(signers: &[AllowedSigner]) -> String {
    signers
        .iter()
        .map(|s| format!("{} {}", s.principal, s.public_key))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse an allowed_signers file.
///
/// # Errors
///
/// Returns `SigningError::Failed` if the file format is invalid.
pub fn parse_allowed_signers(content: &str) -> crate::error::Result<Vec<AllowedSigner>> {
    let mut signers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err(Error::Signing(SigningError::Failed(format!(
                "invalid allowed_signers line: {line}"
            ))));
        }
        signers.push(AllowedSigner {
            principal: parts[0].to_string(),
            public_key: parts[1].to_string(),
        });
    }
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_allowed_signers() {
        let signers = vec![AllowedSigner {
            principal: "user@example.com".to_string(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".to_string(),
        }];
        let output = generate_allowed_signers(&signers);
        assert!(output.contains("user@example.com"));
        assert!(output.contains("ssh-ed25519"));
    }

    #[test]
    fn test_parse_allowed_signers() {
        let content = "user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n# comment\n\nadmin@host ssh-rsa AAAA...";
        let signers = parse_allowed_signers(content).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0].principal, "user@example.com");
        assert_eq!(signers[1].principal, "admin@host");
    }

    #[test]
    fn test_parse_allowed_signers_empty() {
        let content = "# only comments\n\n";
        let signers = parse_allowed_signers(content).unwrap();
        assert!(signers.is_empty());
    }

    #[test]
    fn test_git_namespace_constant() {
        assert_eq!(GIT_NAMESPACE, "git");
    }
}

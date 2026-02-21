//! Configuration types for the Padlock credential manager.
//!
//! Configuration is loaded from `~/.padlock/config.toml`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::session::types::{parse_idle_timeout, SessionDuration, DEFAULT_IDLE_TIMEOUT};

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Session caching configuration.
    #[serde(default)]
    pub session: SessionConfig,
}

/// Configuration for the session caching mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session duration (e.g., "1h", "4h", "24h").
    #[serde(default = "default_duration")]
    pub duration: String,

    /// Idle timeout — session expires if unused for this long (e.g., "15m", "30m", "1h").
    /// Reset on each use, like gpg-agent's `default-cache-ttl`.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,

    /// Maximum number of concurrent sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Automatically create a session on unlock.
    #[serde(default = "default_auto_session")]
    pub auto_session: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            duration: default_duration(),
            idle_timeout: default_idle_timeout(),
            max_sessions: default_max_sessions(),
            auto_session: default_auto_session(),
        }
    }
}

impl SessionConfig {
    /// Parse the configured duration into a `SessionDuration`.
    ///
    /// Falls back to `OneHour` if the configured value is invalid.
    #[must_use]
    pub fn parsed_duration(&self) -> SessionDuration {
        SessionDuration::from_str_label(&self.duration).unwrap_or(SessionDuration::OneHour)
    }

    /// Parse the configured idle timeout into a `Duration`.
    ///
    /// Falls back to `DEFAULT_IDLE_TIMEOUT` (15 minutes) if the value is invalid.
    #[must_use]
    pub fn parsed_idle_timeout(&self) -> Duration {
        parse_idle_timeout(&self.idle_timeout).unwrap_or(DEFAULT_IDLE_TIMEOUT)
    }
}

fn default_duration() -> String {
    "1h".to_string()
}

fn default_idle_timeout() -> String {
    "15m".to_string()
}

fn default_max_sessions() -> usize {
    3
}

fn default_auto_session() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.session.duration, "1h");
        assert_eq!(config.session.idle_timeout, "15m");
        assert_eq!(config.session.max_sessions, 3);
        assert!(config.session.auto_session);
    }

    #[test]
    fn test_parse_config_from_toml() {
        let toml_str = r#"
[session]
duration = "4h"
idle_timeout = "30m"
max_sessions = 5
auto_session = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.session.duration, "4h");
        assert_eq!(config.session.idle_timeout, "30m");
        assert_eq!(config.session.max_sessions, 5);
        assert!(!config.session.auto_session);
    }

    #[test]
    fn test_parsed_duration_valid() {
        let config = SessionConfig {
            duration: "8h".to_string(),
            ..Default::default()
        };
        assert_eq!(config.parsed_duration(), SessionDuration::EightHours);
    }

    #[test]
    fn test_parsed_duration_invalid_fallback() {
        let config = SessionConfig {
            duration: "99h".to_string(),
            ..Default::default()
        };
        assert_eq!(config.parsed_duration(), SessionDuration::OneHour);
    }

    #[test]
    fn test_parsed_idle_timeout_valid() {
        let config = SessionConfig {
            idle_timeout: "30m".to_string(),
            ..Default::default()
        };
        assert_eq!(config.parsed_idle_timeout(), Duration::from_secs(1800));
    }

    #[test]
    fn test_parsed_idle_timeout_invalid_fallback() {
        let config = SessionConfig {
            idle_timeout: "99m".to_string(),
            ..Default::default()
        };
        assert_eq!(config.parsed_idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    }

    #[test]
    fn test_empty_toml_uses_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.session.duration, "1h");
        assert_eq!(config.session.idle_timeout, "15m");
        assert_eq!(config.session.max_sessions, 3);
        assert!(config.session.auto_session);
    }
}

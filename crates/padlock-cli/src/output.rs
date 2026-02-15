//! Output formatting for the Padlock CLI.
//!
//! Provides a unified `OutputFormatter` that respects `--json`, `--quiet`,
//! and `--no-color` flags. All CLI commands should use this formatter
//! instead of calling `println!` directly.

use colored::Colorize;
use serde::Serialize;

/// Output mode selected by the user via CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Human-readable output with optional color (default).
    Human,
    /// Structured JSON output for scripting.
    Json,
    /// Minimal output -- only values, no decoration.
    Quiet,
}

/// Formats CLI output according to the selected mode.
///
/// Constructed from CLI flags and threaded through commands.
#[derive(Debug, Clone)]
pub struct OutputFormatter {
    mode: OutputMode,
}

impl OutputFormatter {
    /// Create a formatter from CLI flags.
    ///
    /// Priority: `--quiet` > `--json` > default human mode.
    /// If `--no-color` is set, colored output is globally disabled.
    #[must_use]
    pub fn new(json: bool, quiet: bool, no_color: bool) -> Self {
        if no_color {
            colored::control::set_override(false);
        }

        let mode = if quiet {
            OutputMode::Quiet
        } else if json {
            OutputMode::Json
        } else {
            OutputMode::Human
        };

        Self { mode }
    }

    /// Get the current output mode.
    #[must_use]
    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Print a success message. Suppressed in quiet mode; wrapped in
    /// JSON in json mode.
    pub fn success(&self, msg: &str) {
        match self.mode {
            OutputMode::Human => {
                println!("{} {msg}", "ok:".green().bold());
            }
            OutputMode::Json => {
                println!(
                    "{}",
                    serde_json::json!({"status": "ok", "message": msg})
                );
            }
            OutputMode::Quiet => {}
        }
    }

    /// Print an error message to stderr. Always printed (even in quiet mode)
    /// because errors should not be silently swallowed.
    pub fn error(&self, msg: &str) {
        match self.mode {
            OutputMode::Human => {
                eprintln!("{} {msg}", "error:".red().bold());
            }
            OutputMode::Json => {
                eprintln!(
                    "{}",
                    serde_json::json!({"status": "error", "message": msg})
                );
            }
            OutputMode::Quiet => {
                eprintln!("{msg}");
            }
        }
    }

    /// Print a warning message to stderr.
    pub fn warning(&self, msg: &str) {
        match self.mode {
            OutputMode::Human => {
                eprintln!("{} {msg}", "warning:".yellow().bold());
            }
            OutputMode::Json => {
                eprintln!(
                    "{}",
                    serde_json::json!({"status": "warning", "message": msg})
                );
            }
            OutputMode::Quiet => {}
        }
    }

    /// Print a key-value pair. In quiet mode, only the value is printed.
    pub fn key_value(&self, key: &str, value: &str) {
        match self.mode {
            OutputMode::Human => {
                println!("{}: {value}", key.cyan().bold());
            }
            OutputMode::Json => {
                println!("{}", serde_json::json!({key: value}));
            }
            OutputMode::Quiet => {
                println!("{value}");
            }
        }
    }

    /// Print a serializable value as JSON. Only meaningful in JSON mode;
    /// in other modes this is a no-op (use specific methods instead).
    pub fn json<T: Serialize>(&self, value: &T) {
        if self.mode == OutputMode::Json {
            if let Ok(json) = serde_json::to_string(value) {
                println!("{json}");
            }
        }
    }

    /// Print a list of serializable items as a JSON array.
    pub fn json_list<T: Serialize>(&self, items: &[T]) {
        if self.mode == OutputMode::Json {
            if let Ok(json) = serde_json::to_string(items) {
                println!("{json}");
            }
        }
    }

    /// Print a human-readable table header. No-op in JSON/quiet modes.
    pub fn table_header(&self, columns: &[&str]) {
        if self.mode == OutputMode::Human {
            let header: Vec<String> = columns
                .iter()
                .map(|c| c.bold().underline().to_string())
                .collect();
            println!("{}", header.join("  "));
        }
    }

    /// Print a human-readable table row. No-op in JSON/quiet modes.
    pub fn table_row(&self, values: &[&str]) {
        if self.mode == OutputMode::Human {
            println!("{}", values.join("  "));
        }
    }

    /// Returns true if output should be suppressed (quiet mode).
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.mode == OutputMode::Quiet
    }

    /// Returns true if output should be JSON.
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.mode == OutputMode::Json
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_mode_priority_quiet_over_json() {
        let fmt = OutputFormatter::new(true, true, false);
        assert_eq!(fmt.mode(), OutputMode::Quiet);
    }

    #[test]
    fn test_output_mode_json() {
        let fmt = OutputFormatter::new(true, false, false);
        assert_eq!(fmt.mode(), OutputMode::Json);
    }

    #[test]
    fn test_output_mode_human_default() {
        let fmt = OutputFormatter::new(false, false, false);
        assert_eq!(fmt.mode(), OutputMode::Human);
    }

    #[test]
    fn test_is_quiet() {
        let fmt = OutputFormatter::new(false, true, false);
        assert!(fmt.is_quiet());
        assert!(!fmt.is_json());
    }

    #[test]
    fn test_is_json() {
        let fmt = OutputFormatter::new(true, false, false);
        assert!(fmt.is_json());
        assert!(!fmt.is_quiet());
    }
}

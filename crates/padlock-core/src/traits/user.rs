//! User confirmation trait for interactive prompts.
//!
//! This trait abstracts user interaction, allowing the core library
//! to request passwords, confirmations, and display messages without
//! depending on any specific UI framework.

use crate::error::Result;

/// Abstraction over user interaction for vault operations.
///
/// The core library uses this trait to request passphrases, confirmations,
/// and display messages. This decouples domain logic from CLI, TUI, or
/// GUI implementations.
///
/// # Implementors
///
/// - `CliPrompt` (padlock-cli): interactive terminal prompts
/// - `NonInteractivePrompt` (scripting): fixed responses for automation
/// - `TestPrompt` (testing): predetermined responses for tests
pub trait UserConfirmation: Send + Sync {
    /// Prompt the user for a password.
    ///
    /// The implementation should not echo the password to the terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt cannot be displayed or input cannot be read.
    fn prompt_password(&self, prompt: &str) -> Result<String>;

    /// Prompt the user for a yes/no confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt cannot be displayed or input cannot be read.
    fn prompt_yes_no(&self, prompt: &str) -> Result<bool>;

    /// Display a message to the user.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be displayed.
    fn show_message(&self, message: &str) -> Result<()>;
}

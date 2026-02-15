//! Session caching mechanism for the Padlock daemon.
//!
//! After one successful passphrase entry, the derived KEK is securely
//! cached in the agent daemon's memory for a user-configurable duration.
//! Subsequent CLI commands skip passphrase re-entry by requesting the
//! cached KEK from the daemon over the Unix socket with ephemeral
//! transit encryption.
//!
//! # Security Properties
//!
//! - KEK never in plaintext on the socket — ephemeral X25519 + XChaCha20-Poly1305
//! - KEK never in plaintext at rest in daemon — wrapped by SEK in mlock'd memory
//! - Session token comparison is constant-time
//! - Expiry uses `std::time::Instant` (monotonic clock)
//! - Maximum duration enforced by `SessionDuration` enum
//! - Daemon crash destroys all sessions — no persistent state

pub mod manager;
pub mod protocol;
pub mod transit;
pub mod types;

pub use manager::SessionStore;
pub use types::{
    Session, SessionAlgorithm, SessionDuration, SessionInfo, SessionToken, SESSION_TOKEN_SIZE,
};

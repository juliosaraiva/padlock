//! Vault lifecycle management and file format handling.
//!
//! This module implements the vault binary file format, state machine
//! (Locked/Unlocked), atomic file writes, and all vault operations
//! including init, open, lock, close, and passphrase change.
//!
//! # Vault File Structure
//!
//! ```text
//! [Header (1024 bytes)] [Index (variable)] [Entries (variable)] [HMAC (32 bytes)]
//! ```
//!
//! # State Machine
//!
//! ```text
//! [Init] --> Locked --open()--> Unlocked --lock()--> Locked
//! ```

pub mod atomic;
pub mod entries;
pub mod format;
pub mod lifecycle;
pub mod storage;

pub use format::{VaultHeader, VaultIndex, EntryMetadata};
pub use lifecycle::{KdfParams, Vault, VaultState};

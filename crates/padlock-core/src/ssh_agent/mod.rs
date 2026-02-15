//! SSH agent protocol implementation.
//!
//! Implements a subset of the SSH agent protocol for serving vault
//! keys to SSH clients via a Unix domain socket. Supports key listing,
//! signing requests, and agent lifecycle management.
//!
//! # Modules
//!
//! - [`protocol`]: Wire format parsing and serialization.
//! - [`handler`]: Request dispatch and signing logic.
//!
//! # Protocol
//!
//! Messages follow the OpenSSH agent protocol format:
//! ```text
//! [uint32: length] [byte: type] [payload...]
//! ```

pub mod handler;
pub mod protocol;

pub use handler::{AgentHandler, LoadedKey};
pub use protocol::{AgentMessage, AgentResponse, parse_message, serialize_response};

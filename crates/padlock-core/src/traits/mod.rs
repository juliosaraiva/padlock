//! Trait definitions for domain-driven design abstraction boundaries.
//!
//! These traits decouple the core domain logic from external systems
//! such as filesystems, platform keyrings, user interfaces, and network
//! transports. This enables testing with mock implementations and
//! supports multiple frontend adapters.

pub mod audit;
pub mod keyring;
pub mod session;
pub mod storage;
pub mod sync;
pub mod user;

pub use audit::AuditLogger;
pub use keyring::PlatformKeyring;
pub use session::SessionManager;
pub use storage::StorageBackend;
pub use sync::SyncTransport;
pub use user::UserConfirmation;

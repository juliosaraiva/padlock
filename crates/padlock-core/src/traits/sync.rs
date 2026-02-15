//! Sync transport trait for cross-device vault synchronization.
//!
//! This module defines the trait for vault sync, which is deferred to v1.1.
//! The trait is defined early to establish the architectural boundary and
//! allow the vault module to be designed with sync in mind.

use crate::error::Result;

/// Abstraction over vault synchronization transport.
///
/// This trait will be implemented in v1.1 for cloud, peer-to-peer,
/// or other sync backends. It is defined now to establish the interface
/// contract and prevent architectural lock-in.
///
/// # Deferred
///
/// All implementations are deferred to v1.1. The MVP does not include
/// any sync functionality.
pub trait SyncTransport: Send + Sync {
    /// Pull the latest vault data from the remote.
    ///
    /// # Errors
    ///
    /// Returns an error if the pull fails or the remote is unreachable.
    fn pull(&self) -> Result<Vec<u8>>;

    /// Push local vault data to the remote.
    ///
    /// # Errors
    ///
    /// Returns an error if the push fails or the remote is unreachable.
    fn push(&self, data: &[u8]) -> Result<()>;

    /// Get the remote vault version for conflict detection.
    ///
    /// # Errors
    ///
    /// Returns an error if the version cannot be retrieved.
    fn get_remote_version(&self) -> Result<u64>;
}

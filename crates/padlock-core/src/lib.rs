//! Padlock Core Library
//!
//! This is the domain library for the Padlock credential manager. It implements
//! all cryptographic operations, vault management, entry handling, and protocol
//! logic. This crate has no dependencies on terminal I/O, filesystem specifics,
//! or platform APIs -- those are abstracted behind traits.
//!
//! # Architecture
//!
//! Padlock follows Domain-Driven Design (DDD) principles:
//!
//! - **`crypto`**: Encryption, KDF, HMAC, key hierarchy, secure memory
//! - **`vault`**: Vault file format, lifecycle (init/open/lock/close), atomic writes
//! - **`entries`**: Entry types, CRUD operations, serialization
//! - **`ssh_agent`**: SSH agent protocol handler
//! - **`signing`**: Git commit/tag signing via SSH keys
//! - **`audit`**: Tamper-evident audit log
//! - **`generate`**: Password, TOTP secret, and SSH key generation
//! - **`traits`**: Abstraction boundaries (storage, keyring, user interaction)
//! - **`types`**: Shared domain types (Entry, `SecretBuf`, identifiers)
//!
//! # Security Priority
//!
//! Security > Correctness > Performance > Usability

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]

pub mod audit;
pub mod config;
pub mod crypto;
pub mod entries;
pub mod error;
pub mod generate;
pub mod session;
pub mod signing;
pub mod ssh_agent;
pub mod sync;
pub mod traits;
pub mod types;
pub mod vault;

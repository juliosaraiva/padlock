//! Credential entry types, CRUD operations, and serialization.
//!
//! This module defines the entry types (Credential, `SSHKey`, TOTP, etc.),
//! their `MessagePack` serialization, and CRUD operations for managing
//! entries within an unlocked vault.

pub mod crud;
pub mod serialize;
pub mod types;

pub use crud::{
    create_entry, delete_entry, list_entries, read_entry, search_by_name, search_by_tag,
    update_entry,
};
pub use serialize::{deserialize_entry, serialize_entry};
pub use types::{Entry, EntryData, EntryMeta, EntryType, SSHKeyType, TOTPAlgorithm};

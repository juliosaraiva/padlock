//! CRUD operations for vault entries.
//!
//! Provides create, read, update, and delete operations that manage
//! entries within an unlocked vault.

use crate::entries::serialize::{deserialize_entry, serialize_entry};
use crate::entries::types::{Entry, EntryData};
use crate::error::{EntryError, Error, VaultError};
use crate::types::{EntryId, Timestamp};
use crate::vault::format::EntryMetadata;
use crate::vault::lifecycle::Vault;

/// Create a new entry in the vault.
///
/// Encrypts the entry and appends it to the vault entries blob.
/// Updates the vault index with the new entry metadata.
///
/// # Errors
///
/// Returns `VaultError::Locked` if the vault is not unlocked.
/// Returns `EntryError::AlreadyExists` if an entry with the same name exists.
pub fn create_entry(
    vault: &mut Vault,
    name: String,
    data: EntryData,
    tags: Vec<String>,
) -> crate::error::Result<Entry> {
    let kek = vault.kek()?;

    // Check for duplicate names
    for meta in vault.index().entries.values() {
        if !meta.deleted && meta.title == name {
            return Err(Error::Entry(EntryError::AlreadyExists { name }));
        }
    }

    let mut entry = Entry::new(name.clone(), data);
    entry.tags = tags.clone();

    // Serialize and encrypt
    let serialized = serialize_entry(&entry)?;
    let encrypted = crate::vault::entries::encrypt_entry(&serialized, &kek)?;

    // Append to entries blob in place (avoids full-blob copy)
    let (offset, length) = vault.append_to_entries_blob(&encrypted)?;

    // Update index
    let now = Timestamp::now().as_epoch_secs() as u64;
    let uuid = *entry.id.as_bytes();
    let index = vault.index_mut()?;
    index.entries.insert(
        uuid,
        EntryMetadata {
            uuid,
            entry_offset: offset,
            entry_length: length,
            created_at: now,
            modified_at: now,
            deleted: false,
            title: name,
            tags: tags.clone(),
        },
    );

    // Maintain tag index
    index.add_tags(uuid, &tags);

    Ok(entry)
}

/// Read an entry from the vault by its ID.
///
/// Decrypts the entry data and returns the full Entry struct.
///
/// # Errors
///
/// Returns `EntryError::NotFound` if the entry does not exist.
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn read_entry(vault: &Vault, id: &EntryId) -> crate::error::Result<Entry> {
    let kek = vault.kek()?;
    let uuid = *id.as_bytes();

    let meta = vault
        .index()
        .entries
        .get(&uuid)
        .filter(|m| !m.deleted)
        .ok_or_else(|| Error::Entry(EntryError::NotFound { id: id.to_string() }))?;

    let offset = meta.entry_offset as usize;
    let length = meta.entry_length as usize;
    let blob = vault.entries_blob();

    if offset + length > blob.len() {
        return Err(Error::Vault(VaultError::CorruptedData));
    }

    let encrypted = &blob[offset..offset + length];
    let decrypted = crate::vault::entries::decrypt_entry(encrypted, kek)?;
    deserialize_entry(&decrypted)
}

/// Update an existing entry in the vault.
///
/// Replaces the entry data, increments the version, and re-encrypts.
///
/// # Errors
///
/// Returns `EntryError::NotFound` if the entry does not exist.
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn update_entry(
    vault: &mut Vault,
    id: &EntryId,
    new_data: EntryData,
) -> crate::error::Result<Entry> {
    let mut entry = read_entry(vault, id)?;
    entry.data = new_data;
    entry.bump_version();

    let kek = vault.kek()?;

    // Re-serialize and encrypt
    let serialized = serialize_entry(&entry)?;
    let encrypted = crate::vault::entries::encrypt_entry(&serialized, &kek)?;

    // Append new version to blob in place (old data becomes dead space)
    let (offset, length) = vault.append_to_entries_blob(&encrypted)?;

    // Update index and tag index
    let uuid = *id.as_bytes();
    let new_tags = entry.tags.clone();

    let index = vault.index_mut()?;

    // Extract old tags first to avoid borrow conflict
    let old_tags = index
        .entries
        .get(&uuid)
        .map(|m| m.tags.clone())
        .unwrap_or_default();
    index.remove_tags(&uuid, &old_tags);

    if let Some(meta) = index.entries.get_mut(&uuid) {
        meta.entry_offset = offset;
        meta.entry_length = length;
        meta.modified_at = Timestamp::now().as_epoch_secs() as u64;
        meta.tags = new_tags.clone();
    }

    index.add_tags(uuid, &new_tags);

    Ok(entry)
}

/// Delete an entry from the vault.
///
/// Marks the entry as deleted in the index. The encrypted data
/// remains in the blob until the vault is compacted.
///
/// # Errors
///
/// Returns `EntryError::NotFound` if the entry does not exist.
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn delete_entry(vault: &mut Vault, id: &EntryId) -> crate::error::Result<()> {
    let uuid = *id.as_bytes();

    let index = vault.index_mut()?;
    let meta = index
        .entries
        .get_mut(&uuid)
        .filter(|m| !m.deleted)
        .ok_or_else(|| Error::Entry(EntryError::NotFound { id: id.to_string() }))?;

    meta.deleted = true;
    meta.modified_at = Timestamp::now().as_epoch_secs() as u64;

    // Remove from tag index
    let tags = meta.tags.clone();
    index.remove_tags(&uuid, &tags);
    Ok(())
}

/// List all active (non-deleted) entry summaries from the index.
///
/// Returns entry metadata without decrypting entry data.
/// For full entry data, use `read_entry` on individual entries.
///
/// # Errors
///
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn list_entries(vault: &Vault) -> crate::error::Result<Vec<(EntryId, String)>> {
    // Verify vault is unlocked
    let _ = vault.kek()?;
    let entries: Vec<_> = vault
        .index()
        .entries
        .values()
        .filter(|m| !m.deleted)
        .map(|m| {
            (
                EntryId::from_uuid(uuid::Uuid::from_bytes(m.uuid)),
                m.title.clone(),
            )
        })
        .collect();
    Ok(entries)
}

/// Case-insensitive substring check without allocating.
///
/// Uses ASCII case folding, which is sufficient for entry titles.
fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle_bytes: Vec<u8> = needle.bytes().map(|b| b.to_ascii_lowercase()).collect();
    haystack
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|window| {
            window
                .iter()
                .zip(needle_bytes.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
}

/// Search entries by name (case-insensitive substring match).
///
/// # Errors
///
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn search_by_name(vault: &Vault, query: &str) -> crate::error::Result<Vec<Entry>> {
    let kek = vault.kek()?;
    let mut results = Vec::new();

    for meta in vault.index().entries.values() {
        if meta.deleted {
            continue;
        }
        if contains_case_insensitive(&meta.title, query) {
            let offset = meta.entry_offset as usize;
            let length = meta.entry_length as usize;
            let blob = vault.entries_blob();
            if offset + length <= blob.len() {
                let encrypted = &blob[offset..offset + length];
                if let Ok(decrypted) = crate::vault::entries::decrypt_entry(encrypted, kek) {
                    if let Ok(entry) = deserialize_entry(&decrypted) {
                        results.push(entry);
                    }
                }
            }
        }
    }
    Ok(results)
}

/// Search entries by tag.
///
/// Uses the tag index for O(1) lookup if available, otherwise falls
/// back to decrypting entries. Tags are compared case-insensitively
/// using `eq_ignore_ascii_case` to avoid per-tag allocations.
///
/// # Errors
///
/// Returns `VaultError::Locked` if the vault is not unlocked.
pub fn search_by_tag(vault: &Vault, tag: &str) -> crate::error::Result<Vec<Entry>> {
    let kek = vault.kek()?;
    let tag_lower = tag.to_lowercase();

    // Fast path: use the tag index if available
    if !vault.index().tag_index.is_empty() {
        let uuids = match vault.index().tag_index.get(&tag_lower) {
            Some(ids) => ids.clone(),
            None => return Ok(Vec::new()),
        };

        let mut results = Vec::with_capacity(uuids.len());
        for uuid in &uuids {
            let meta = vault.index().entries.get(uuid);
            if let Some(m) = meta {
                if m.deleted {
                    continue;
                }
                let offset = m.entry_offset as usize;
                let length = m.entry_length as usize;
                let blob = vault.entries_blob();
                if offset + length <= blob.len() {
                    let encrypted = &blob[offset..offset + length];
                    if let Ok(decrypted) = crate::vault::entries::decrypt_entry(encrypted, kek) {
                        if let Ok(entry) = deserialize_entry(&decrypted) {
                            results.push(entry);
                        }
                    }
                }
            }
        }
        return Ok(results);
    }

    // Slow path: decrypt all entries and check tags
    let mut results = Vec::new();
    for meta in vault.index().entries.values() {
        if meta.deleted {
            continue;
        }
        let offset = meta.entry_offset as usize;
        let length = meta.entry_length as usize;
        let blob = vault.entries_blob();
        if offset + length <= blob.len() {
            let encrypted = &blob[offset..offset + length];
            if let Ok(decrypted) = crate::vault::entries::decrypt_entry(encrypted, kek) {
                if let Ok(entry) = deserialize_entry(&decrypted) {
                    if entry
                        .tags
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(&tag_lower))
                    {
                        results.push(entry);
                    }
                }
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::types::*;
    use crate::traits::storage::StorageBackend;
    use crate::vault::lifecycle::{KdfParams, Vault};

    struct InMemStorage {
        data: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl InMemStorage {
        fn new() -> Self {
            Self {
                data: std::sync::Mutex::new(None),
            }
        }
    }

    impl StorageBackend for InMemStorage {
        fn write_vault(&self, data: &[u8]) -> crate::error::Result<()> {
            *self.data.lock().unwrap() = Some(data.to_vec());
            Ok(())
        }
        fn read_vault(&self) -> crate::error::Result<Vec<u8>> {
            self.data.lock().unwrap().clone().ok_or_else(|| {
                Error::Vault(VaultError::NotFound {
                    path: "<mem>".to_string(),
                })
            })
        }
        fn vault_exists(&self) -> crate::error::Result<bool> {
            Ok(self.data.lock().unwrap().is_some())
        }
        fn write_backup(&self, _data: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
    }

    fn test_vault() -> (Vault, InMemStorage) {
        let storage = InMemStorage::new();
        let vault = Vault::init("test", &storage, &KdfParams::testing()).unwrap();
        (vault, storage)
    }

    #[test]
    fn test_create_and_read_credential() {
        let (mut vault, _storage) = test_vault();
        let entry = create_entry(
            &mut vault,
            "github".to_string(),
            EntryData::Credential {
                username: "user".to_string(),
                password: "pass".to_string(),
                url: None,
                notes: None,
            },
            vec!["dev".to_string()],
        )
        .unwrap();

        let read = read_entry(&vault, &entry.id).unwrap();
        assert_eq!(read.name, "github");
        assert_eq!(read.tags, vec!["dev"]);
        assert_eq!(read.version, 1);
    }

    #[test]
    fn test_create_duplicate_name_fails() {
        let (mut vault, _storage) = test_vault();
        create_entry(
            &mut vault,
            "dup".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        let result = create_entry(
            &mut vault,
            "dup".to_string(),
            EntryData::Credential {
                username: "u2".to_string(),
                password: "p2".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_update_entry_increments_version() {
        let (mut vault, _storage) = test_vault();
        let entry = create_entry(
            &mut vault,
            "test".to_string(),
            EntryData::Credential {
                username: "old".to_string(),
                password: "old-pass".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        let updated = update_entry(
            &mut vault,
            &entry.id,
            EntryData::Credential {
                username: "new".to_string(),
                password: "new-pass".to_string(),
                url: None,
                notes: None,
            },
        )
        .unwrap();

        assert_eq!(updated.version, 2);
    }

    #[test]
    fn test_delete_entry_removes_from_listing() {
        let (mut vault, _storage) = test_vault();
        let entry = create_entry(
            &mut vault,
            "delete-me".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        delete_entry(&mut vault, &entry.id).unwrap();
        let list = list_entries(&vault).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn test_read_deleted_entry_fails() {
        let (mut vault, _storage) = test_vault();
        let entry = create_entry(
            &mut vault,
            "gone".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        delete_entry(&mut vault, &entry.id).unwrap();
        let result = read_entry(&vault, &entry.id);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_entries_returns_active_only() {
        let (mut vault, _storage) = test_vault();
        create_entry(
            &mut vault,
            "a".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();
        let entry_b = create_entry(
            &mut vault,
            "b".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();
        delete_entry(&mut vault, &entry_b.id).unwrap();

        let list = list_entries(&vault).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1, "a");
    }

    #[test]
    fn test_search_by_name_case_insensitive() {
        let (mut vault, _storage) = test_vault();
        create_entry(
            &mut vault,
            "GitHub Token".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        let results = search_by_name(&vault, "github").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "GitHub Token");
    }

    #[test]
    fn test_search_by_tag() {
        let (mut vault, _storage) = test_vault();
        create_entry(
            &mut vault,
            "tagged".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec!["production".to_string()],
        )
        .unwrap();
        create_entry(
            &mut vault,
            "untagged".to_string(),
            EntryData::Credential {
                username: "u".to_string(),
                password: "p".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();

        let results = search_by_tag(&vault, "production").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "tagged");
    }

    #[test]
    fn test_persist_and_reopen_with_entries() {
        let storage = InMemStorage::new();
        let params = KdfParams::testing();
        let mut vault = Vault::init("pass", &storage, &params).unwrap();

        create_entry(
            &mut vault,
            "persist-test".to_string(),
            EntryData::Credential {
                username: "user".to_string(),
                password: "secret".to_string(),
                url: None,
                notes: None,
            },
            vec![],
        )
        .unwrap();
        vault.write_to_storage(&storage).unwrap();

        let vault2 = Vault::open("pass", &storage, &params).unwrap();
        let list = list_entries(&vault2).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1, "persist-test");
    }
}

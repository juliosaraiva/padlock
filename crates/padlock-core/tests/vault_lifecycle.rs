//! Integration tests for vault lifecycle operations.
//!
//! Tests init, open, lock, unlock, passphrase change, and
//! data persistence across vault reopen cycles.

use padlock_core::vault::lifecycle::{KdfParams, Vault, VaultState};
use padlock_core::vault::storage::FilesystemBackend;
use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};
use padlock_core::vault::format::EntryMetadata;
use padlock_core::types::Timestamp;
use tempfile::TempDir;

fn test_params() -> KdfParams {
    KdfParams::testing()
}

fn create_backend(dir: &TempDir) -> FilesystemBackend {
    FilesystemBackend::new(dir.path().join("test.vault"))
}

// --- Init ---

#[test]
fn test_vault_init_creates_unlocked_vault() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let vault = Vault::init("test-passphrase", &backend, &test_params()).unwrap();
    assert_eq!(vault.state(), VaultState::Unlocked);
}

#[test]
fn test_vault_init_writes_file_to_disk() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    Vault::init("pass", &backend, &test_params()).unwrap();
    assert!(backend.vault_path().exists());
}

#[test]
fn test_vault_init_already_exists_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    Vault::init("pass", &backend, &test_params()).unwrap();
    let result = Vault::init("pass", &backend, &test_params());
    assert!(result.is_err());
}

// --- Lock ---

#[test]
fn test_vault_lock_sets_locked_state() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert_eq!(vault.state(), VaultState::Locked);
}

#[test]
fn test_vault_locked_kek_access_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert!(vault.kek().is_err());
}

#[test]
fn test_vault_locked_mackey_access_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert!(vault.mackey().is_err());
}

#[test]
fn test_vault_locked_index_mut_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert!(vault.index_mut().is_err());
}

#[test]
fn test_vault_locked_write_to_storage_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert!(vault.write_to_storage(&backend).is_err());
}

#[test]
fn test_vault_locked_set_entries_blob_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let mut vault = Vault::init("pass", &backend, &test_params()).unwrap();
    vault.lock();
    assert!(vault.set_entries_blob(vec![1, 2, 3]).is_err());
}

// --- Open / Unlock ---

#[test]
fn test_vault_open_correct_passphrase_succeeds() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    Vault::init("correct", &backend, &params).unwrap();
    let vault = Vault::open("correct", &backend, &params).unwrap();
    assert_eq!(vault.state(), VaultState::Unlocked);
}

#[test]
fn test_vault_open_wrong_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    Vault::init("correct", &backend, &params).unwrap();
    let result = Vault::open("wrong", &backend, &params);
    assert!(result.is_err());
}

#[test]
fn test_vault_open_preserves_uuid() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let vault1 = Vault::init("pass", &backend, &params).unwrap();
    let uuid1 = vault1.header().vault_uuid;
    let vault2 = Vault::open("pass", &backend, &params).unwrap();
    assert_eq!(vault2.header().vault_uuid, uuid1);
}

// --- Data persistence across reopen ---

#[test]
fn test_vault_reopen_preserves_entry_data() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let mut vault = Vault::init("pass", &backend, &params).unwrap();

    // Add an encrypted entry
    let kek = vault.kek().unwrap();
    let plaintext = b"username=admin\npassword=hunter2";
    let encrypted = encrypt_entry(plaintext, kek).unwrap();
    let entry_uuid = [0x42; 16];
    let now = Timestamp::now().as_epoch_secs() as u64;
    let entry_len = encrypted.len() as u32;

    vault.index_mut().unwrap().entries.insert(
        entry_uuid,
        EntryMetadata {
            uuid: entry_uuid,
            entry_offset: 0,
            entry_length: entry_len,
            created_at: now,
            modified_at: now,
            deleted: false,
            title: "admin-creds".to_string(),
        },
    );
    vault.set_entries_blob(encrypted).unwrap();
    vault.write_to_storage(&backend).unwrap();

    // Reopen and verify
    let vault2 = Vault::open("pass", &backend, &params).unwrap();
    assert_eq!(vault2.index().entries.len(), 1);
    let meta = vault2.index().entries.get(&entry_uuid).unwrap();
    assert_eq!(meta.title, "admin-creds");
    let blob = &vault2.entries_blob()
        [meta.entry_offset as usize..meta.entry_offset as usize + meta.entry_length as usize];
    let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_vault_reopen_preserves_multiple_entries() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let mut vault = Vault::init("pass", &backend, &params).unwrap();

    let mut blob = Vec::new();
    let mut entries_info = Vec::new();

    for i in 0u8..5 {
        let plaintext = format!("entry-data-{i}");
        let kek = vault.kek().unwrap();
        let encrypted = encrypt_entry(plaintext.as_bytes(), kek).unwrap();
        let uuid = [i + 1; 16];
        let offset = blob.len() as u64;
        let length = encrypted.len() as u32;
        blob.extend_from_slice(&encrypted);
        entries_info.push((uuid, offset, length, format!("entry-{i}")));
    }

    let now = Timestamp::now().as_epoch_secs() as u64;
    for (uuid, offset, length, title) in entries_info {
        vault.index_mut().unwrap().entries.insert(
            uuid,
            EntryMetadata {
                uuid,
                entry_offset: offset,
                entry_length: length,
                created_at: now,
                modified_at: now,
                deleted: false,
                title,
            },
        );
    }
    vault.set_entries_blob(blob).unwrap();
    vault.write_to_storage(&backend).unwrap();

    // Reopen
    let vault2 = Vault::open("pass", &backend, &params).unwrap();
    assert_eq!(vault2.index().active_count(), 5);

    for i in 0u8..5 {
        let uuid = [i + 1; 16];
        let meta = vault2.index().entries.get(&uuid).unwrap();
        let entry_blob = &vault2.entries_blob()
            [meta.entry_offset as usize..meta.entry_offset as usize + meta.entry_length as usize];
        let decrypted = decrypt_entry(entry_blob, vault2.kek().unwrap()).unwrap();
        assert_eq!(decrypted, format!("entry-data-{i}").as_bytes());
    }
}

// --- Change passphrase ---

#[test]
fn test_vault_change_passphrase_new_passphrase_works() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let mut vault = Vault::init("old-pass", &backend, &params).unwrap();

    // Add data before passphrase change
    let kek = vault.kek().unwrap();
    let encrypted = encrypt_entry(b"preserved-secret", kek).unwrap();
    let entry_uuid = [0xAA; 16];
    let now = Timestamp::now().as_epoch_secs() as u64;
    let entry_len = encrypted.len() as u32;

    vault.index_mut().unwrap().entries.insert(
        entry_uuid,
        EntryMetadata {
            uuid: entry_uuid,
            entry_offset: 0,
            entry_length: entry_len,
            created_at: now,
            modified_at: now,
            deleted: false,
            title: "secret".to_string(),
        },
    );
    vault.set_entries_blob(encrypted).unwrap();
    vault.write_to_storage(&backend).unwrap();

    // Change passphrase
    vault
        .change_passphrase("new-pass", &backend, &params)
        .unwrap();

    // New passphrase works
    let vault2 = Vault::open("new-pass", &backend, &params).unwrap();
    let meta = vault2.index().entries.get(&entry_uuid).unwrap();
    let blob = &vault2.entries_blob()
        [meta.entry_offset as usize..meta.entry_offset as usize + meta.entry_length as usize];
    let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
    assert_eq!(decrypted, b"preserved-secret");
}

#[test]
fn test_vault_change_passphrase_old_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let mut vault = Vault::init("old-pass", &backend, &params).unwrap();
    vault
        .change_passphrase("new-pass", &backend, &params)
        .unwrap();

    let result = Vault::open("old-pass", &backend, &params);
    assert!(result.is_err());
}

#[test]
fn test_vault_change_passphrase_when_locked_fails() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    let mut vault = Vault::init("pass", &backend, &params).unwrap();
    vault.lock();
    let result = vault.change_passphrase("new", &backend, &params);
    assert!(result.is_err());
}

// --- Tamper detection ---

#[test]
fn test_vault_tampered_file_detected_on_open() {
    let dir = TempDir::new().unwrap();
    let backend = create_backend(&dir);
    let params = test_params();
    Vault::init("pass", &backend, &params).unwrap();

    // Tamper with the stored file
    let path = backend.vault_path().to_path_buf();
    let mut data = std::fs::read(&path).unwrap();
    data[20] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();

    let result = Vault::open("pass", &backend, &params);
    assert!(result.is_err());
}

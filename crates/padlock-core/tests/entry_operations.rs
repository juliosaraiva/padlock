//! Integration tests for entry CRUD operations.
//!
//! Tests create, read, update, delete, list, and search operations
//! for all entry types through the vault CRUD API.

use padlock_core::entries::{
    create_entry, delete_entry, list_entries, read_entry, search_by_name, search_by_tag,
    update_entry,
};
use padlock_core::entries::types::{
    EntryData, EntryType, SSHKeyType, TOTPAlgorithm,
};
use padlock_core::error::Error;
use padlock_core::traits::storage::StorageBackend;
use padlock_core::vault::lifecycle::{KdfParams, Vault};

// --- In-memory storage for tests ---

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
    fn write_vault(&self, data: &[u8]) -> padlock_core::error::Result<()> {
        *self.data.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
    fn read_vault(&self) -> padlock_core::error::Result<Vec<u8>> {
        self.data
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::Vault(padlock_core::error::VaultError::NotFound {
                path: "<mem>".to_string(),
            }))
    }
    fn vault_exists(&self) -> padlock_core::error::Result<bool> {
        Ok(self.data.lock().unwrap().is_some())
    }
    fn write_backup(&self, _data: &[u8]) -> padlock_core::error::Result<()> {
        Ok(())
    }
}

fn test_vault() -> (Vault, InMemStorage) {
    let storage = InMemStorage::new();
    let vault = Vault::init("test", &storage, &KdfParams::testing()).unwrap();
    (vault, storage)
}

// --- Helper entry constructors ---

fn sample_credential() -> (String, EntryData, Vec<String>) {
    (
        "github-login".to_string(),
        EntryData::Credential {
            username: "octocat".to_string(),
            password: "gh-secret-token".to_string(),
            url: Some("https://github.com".to_string()),
            notes: Some("primary account".to_string()),
        },
        vec!["dev".to_string(), "work".to_string()],
    )
}

fn sample_ssh_key() -> (String, EntryData, Vec<String>) {
    (
        "deploy-key".to_string(),
        EntryData::SSHKey {
            key_type: SSHKeyType::ED25519,
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-data\n-----END OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAAAC3Nza...== deploy@server".to_string(),
            passphrase: Some("key-pass".to_string()),
            comment: Some("production deploy key".to_string()),
        },
        vec!["ssh".to_string(), "production".to_string()],
    )
}

fn sample_totp() -> (String, EntryData, Vec<String>) {
    (
        "aws-mfa".to_string(),
        EntryData::TOTP {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: TOTPAlgorithm::SHA1,
            digits: 6,
            period: 30,
            account_name: "user@aws".to_string(),
            issuer: Some("Amazon Web Services".to_string()),
        },
        vec!["mfa".to_string(), "aws".to_string()],
    )
}

fn sample_binary() -> (String, EntryData, Vec<String>) {
    (
        "tls-cert".to_string(),
        EntryData::Binary {
            data: vec![0x30, 0x82, 0x01, 0xA2, 0xDE, 0xAD, 0xBE, 0xEF],
            content_type: Some("application/x-x509-ca-cert".to_string()),
            filename: Some("ca-cert.pem".to_string()),
            description: Some("Root CA certificate".to_string()),
        },
        vec!["tls".to_string(), "infrastructure".to_string()],
    )
}

fn sample_netrc() -> (String, EntryData, Vec<String>) {
    (
        "npm-registry".to_string(),
        EntryData::Netrc {
            machine: "registry.npmjs.org".to_string(),
            login: "npm-user".to_string(),
            password: "npm-token-abc123".to_string(),
            account: None,
        },
        vec!["npm".to_string(), "registry".to_string()],
    )
}

// --- Create tests ---

#[test]
fn test_create_credential_entry() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name.clone(), data, tags.clone()).unwrap();
    assert_eq!(entry.name, name);
    assert_eq!(entry.entry_type(), EntryType::Credential);
    assert_eq!(entry.tags, tags);
    assert_eq!(entry.version, 1);
}

#[test]
fn test_create_ssh_key_entry() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_ssh_key();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(entry.entry_type(), EntryType::SSHKey);
}

#[test]
fn test_create_totp_entry() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_totp();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(entry.entry_type(), EntryType::TOTP);
}

#[test]
fn test_create_binary_entry() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_binary();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(entry.entry_type(), EntryType::Binary);
}

#[test]
fn test_create_netrc_entry() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_netrc();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(entry.entry_type(), EntryType::Netrc);
}

// --- Read tests ---

#[test]
fn test_read_credential_data_matches() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data.clone(), tags).unwrap();
    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, data);
    assert_eq!(read.name, "github-login");
}

#[test]
fn test_read_ssh_key_data_matches() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_ssh_key();
    let entry = create_entry(&mut vault, name, data.clone(), tags).unwrap();
    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, data);
}

#[test]
fn test_read_totp_data_matches() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_totp();
    let entry = create_entry(&mut vault, name, data.clone(), tags).unwrap();
    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, data);
}

#[test]
fn test_read_binary_data_matches() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_binary();
    let entry = create_entry(&mut vault, name, data.clone(), tags).unwrap();
    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, data);
}

#[test]
fn test_read_netrc_data_matches() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_netrc();
    let entry = create_entry(&mut vault, name, data.clone(), tags).unwrap();
    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, data);
}

#[test]
fn test_read_nonexistent_entry_fails() {
    let (vault, _) = test_vault();
    let fake_id = padlock_core::types::EntryId::new();
    let result = read_entry(&vault, &fake_id);
    assert!(result.is_err());
}

// --- Update tests ---

#[test]
fn test_update_entry_increments_version() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(entry.version, 1);

    let new_data = EntryData::Credential {
        username: "new-user".to_string(),
        password: "new-password".to_string(),
        url: None,
        notes: None,
    };
    let updated = update_entry(&mut vault, &entry.id, new_data.clone()).unwrap();
    assert_eq!(updated.version, 2);

    let read = read_entry(&vault, &entry.id).unwrap();
    assert_eq!(read.data, new_data);
    assert_eq!(read.version, 2);
}

#[test]
fn test_update_entry_preserves_id_and_name() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name.clone(), data, tags).unwrap();

    let new_data = EntryData::Credential {
        username: "changed".to_string(),
        password: "changed".to_string(),
        url: None,
        notes: None,
    };
    let updated = update_entry(&mut vault, &entry.id, new_data).unwrap();
    assert_eq!(updated.id, entry.id);
    assert_eq!(updated.name, name);
}

#[test]
fn test_update_nonexistent_entry_fails() {
    let (mut vault, _) = test_vault();
    let fake_id = padlock_core::types::EntryId::new();
    let result = update_entry(
        &mut vault,
        &fake_id,
        EntryData::Credential {
            username: "x".to_string(),
            password: "y".to_string(),
            url: None,
            notes: None,
        },
    );
    assert!(result.is_err());
}

// --- Delete tests ---

#[test]
fn test_delete_entry_removes_from_listing() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    assert_eq!(list_entries(&vault).unwrap().len(), 1);

    delete_entry(&mut vault, &entry.id).unwrap();
    assert!(list_entries(&vault).unwrap().is_empty());
}

#[test]
fn test_delete_entry_read_fails() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    delete_entry(&mut vault, &entry.id).unwrap();
    let result = read_entry(&vault, &entry.id);
    assert!(result.is_err());
}

#[test]
fn test_delete_nonexistent_entry_fails() {
    let (mut vault, _) = test_vault();
    let fake_id = padlock_core::types::EntryId::new();
    let result = delete_entry(&mut vault, &fake_id);
    assert!(result.is_err());
}

#[test]
fn test_delete_already_deleted_entry_fails() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    delete_entry(&mut vault, &entry.id).unwrap();
    let result = delete_entry(&mut vault, &entry.id);
    assert!(result.is_err());
}

// --- List tests ---

#[test]
fn test_list_entries_returns_all_active() {
    let (mut vault, _) = test_vault();
    let samples = vec![sample_credential(), sample_ssh_key(), sample_totp()];
    for (name, data, tags) in samples {
        create_entry(&mut vault, name, data, tags).unwrap();
    }
    let list = list_entries(&vault).unwrap();
    assert_eq!(list.len(), 3);
}

#[test]
fn test_list_entries_excludes_deleted() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    let (name2, data2, tags2) = sample_ssh_key();
    create_entry(&mut vault, name2, data2, tags2).unwrap();

    delete_entry(&mut vault, &entry.id).unwrap();
    let list = list_entries(&vault).unwrap();
    assert_eq!(list.len(), 1);
}

// --- Search by name ---

#[test]
fn test_search_by_name_case_insensitive() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name, data, tags).unwrap();

    // Search with different case
    let results = search_by_name(&vault, "GITHUB").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "github-login");
}

#[test]
fn test_search_by_name_partial_match() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name, data, tags).unwrap();

    let results = search_by_name(&vault, "hub").unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_search_by_name_no_match() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name, data, tags).unwrap();

    let results = search_by_name(&vault, "nonexistent").unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_search_by_name_excludes_deleted() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data, tags).unwrap();
    delete_entry(&mut vault, &entry.id).unwrap();

    let results = search_by_name(&vault, "github").unwrap();
    assert!(results.is_empty());
}

// --- Search by tag ---

#[test]
fn test_search_by_tag_finds_matching() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name, data, tags).unwrap();
    let (name2, data2, tags2) = sample_ssh_key();
    create_entry(&mut vault, name2, data2, tags2).unwrap();

    let results = search_by_tag(&vault, "dev").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "github-login");
}

#[test]
fn test_search_by_tag_case_insensitive() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name, data, tags).unwrap();

    let results = search_by_tag(&vault, "DEV").unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_search_by_tag_shared_tag() {
    let (mut vault, _) = test_vault();
    let (name1, data1, _) = sample_credential();
    create_entry(&mut vault, name1, data1, vec!["shared".to_string()]).unwrap();
    let (name2, data2, _) = sample_ssh_key();
    create_entry(&mut vault, name2, data2, vec!["shared".to_string()]).unwrap();

    let results = search_by_tag(&vault, "shared").unwrap();
    assert_eq!(results.len(), 2);
}

// --- Duplicate name rejection ---

#[test]
fn test_create_duplicate_name_rejected() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    create_entry(&mut vault, name.clone(), data, tags).unwrap();

    let result = create_entry(
        &mut vault,
        name,
        EntryData::Credential {
            username: "other".to_string(),
            password: "other".to_string(),
            url: None,
            notes: None,
        },
        vec![],
    );
    assert!(result.is_err());
}

#[test]
fn test_create_after_delete_same_name_succeeds() {
    let (mut vault, _) = test_vault();
    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name.clone(), data.clone(), tags.clone()).unwrap();
    delete_entry(&mut vault, &entry.id).unwrap();

    // Should succeed after deletion
    let entry2 = create_entry(&mut vault, name.clone(), data, tags).unwrap();
    assert_ne!(entry.id, entry2.id);
    assert_eq!(entry2.name, name);
}

// --- Persistence across vault save/reopen ---

#[test]
fn test_entries_survive_vault_reopen() {
    let storage = InMemStorage::new();
    let params = KdfParams::testing();
    let mut vault = Vault::init("pass", &storage, &params).unwrap();

    let (name, data, tags) = sample_credential();
    let entry = create_entry(&mut vault, name, data.clone(), tags.clone()).unwrap();
    vault.write_to_storage(&storage).unwrap();

    let vault2 = Vault::open("pass", &storage, &params).unwrap();
    let list = list_entries(&vault2).unwrap();
    assert_eq!(list.len(), 1);

    let read = read_entry(&vault2, &entry.id).unwrap();
    assert_eq!(read.data, data);
    assert_eq!(read.tags, tags);
}

// --- All entry types CRUD round-trip ---

#[test]
fn test_all_entry_types_create_read_round_trip() {
    let (mut vault, _) = test_vault();

    let samples: Vec<(String, EntryData, Vec<String>)> = vec![
        sample_credential(),
        sample_ssh_key(),
        sample_totp(),
        sample_binary(),
        sample_netrc(),
    ];

    let mut ids = Vec::new();
    for (name, data, tags) in &samples {
        let entry = create_entry(&mut vault, name.clone(), data.clone(), tags.clone()).unwrap();
        ids.push(entry.id);
    }

    // Verify each entry can be read back correctly
    for (i, (name, data, tags)) in samples.iter().enumerate() {
        let read = read_entry(&vault, &ids[i]).unwrap();
        assert_eq!(&read.name, name);
        assert_eq!(&read.data, data);
        assert_eq!(&read.tags, tags);
        assert_eq!(read.version, 1);
    }

    let list = list_entries(&vault).unwrap();
    assert_eq!(list.len(), 5);
}

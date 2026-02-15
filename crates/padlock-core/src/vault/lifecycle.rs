//! Vault state machine and lifecycle operations.
//!
//! Implements init, open/unlock, lock, and close operations
//! with proper state transition enforcement.
//!
//! # State Machine
//!
//! ```text
//! [Init] --> Locked --unlock()--> Unlocked --lock()--> Locked
//! ```

use crate::crypto::hmac::{compute_hmac, verify_hmac, HMAC_SIZE};
use crate::crypto::kdf::{derive_pdk_with_params, generate_argon2_salt};
use crate::crypto::hkdf_keys::{derive_kek, derive_mackey};
use crate::crypto::secret_buf::SecretBuf;
use crate::error::{Error, VaultError};
use crate::traits::storage::StorageBackend;
use crate::types::Timestamp;
use crate::vault::format::{
    deserialize_index, parse_header, serialize_header, serialize_index, VaultHeader, VaultIndex,
    HEADER_SIZE,
};

/// Vault lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// The vault is locked; no keys are in memory.
    Locked,
    /// The vault is unlocked; keys are available for operations.
    Unlocked,
}

/// The vault manager holding state and cryptographic keys.
///
/// When unlocked, the vault holds the KEK and MACKEY in memory
/// for performing entry operations. When locked, all keys are
/// zeroized and cleared.
pub struct Vault {
    state: VaultState,
    header: VaultHeader,
    index: VaultIndex,
    /// KEK for entry encryption/decryption (only present when unlocked).
    kek: Option<SecretBuf>,
    /// MACKEY for vault HMAC (only present when unlocked).
    mackey: Option<SecretBuf>,
    /// Raw entries blob (encrypted).
    entries_blob: Vec<u8>,
}

/// Parameters for KDF during vault operations.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2 time cost (iterations).
    pub time_cost: u32,
    /// Argon2 parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Production KDF parameters (1 GiB, t=2, p=4).
    #[must_use]
    pub fn production() -> Self {
        Self {
            memory_kib: crate::crypto::kdf::ARGON2_MEMORY_KIB,
            time_cost: crate::crypto::kdf::ARGON2_TIME_COST,
            parallelism: crate::crypto::kdf::ARGON2_PARALLELISM,
        }
    }

    /// Test KDF parameters (64 KiB, t=1, p=1).
    #[must_use]
    pub fn testing() -> Self {
        Self {
            memory_kib: 64,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

impl Vault {
    /// Initialize a new vault.
    ///
    /// Creates a fresh vault file with a random salt and UUID,
    /// derives keys from the passphrase, and writes to storage.
    /// The vault is left in an unlocked state.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or storage write fails.
    pub fn init(
        passphrase: &str,
        storage: &dyn StorageBackend,
        params: &KdfParams,
    ) -> crate::error::Result<Self> {
        if storage.vault_exists()? {
            return Err(Error::Vault(VaultError::AlreadyExists {
                path: "<vault>".to_string(),
            }));
        }

        let salt = generate_argon2_salt();
        let vault_uuid = uuid::Uuid::new_v4();
        let now = Timestamp::now().as_epoch_secs() as u64;

        let header = VaultHeader::new(salt, *vault_uuid.as_bytes(), now);
        let index = VaultIndex::new();

        // Derive keys
        let pdk = derive_pdk_with_params(
            passphrase,
            &salt,
            params.memory_kib,
            params.time_cost,
            params.parallelism,
        )?;
        let kek = derive_kek(&pdk)?;
        let mackey = derive_mackey(&pdk)?;
        // PDK is dropped here (zeroized)

        let mut vault = Self {
            state: VaultState::Unlocked,
            header,
            index,
            kek: Some(kek),
            mackey: Some(mackey),
            entries_blob: Vec::new(),
        };

        vault.write_to_storage(storage)?;

        Ok(vault)
    }

    /// Open and unlock an existing vault.
    ///
    /// Reads the vault file from storage, derives keys from the passphrase,
    /// verifies the HMAC, and loads the index.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::WrongPassphrase` if the HMAC check fails.
    /// Returns errors if the vault file is corrupted or unreadable.
    pub fn open(
        passphrase: &str,
        storage: &dyn StorageBackend,
        params: &KdfParams,
    ) -> crate::error::Result<Self> {
        let data = storage.read_vault()?;

        if data.len() < HEADER_SIZE + HMAC_SIZE {
            return Err(Error::Vault(VaultError::CorruptedData));
        }

        let header = parse_header(&data)?;

        // Derive keys from passphrase + stored salt
        let pdk = derive_pdk_with_params(
            passphrase,
            &header.argon2_salt,
            params.memory_kib,
            params.time_cost,
            params.parallelism,
        )?;
        let kek = derive_kek(&pdk)?;
        let mackey = derive_mackey(&pdk)?;

        // Verify HMAC (covers header + index + entries, excludes trailing HMAC)
        let hmac_start = data.len() - HMAC_SIZE;
        let authenticated_data = &data[..hmac_start];
        let stored_hmac = &data[hmac_start..];

        verify_hmac(&mackey, authenticated_data, stored_hmac)
            .map_err(|_| Error::Vault(VaultError::WrongPassphrase))?;

        // Parse index
        let index_start = HEADER_SIZE;
        let index_end = index_start + header.vault_index_length as usize;
        if index_end > hmac_start {
            return Err(Error::Vault(VaultError::CorruptedData));
        }

        let index = if header.vault_index_length > 0 {
            deserialize_index(&data[index_start..index_end])?
        } else {
            VaultIndex::new()
        };

        // Extract entries blob
        let entries_end = index_end + header.entries_blob_length as usize;
        if entries_end > hmac_start {
            return Err(Error::Vault(VaultError::CorruptedData));
        }
        let entries_blob = data[index_end..entries_end].to_vec();

        Ok(Self {
            state: VaultState::Unlocked,
            header,
            index,
            kek: Some(kek),
            mackey: Some(mackey),
            entries_blob,
        })
    }

    /// Lock the vault, clearing all keys from memory.
    ///
    /// After locking, no entry operations can be performed until
    /// the vault is unlocked again.
    pub fn lock(&mut self) {
        self.kek = None;
        self.mackey = None;
        self.state = VaultState::Locked;
    }

    /// Get the current vault state.
    #[must_use]
    pub fn state(&self) -> VaultState {
        self.state
    }

    /// Get the vault header.
    #[must_use]
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Get the vault index.
    #[must_use]
    pub fn index(&self) -> &VaultIndex {
        &self.index
    }

    /// Get a mutable reference to the vault index.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn index_mut(&mut self) -> crate::error::Result<&mut VaultIndex> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }
        Ok(&mut self.index)
    }

    /// Get the KEK for entry operations.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn kek(&self) -> crate::error::Result<&SecretBuf> {
        self.kek
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))
    }

    /// Get the MACKEY for vault integrity operations.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn mackey(&self) -> crate::error::Result<&SecretBuf> {
        self.mackey
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))
    }

    /// Open a vault using pre-derived KEK and MACKEY (from session cache).
    ///
    /// Skips passphrase prompt and Argon2id derivation by using
    /// keys cached from a previous session.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::WrongPassphrase` if HMAC verification fails.
    /// Returns errors if the vault file is corrupted or unreadable.
    pub fn open_with_keys(
        kek: SecretBuf,
        mackey: SecretBuf,
        storage: &dyn StorageBackend,
    ) -> crate::error::Result<Self> {
        let data = storage.read_vault()?;

        if data.len() < HEADER_SIZE + HMAC_SIZE {
            return Err(Error::Vault(VaultError::CorruptedData));
        }

        let header = parse_header(&data)?;

        // Verify HMAC
        let hmac_start = data.len() - HMAC_SIZE;
        let authenticated_data = &data[..hmac_start];
        let stored_hmac = &data[hmac_start..];

        verify_hmac(&mackey, authenticated_data, stored_hmac)
            .map_err(|_| Error::Vault(VaultError::WrongPassphrase))?;

        // Parse index
        let index_start = HEADER_SIZE;
        let index_end = index_start + header.vault_index_length as usize;
        if index_end > hmac_start {
            return Err(Error::Vault(VaultError::CorruptedData));
        }

        let index = if header.vault_index_length > 0 {
            deserialize_index(&data[index_start..index_end])?
        } else {
            VaultIndex::new()
        };

        // Extract entries blob
        let entries_end = index_end + header.entries_blob_length as usize;
        if entries_end > hmac_start {
            return Err(Error::Vault(VaultError::CorruptedData));
        }
        let entries_blob = data[index_end..entries_end].to_vec();

        Ok(Self {
            state: VaultState::Unlocked,
            header,
            index,
            kek: Some(kek),
            mackey: Some(mackey),
            entries_blob,
        })
    }

    /// Get the entries blob.
    #[must_use]
    pub fn entries_blob(&self) -> &[u8] {
        &self.entries_blob
    }

    /// Set the entries blob (used after adding/removing entries).
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn set_entries_blob(&mut self, blob: Vec<u8>) -> crate::error::Result<()> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }
        self.entries_blob = blob;
        Ok(())
    }

    /// Write the current vault state to storage.
    ///
    /// Serializes the header, index, and entries blob, computes the HMAC,
    /// and writes the complete vault file.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    /// Returns errors if serialization or storage write fails.
    pub fn write_to_storage(&mut self, storage: &dyn StorageBackend) -> crate::error::Result<()> {
        let mackey = self
            .mackey
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))?;

        // Serialize index
        let index_bytes = serialize_index(&self.index)?;

        // Update header counts and lengths
        self.header.entry_count = self.index.active_count() as u32;
        self.header.deleted_entry_count = self.index.deleted_count() as u32;
        self.header.vault_index_length = index_bytes.len() as u32;
        self.header.entries_blob_length = self.entries_blob.len() as u32;
        self.header.modified_timestamp = Timestamp::now().as_epoch_secs() as u64;

        // Serialize header
        let header_bytes = serialize_header(&self.header);

        // Assemble data for HMAC: header || index || entries
        let mut data = Vec::with_capacity(
            HEADER_SIZE + index_bytes.len() + self.entries_blob.len() + HMAC_SIZE,
        );
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&index_bytes);
        data.extend_from_slice(&self.entries_blob);

        // Compute and append HMAC
        let hmac = compute_hmac(mackey, &data);
        data.extend_from_slice(&hmac);

        storage.write_vault(&data)
    }

    /// Change the vault passphrase.
    ///
    /// Re-derives all keys from the new passphrase, re-computes the HMAC,
    /// and writes the updated vault to storage.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &str,
        storage: &dyn StorageBackend,
        params: &KdfParams,
    ) -> crate::error::Result<()> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }

        // Generate new salt
        let new_salt = generate_argon2_salt();
        self.header.argon2_salt = new_salt;

        // Derive new keys
        let pdk = derive_pdk_with_params(
            new_passphrase,
            &new_salt,
            params.memory_kib,
            params.time_cost,
            params.parallelism,
        )?;
        let new_kek = derive_kek(&pdk)?;
        let new_mackey = derive_mackey(&pdk)?;

        // Re-encrypt all entries with the new KEK
        let old_kek = self
            .kek
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))?;

        if !self.entries_blob.is_empty() {
            let mut new_entries_blob = Vec::new();
            // Collect entry info first to avoid borrow conflict
            let entry_info: Vec<([u8; 16], usize, usize, bool)> = self
                .index
                .entries
                .values()
                .map(|m| (m.uuid, m.entry_offset as usize, m.entry_length as usize, m.deleted))
                .collect();

            for (uuid, offset, length, deleted) in &entry_info {
                if *deleted {
                    continue;
                }
                if offset + length > self.entries_blob.len() {
                    return Err(Error::Vault(VaultError::CorruptedData));
                }
                let encrypted_entry = &self.entries_blob[*offset..*offset + *length];
                let plaintext =
                    crate::vault::entries::decrypt_entry(encrypted_entry, old_kek)?;
                let new_encrypted =
                    crate::vault::entries::encrypt_entry(&plaintext, &new_kek)?;

                let new_offset = new_entries_blob.len() as u64;
                let new_length = new_encrypted.len() as u32;
                new_entries_blob.extend_from_slice(&new_encrypted);

                if let Some(entry_meta) = self.index.entries.get_mut(uuid) {
                    entry_meta.entry_offset = new_offset;
                    entry_meta.entry_length = new_length;
                }
            }

            self.entries_blob = new_entries_blob;
        }

        // Install new keys
        self.kek = Some(new_kek);
        self.mackey = Some(new_mackey);

        // Write to storage
        self.write_to_storage(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entries::{encrypt_entry, decrypt_entry};

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

    fn test_params() -> KdfParams {
        KdfParams::testing()
    }

    #[test]
    fn test_vault_init_creates_unlocked_vault() {
        let storage = InMemStorage::new();
        let vault = Vault::init("test-passphrase", &storage, &test_params()).unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);
        assert!(storage.vault_exists().unwrap());
    }

    #[test]
    fn test_vault_init_already_exists_fails() {
        let storage = InMemStorage::new();
        Vault::init("pass", &storage, &test_params()).unwrap();
        let result = Vault::init("pass", &storage, &test_params());
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_open_with_correct_passphrase() {
        let storage = InMemStorage::new();
        let params = test_params();
        Vault::init("correct-pass", &storage, &params).unwrap();
        let vault = Vault::open("correct-pass", &storage, &params).unwrap();
        assert_eq!(vault.state(), VaultState::Unlocked);
    }

    #[test]
    fn test_vault_open_with_wrong_passphrase_fails() {
        let storage = InMemStorage::new();
        let params = test_params();
        Vault::init("correct-pass", &storage, &params).unwrap();
        let result = Vault::open("wrong-pass", &storage, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_lock_clears_keys() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        assert!(vault.kek().is_ok());
        vault.lock();
        assert_eq!(vault.state(), VaultState::Locked);
        assert!(vault.kek().is_err());
    }

    #[test]
    fn test_vault_locked_operations_fail() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        vault.lock();
        assert!(vault.index_mut().is_err());
        assert!(vault.write_to_storage(&storage).is_err());
    }

    #[test]
    fn test_vault_write_and_reopen_preserves_data() {
        let storage = InMemStorage::new();
        let params = test_params();
        let mut vault = Vault::init("pass", &storage, &params).unwrap();

        // Add an entry
        let kek = vault.kek().unwrap();
        let encrypted = encrypt_entry(b"my secret data", kek).unwrap();
        let entry_uuid = [0x42; 16];
        let now = Timestamp::now().as_epoch_secs() as u64;

        let entry_len = encrypted.len() as u32;
        vault.index_mut().unwrap().entries.insert(
            entry_uuid,
            crate::vault::format::EntryMetadata {
                uuid: entry_uuid,
                entry_offset: 0,
                entry_length: entry_len,
                created_at: now,
                modified_at: now,
                deleted: false,
                title: "test".to_string(),
            },
        );
        vault.set_entries_blob(encrypted).unwrap();
        vault.write_to_storage(&storage).unwrap();

        // Reopen and verify
        let vault2 = Vault::open("pass", &storage, &params).unwrap();
        assert_eq!(vault2.index().entries.len(), 1);
        let meta = vault2.index().entries.get(&entry_uuid).unwrap();
        let blob = &vault2.entries_blob()[meta.entry_offset as usize
            ..meta.entry_offset as usize + meta.entry_length as usize];
        let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
        assert_eq!(decrypted, b"my secret data");
    }

    #[test]
    fn test_vault_tampered_file_detected() {
        let storage = InMemStorage::new();
        let params = test_params();
        Vault::init("pass", &storage, &params).unwrap();

        // Tamper with the stored data
        let mut data = storage.read_vault().unwrap();
        // Flip a byte in the header area (after magic/version)
        data[20] ^= 0xFF;
        storage.write_vault(&data).unwrap();

        // Open should fail due to HMAC mismatch
        let result = Vault::open("pass", &storage, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_change_passphrase() {
        let storage = InMemStorage::new();
        let params = test_params();
        let mut vault = Vault::init("old-pass", &storage, &params).unwrap();

        // Add an entry
        let kek = vault.kek().unwrap();
        let encrypted = encrypt_entry(b"preserved data", kek).unwrap();
        let entry_uuid = [0x99; 16];
        let now = Timestamp::now().as_epoch_secs() as u64;
        let entry_len = encrypted.len() as u32;
        vault.index_mut().unwrap().entries.insert(
            entry_uuid,
            crate::vault::format::EntryMetadata {
                uuid: entry_uuid,
                entry_offset: 0,
                entry_length: entry_len,
                created_at: now,
                modified_at: now,
                deleted: false,
                title: "keep-me".to_string(),
            },
        );
        vault.set_entries_blob(encrypted).unwrap();
        vault.write_to_storage(&storage).unwrap();

        // Change passphrase
        vault
            .change_passphrase("new-pass", &storage, &params)
            .unwrap();

        // Old passphrase should fail
        let result = Vault::open("old-pass", &storage, &params);
        assert!(result.is_err());

        // New passphrase should work and data is preserved
        let vault2 = Vault::open("new-pass", &storage, &params).unwrap();
        let meta = vault2.index().entries.get(&entry_uuid).unwrap();
        let blob = &vault2.entries_blob()[meta.entry_offset as usize
            ..meta.entry_offset as usize + meta.entry_length as usize];
        let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
        assert_eq!(decrypted, b"preserved data");
    }
}

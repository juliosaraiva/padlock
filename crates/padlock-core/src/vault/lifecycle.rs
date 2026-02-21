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

use crate::crypto::hkdf_keys::{derive_kek, derive_mackey};
use crate::crypto::hmac::{compute_hmac_incremental, verify_hmac, HMAC_SIZE};
use crate::crypto::kdf::{derive_pdk_with_params, generate_argon2_salt};
use crate::crypto::recovery::{
    decode_recovery_key, derive_recovery_wrapping_key, encode_recovery_key, generate_recovery_key,
    generate_recovery_salt, unwrap_keys_from_recovery, wrap_keys_for_recovery,
};
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
    /// Production KDF parameters (256 MiB, t=3, p=4).
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
        let now = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);

        let header = VaultHeader::new(
            salt,
            *vault_uuid.as_bytes(),
            now,
            params.memory_kib,
            params.time_cost,
            params.parallelism,
        );
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

        // Use KDF params from the header if present (non-zero), otherwise
        // fall back to the caller-provided params (for legacy vaults with
        // zeros at offsets 76-87).
        let (mem, time, par) = if header.argon2_memory_kib > 0
            && header.argon2_time_cost > 0
            && header.argon2_parallelism > 0
        {
            (
                header.argon2_memory_kib,
                header.argon2_time_cost,
                header.argon2_parallelism,
            )
        } else {
            (params.memory_kib, params.time_cost, params.parallelism)
        };

        // Derive keys from passphrase + stored salt
        let pdk = derive_pdk_with_params(passphrase, &header.argon2_salt, mem, time, par)?;
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
        self.kek.as_ref().ok_or(Error::Vault(VaultError::Locked))
    }

    /// Get the MACKEY for vault integrity operations.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn mackey(&self) -> crate::error::Result<&SecretBuf> {
        self.mackey.as_ref().ok_or(Error::Vault(VaultError::Locked))
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

    /// Append data to the entries blob in place.
    ///
    /// Returns the (offset, length) of the appended data within the blob.
    /// This avoids copying the entire blob when adding a single entry.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds `u32::MAX` (not possible for valid entries).
    pub fn append_to_entries_blob(&mut self, data: &[u8]) -> crate::error::Result<(u64, u32)> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }
        let offset = self.entries_blob.len() as u64;
        let length = u32::try_from(data.len()).expect("entry data length fits in u32");
        self.entries_blob.extend_from_slice(data);
        Ok((offset, length))
    }

    /// Write the current vault state to storage.
    ///
    /// Serializes the header, index, and entries blob, computes the HMAC
    /// incrementally over segments, and writes without assembling a full
    /// buffer copy. This reduces peak memory from 2x to ~1x vault size.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    /// Returns errors if serialization or storage write fails.
    ///
    /// # Panics
    ///
    /// Panics if the entry count, index length, or blob length exceeds
    /// `u32::MAX` (not possible in practice).
    pub fn write_to_storage(&mut self, storage: &dyn StorageBackend) -> crate::error::Result<()> {
        let mackey = self
            .mackey
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))?;

        // Serialize index
        let index_bytes = serialize_index(&self.index)?;

        // Update header counts and lengths
        self.header.entry_count = u32::try_from(self.index.active_count()).expect("entry count fits in u32");
        self.header.deleted_entry_count = u32::try_from(self.index.deleted_count()).expect("deleted count fits in u32");
        self.header.vault_index_length = u32::try_from(index_bytes.len()).expect("index length fits in u32");
        self.header.entries_blob_length = u32::try_from(self.entries_blob.len()).expect("entries blob length fits in u32");
        self.header.modified_timestamp = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);

        // Serialize header
        let header_bytes = serialize_header(&self.header);

        // Compute HMAC incrementally over segments (no full-buffer assembly)
        let hmac =
            compute_hmac_incremental(mackey, &[&header_bytes, &index_bytes, &self.entries_blob]);

        // Write segments without assembling full buffer
        storage.write_vault_segments(&[&header_bytes, &index_bytes, &self.entries_blob, &hmac])
    }

    /// Compact the entries blob by removing dead space from deleted and
    /// superseded entries.
    ///
    /// Rewrites the blob to contain only live entries, updating their
    /// offsets in the index. Deleted entries are removed from the index.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    /// Returns `VaultError::CorruptedData` if any entry offset is out of bounds.
    ///
    /// # Panics
    ///
    /// Panics if the internal index is inconsistent (entry present in live list
    /// but missing from the index map — this is a programming error).
    pub fn compact_entries_blob(&mut self) -> crate::error::Result<()> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }

        let mut new_blob = Vec::with_capacity(self.entries_blob.len());

        // Collect UUIDs to process to avoid borrow conflict
        let live_entries: Vec<[u8; 16]> = self
            .index
            .entries
            .values()
            .filter(|m| !m.deleted)
            .map(|m| m.uuid)
            .collect();

        for uuid in &live_entries {
            let meta = self.index.entries.get(uuid).expect("uuid from live_entries must exist in index");
            let start = usize::try_from(meta.entry_offset).map_err(|_| Error::Vault(VaultError::CorruptedData))?;
            let end = start + meta.entry_length as usize;
            if end > self.entries_blob.len() {
                return Err(Error::Vault(VaultError::CorruptedData));
            }
            let new_offset = new_blob.len() as u64;
            new_blob.extend_from_slice(&self.entries_blob[start..end]);

            // Update offset in index
            let meta_mut = self.index.entries.get_mut(uuid).expect("uuid from live_entries must exist in index");
            meta_mut.entry_offset = new_offset;
        }

        // Remove deleted entries from the index
        self.index.entries.retain(|_, m| !m.deleted);

        self.entries_blob = new_blob;
        Ok(())
    }

    /// Change the vault passphrase.
    ///
    /// Compacts dead entries first, then re-derives all keys from the new
    /// passphrase, re-encrypts live entries, and writes to storage.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    ///
    /// # Panics
    ///
    /// Panics if the re-encrypted entry length exceeds `u32::MAX` (not
    /// possible in practice for valid entries).
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &str,
        storage: &dyn StorageBackend,
        params: &KdfParams,
    ) -> crate::error::Result<()> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }

        // Compact dead entries first to avoid re-encrypting stale data
        self.compact_entries_blob()?;

        // Generate new salt and store new KDF params in header
        let new_salt = generate_argon2_salt();
        self.header.argon2_salt = new_salt;
        self.header.argon2_memory_kib = params.memory_kib;
        self.header.argon2_time_cost = params.time_cost;
        self.header.argon2_parallelism = params.parallelism;

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
        let old_kek = self.kek.as_ref().ok_or(Error::Vault(VaultError::Locked))?;

        if !self.entries_blob.is_empty() {
            let mut new_entries_blob = Vec::with_capacity(self.entries_blob.len());
            // Collect entry info first to avoid borrow conflict
            let entry_info: Vec<([u8; 16], usize, usize, bool)> = self
                .index
                .entries
                .values()
                .map(|m| {
                    (
                        m.uuid,
                        usize::try_from(m.entry_offset).unwrap_or(usize::MAX),
                        m.entry_length as usize,
                        m.deleted,
                    )
                })
                .collect();

            for (uuid, offset, length, deleted) in &entry_info {
                if *deleted {
                    continue;
                }
                if offset + length > self.entries_blob.len() {
                    return Err(Error::Vault(VaultError::CorruptedData));
                }
                let encrypted_entry = &self.entries_blob[*offset..*offset + *length];
                let plaintext = crate::vault::entries::decrypt_entry(encrypted_entry, old_kek)?;
                let new_encrypted = crate::vault::entries::encrypt_entry(&plaintext, &new_kek)?;

                let new_offset = new_entries_blob.len() as u64;
                let new_length = u32::try_from(new_encrypted.len()).expect("entry length fits in u32");
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

        // Invalidate recovery: new KEK+MACKEY means old recovery blob is stale.
        // We don't have the recovery key to re-wrap, so zero everything out.
        if self.header.recovery_enabled() {
            self.header.recovery_salt = [0u8; 16];
            self.header.recovery_nonce = [0u8; 24];
            self.header.recovery_blob = [0u8; 80];
            self.header.set_recovery_enabled(false);
        }

        // Write to storage
        self.write_to_storage(storage)
    }

    /// Enable recovery for this vault.
    ///
    /// Generates a random 256-bit recovery key, derives a wrapping key
    /// via HKDF, wraps the current KEK and MACKEY, and stores the
    /// recovery blob in the vault header. Returns the recovery key as
    /// a formatted string that the user must save.
    ///
    /// The vault must be unlocked. If recovery is already enabled,
    /// the old recovery data is replaced.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn enable_recovery(
        &mut self,
        storage: &dyn StorageBackend,
    ) -> crate::error::Result<String> {
        let kek = self.kek.as_ref().ok_or(Error::Vault(VaultError::Locked))?;
        let mackey = self
            .mackey
            .as_ref()
            .ok_or(Error::Vault(VaultError::Locked))?;

        let recovery_key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &salt)?;

        let (nonce, blob) = wrap_keys_for_recovery(&wrapping_key, kek, mackey)?;

        // Store in header
        self.header.recovery_salt = salt;
        self.header.recovery_nonce = nonce;
        self.header.recovery_blob.copy_from_slice(&blob);
        self.header.set_recovery_enabled(true);

        self.write_to_storage(storage)?;

        Ok(encode_recovery_key(&recovery_key))
    }

    /// Disable recovery for this vault.
    ///
    /// Zeros the recovery fields in the header and clears the recovery flag.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::Locked` if the vault is locked.
    pub fn disable_recovery(&mut self, storage: &dyn StorageBackend) -> crate::error::Result<()> {
        if self.state != VaultState::Unlocked {
            return Err(Error::Vault(VaultError::Locked));
        }

        self.header.recovery_salt = [0u8; 16];
        self.header.recovery_nonce = [0u8; 24];
        self.header.recovery_blob = [0u8; 80];
        self.header.set_recovery_enabled(false);

        self.write_to_storage(storage)
    }

    /// Recover a vault using a recovery key.
    ///
    /// Reads the vault from storage, decrypts the recovery blob to
    /// obtain KEK and MACKEY, verifies the HMAC, and returns an
    /// unlocked vault. The caller should then call `change_passphrase`
    /// to set a new passphrase.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::RecoveryNotEnabled` if recovery is not enabled.
    /// Returns `CryptoError::AuthenticationFailed` if the recovery key is wrong.
    pub fn recover(
        recovery_key_str: &str,
        storage: &dyn StorageBackend,
    ) -> crate::error::Result<Self> {
        let data = storage.read_vault()?;

        if data.len() < HEADER_SIZE + HMAC_SIZE {
            return Err(Error::Vault(VaultError::CorruptedData));
        }

        let header = parse_header(&data)?;

        if !header.recovery_enabled() {
            return Err(Error::Vault(VaultError::RecoveryNotEnabled));
        }

        // Decode and derive wrapping key
        let recovery_key = decode_recovery_key(recovery_key_str)?;
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &header.recovery_salt)?;

        // Unwrap KEK and MACKEY from recovery blob
        let (kek, mackey) = unwrap_keys_from_recovery(
            &wrapping_key,
            &header.recovery_nonce,
            &header.recovery_blob,
        )?;

        // Verify HMAC to confirm keys are correct
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entries::{decrypt_entry, encrypt_entry};

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
        let now = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);

        let entry_len = u32::try_from(encrypted.len()).expect("fits in u32");
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
                tags: vec![],
            },
        );
        vault.set_entries_blob(encrypted).unwrap();
        vault.write_to_storage(&storage).unwrap();

        // Reopen and verify
        let vault2 = Vault::open("pass", &storage, &params).unwrap();
        assert_eq!(vault2.index().entries.len(), 1);
        let meta = vault2.index().entries.get(&entry_uuid).unwrap();
        let blob = &vault2.entries_blob()
            [usize::try_from(meta.entry_offset).expect("fits in usize")..usize::try_from(meta.entry_offset).expect("fits in usize") + usize::try_from(meta.entry_length).expect("fits in usize")];
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
        let now = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);
        let entry_len = u32::try_from(encrypted.len()).expect("fits in u32");
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
                tags: vec![],
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
        let blob = &vault2.entries_blob()
            [usize::try_from(meta.entry_offset).expect("fits in usize")..usize::try_from(meta.entry_offset).expect("fits in usize") + usize::try_from(meta.entry_length).expect("fits in usize")];
        let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
        assert_eq!(decrypted, b"preserved data");
    }

    #[test]
    fn test_append_to_entries_blob_in_place() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();

        let data1 = b"entry-one";
        let (offset1, len1) = vault.append_to_entries_blob(data1).unwrap();
        assert_eq!(offset1, 0);
        assert_eq!(len1, 9);

        let data2 = b"entry-two";
        let (offset2, len2) = vault.append_to_entries_blob(data2).unwrap();
        assert_eq!(offset2, 9);
        assert_eq!(len2, 9);

        assert_eq!(vault.entries_blob().len(), 18);
        assert_eq!(&vault.entries_blob()[0..9], b"entry-one");
        assert_eq!(&vault.entries_blob()[9..18], b"entry-two");
    }

    #[test]
    fn test_append_to_entries_blob_locked_fails() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        vault.lock();
        assert!(vault.append_to_entries_blob(b"data").is_err());
    }

    #[test]
    fn test_compact_entries_blob_removes_dead_space() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();

        let kek = vault.kek().unwrap();
        let now = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);

        // Add three entries
        let enc1 = encrypt_entry(b"data-1", kek).unwrap();
        let enc2 = encrypt_entry(b"data-2", kek).unwrap();
        let enc3 = encrypt_entry(b"data-3", kek).unwrap();

        let (off1, len1) = vault.append_to_entries_blob(&enc1).unwrap();
        let (off2, len2) = vault.append_to_entries_blob(&enc2).unwrap();
        let (off3, len3) = vault.append_to_entries_blob(&enc3).unwrap();

        let uuid1 = [0x01; 16];
        let uuid2 = [0x02; 16];
        let uuid3 = [0x03; 16];

        for (uuid, off, len, title) in [
            (uuid1, off1, len1, "e1"),
            (uuid2, off2, len2, "e2"),
            (uuid3, off3, len3, "e3"),
        ] {
            vault.index_mut().unwrap().entries.insert(
                uuid,
                crate::vault::format::EntryMetadata {
                    uuid,
                    entry_offset: off,
                    entry_length: len,
                    created_at: now,
                    modified_at: now,
                    deleted: false,
                    title: title.to_string(),
                    tags: vec![],
                },
            );
        }

        let blob_before = vault.entries_blob().len();

        // Delete entry 2
        vault
            .index_mut()
            .unwrap()
            .entries
            .get_mut(&uuid2)
            .unwrap()
            .deleted = true;

        // Compact
        vault.compact_entries_blob().unwrap();

        let blob_after = vault.entries_blob().len();
        assert!(
            blob_after < blob_before,
            "compaction should reduce blob size"
        );

        // Verify live entries are still readable
        assert_eq!(vault.index().entries.len(), 2); // deleted entry removed
        assert!(!vault.index().entries.contains_key(&uuid2));

        for uuid in [uuid1, uuid3] {
            let meta = vault.index().entries.get(&uuid).unwrap();
            let start = usize::try_from(meta.entry_offset).expect("fits in usize");
            let end = start + usize::try_from(meta.entry_length).expect("fits in usize");
            let decrypted =
                decrypt_entry(&vault.entries_blob()[start..end], vault.kek().unwrap()).unwrap();
            assert!(decrypted.starts_with(b"data-"));
        }
    }

    #[test]
    fn test_compact_entries_blob_locked_fails() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        vault.lock();
        assert!(vault.compact_entries_blob().is_err());
    }

    // --- Recovery tests ---

    #[test]
    fn test_enable_recovery_returns_key() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        let key = vault.enable_recovery(&storage).unwrap();
        // Key should be 71 chars: 64 hex + 7 dashes
        assert_eq!(key.len(), 71);
        assert!(vault.header().recovery_enabled());
    }

    #[test]
    fn test_recover_with_correct_key_unlocks() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        let key = vault.enable_recovery(&storage).unwrap();
        drop(vault);

        let recovered = Vault::recover(&key, &storage).unwrap();
        assert_eq!(recovered.state(), VaultState::Unlocked);
    }

    #[test]
    fn test_recover_with_wrong_key_fails() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        let _key = vault.enable_recovery(&storage).unwrap();
        drop(vault);

        // Use a different (wrong) recovery key
        let wrong_key = "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD-EEEEEEEE-FFFFFFFF-00000000-11111111";
        let result = Vault::recover(wrong_key, &storage);
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_when_not_enabled_fails() {
        let storage = InMemStorage::new();
        Vault::init("pass", &storage, &test_params()).unwrap();

        let fake_key = "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD-EEEEEEEE-FFFFFFFF-00000000-11111111";
        let result = Vault::recover(fake_key, &storage);
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            Error::Vault(VaultError::RecoveryNotEnabled)
        ));
    }

    #[test]
    fn test_recover_then_change_passphrase_works() {
        let storage = InMemStorage::new();
        let params = test_params();
        let mut vault = Vault::init("old-pass", &storage, &params).unwrap();

        // Add an entry
        let kek = vault.kek().unwrap();
        let encrypted = encrypt_entry(b"my data", kek).unwrap();
        let entry_uuid = [0x77; 16];
        let now = u64::try_from(Timestamp::now().as_epoch_secs()).unwrap_or(0);
        let entry_len = u32::try_from(encrypted.len()).expect("fits in u32");
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
                tags: vec![],
            },
        );
        vault.set_entries_blob(encrypted).unwrap();
        vault.write_to_storage(&storage).unwrap();

        let key = vault.enable_recovery(&storage).unwrap();
        drop(vault);

        // Recover and set new passphrase
        let mut recovered = Vault::recover(&key, &storage).unwrap();
        recovered
            .change_passphrase("new-pass", &storage, &params)
            .unwrap();

        // Open with new passphrase should work
        let vault2 = Vault::open("new-pass", &storage, &params).unwrap();
        let meta = vault2.index().entries.get(&entry_uuid).unwrap();
        let blob = &vault2.entries_blob()
            [usize::try_from(meta.entry_offset).expect("fits in usize")..usize::try_from(meta.entry_offset).expect("fits in usize") + usize::try_from(meta.entry_length).expect("fits in usize")];
        let decrypted = decrypt_entry(blob, vault2.kek().unwrap()).unwrap();
        assert_eq!(decrypted, b"my data");
    }

    #[test]
    fn test_change_passphrase_invalidates_recovery() {
        let storage = InMemStorage::new();
        let params = test_params();
        let mut vault = Vault::init("pass", &storage, &params).unwrap();
        let key = vault.enable_recovery(&storage).unwrap();
        assert!(vault.header().recovery_enabled());

        vault
            .change_passphrase("new-pass", &storage, &params)
            .unwrap();

        // Recovery should now be disabled
        assert!(!vault.header().recovery_enabled());

        // Trying to recover with the old key should fail
        let result = Vault::recover(&key, &storage);
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            Error::Vault(VaultError::RecoveryNotEnabled)
        ));
    }

    #[test]
    fn test_enable_recovery_when_locked_fails() {
        let storage = InMemStorage::new();
        let mut vault = Vault::init("pass", &storage, &test_params()).unwrap();
        vault.lock();
        assert!(vault.enable_recovery(&storage).is_err());
    }
}

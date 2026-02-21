//! Entry-level encryption and decryption within the vault.
//!
//! Each entry is encrypted with a unique random DEK (Data Encryption Key),
//! which is in turn wrapped (encrypted) by the KEK (Key Encryption Key).
//!
//! # Encrypted Entry Format
//!
//! ```text
//! [nonce (24 bytes)] [wrapped_dek (48 bytes)] [ciphertext (variable)]
//! ```

use crate::crypto::aead::{
    aead_decrypt, aead_encrypt, generate_dek, generate_nonce, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};
use crate::crypto::secret_buf::SecretBuf;
use crate::error::{Error, VaultError};

/// Size of the encrypted entry prefix: nonce (24) + wrapped DEK (48).
pub const ENTRY_PREFIX_SIZE: usize = NONCE_SIZE + KEY_SIZE + TAG_SIZE;

/// Encrypt entry data for storage in the vault.
///
/// Generates a fresh random DEK, encrypts the entry data with the DEK,
/// then wraps the DEK with the KEK. Returns the complete encrypted blob.
///
/// # Encrypted blob format
///
/// ```text
/// [dek_nonce (24)] [wrapped_dek (48)] [data_nonce (24)] [ciphertext (variable + 16 tag)]
/// ```
///
/// # Arguments
///
/// * `entry_data` - The plaintext entry data (serialized entry)
/// * `kek` - The Key Encryption Key for wrapping the DEK
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt_entry(entry_data: &[u8], kek: &SecretBuf) -> crate::error::Result<Vec<u8>> {
    // Generate a fresh DEK for this entry
    let dek = generate_dek();

    // Wrap the DEK with the KEK
    let dek_nonce = generate_nonce();
    let wrapped_dek = aead_encrypt(kek, &dek_nonce, &[], &dek)?;

    // Encrypt the entry data with the DEK
    let data_nonce = generate_nonce();
    let ciphertext = aead_encrypt(&dek, &data_nonce, &[], entry_data)?;

    // Assemble: dek_nonce || wrapped_dek || data_nonce || ciphertext
    let mut blob =
        Vec::with_capacity(NONCE_SIZE + wrapped_dek.len() + NONCE_SIZE + ciphertext.len());
    blob.extend_from_slice(&dek_nonce);
    blob.extend_from_slice(&wrapped_dek);
    blob.extend_from_slice(&data_nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Decrypt an encrypted entry blob.
///
/// Extracts the wrapped DEK and nonce, unwraps the DEK using the KEK,
/// then decrypts the entry data using the DEK.
///
/// # Arguments
///
/// * `blob` - The encrypted entry blob
/// * `kek` - The Key Encryption Key for unwrapping the DEK
///
/// # Errors
///
/// Returns `VaultError::CorruptedData` if the blob is too short.
/// Returns `CryptoError::AuthenticationFailed` if the KEK is wrong or data is corrupted.
pub fn decrypt_entry(blob: &[u8], kek: &SecretBuf) -> crate::error::Result<Vec<u8>> {
    // Minimum size: dek_nonce (24) + wrapped_dek (48) + data_nonce (24) + tag (16)
    let min_size = NONCE_SIZE + KEY_SIZE + TAG_SIZE + NONCE_SIZE + TAG_SIZE;
    if blob.len() < min_size {
        return Err(Error::Vault(VaultError::CorruptedData));
    }

    // Parse the blob
    let dek_nonce = &blob[..NONCE_SIZE];
    let wrapped_dek = &blob[NONCE_SIZE..NONCE_SIZE + KEY_SIZE + TAG_SIZE];
    let data_nonce =
        &blob[NONCE_SIZE + KEY_SIZE + TAG_SIZE..NONCE_SIZE + KEY_SIZE + TAG_SIZE + NONCE_SIZE];
    let ciphertext = &blob[NONCE_SIZE + KEY_SIZE + TAG_SIZE + NONCE_SIZE..];

    // Unwrap the DEK
    let dek_bytes = aead_decrypt(kek, dek_nonce, &[], wrapped_dek)?;
    let dek = SecretBuf::from_bytes(&dek_bytes);

    // Decrypt the entry data
    aead_decrypt(&dek, data_nonce, &[], ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_kek() -> SecretBuf {
        let mut key = vec![0u8; KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut key);
        SecretBuf::from_bytes(&key)
    }

    #[test]
    fn test_encrypt_decrypt_entry_round_trip() {
        let kek = test_kek();
        let plaintext = b"username=admin\npassword=secret123";
        let blob = encrypt_entry(plaintext, &kek).unwrap();
        let decrypted = decrypt_entry(&blob, &kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_entry() {
        let kek = test_kek();
        let plaintext = b"";
        let blob = encrypt_entry(plaintext, &kek).unwrap();
        let decrypted = decrypt_entry(&blob, &kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_entry() {
        let kek = test_kek();
        let plaintext = vec![0xCDu8; 100_000];
        let blob = encrypt_entry(&plaintext, &kek).unwrap();
        let decrypted = decrypt_entry(&blob, &kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_kek_fails() {
        let kek1 = test_kek();
        let kek2 = test_kek();
        let blob = encrypt_entry(b"secret", &kek1).unwrap();
        let result = decrypt_entry(&blob, &kek2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_blob_fails() {
        let kek = test_kek();
        let mut blob = encrypt_entry(b"secret", &kek).unwrap();
        // Tamper with the ciphertext portion
        let last = blob.len() - 1;
        blob[last] ^= 1;
        let result = decrypt_entry(&blob, &kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_blob_fails() {
        let kek = test_kek();
        let result = decrypt_entry(&[0u8; 10], &kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_blobs() {
        let kek = test_kek();
        let blob1 = encrypt_entry(b"same data", &kek).unwrap();
        let blob2 = encrypt_entry(b"same data", &kek).unwrap();
        // Different DEKs and nonces mean different ciphertext
        assert_ne!(blob1, blob2);
    }
}

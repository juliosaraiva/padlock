//! XChaCha20-Poly1305 authenticated encryption and DEK management.
//!
//! Provides AEAD encryption and decryption using XChaCha20-Poly1305
//! with 256-bit keys and 192-bit nonces. The extended nonce size
//! enables safe use of random nonces without collision risk.
//!
//! Also provides Data Encryption Key (DEK) generation, wrapping, and
//! unwrapping. Each vault entry gets a unique random DEK that is
//! wrapped (encrypted) by the KEK.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

use super::secret_buf::SecretBuf;
use crate::error::{CryptoError, Error, Result};

/// Nonce size for XChaCha20-Poly1305 in bytes (192 bits).
pub const NONCE_SIZE: usize = 24;

/// Key size for XChaCha20-Poly1305 in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Authentication tag size in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// The returned ciphertext includes the Poly1305 authentication tag
/// appended at the end (16 bytes longer than the plaintext).
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (must be unique per key)
/// * `aad` - Additional authenticated data (may be empty)
/// * `plaintext` - Data to encrypt
///
/// # Errors
///
/// Returns `CryptoError::InvalidKeyLength` if the key is not 32 bytes.
/// Returns `CryptoError::InvalidNonceLength` if the nonce is not 24 bytes.
/// Returns `CryptoError::EncryptionFailed` if encryption fails.
pub fn aead_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    validate_key_length(key)?;
    validate_nonce_length(nonce)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;

    let nonce = chacha20poly1305::XNonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| Error::Crypto(CryptoError::EncryptionFailed(e.to_string())))
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
///
/// Verifies the Poly1305 authentication tag before returning plaintext.
/// If verification fails, no plaintext is returned.
///
/// # Arguments
///
/// * `key` - 32-byte decryption key
/// * `nonce` - 24-byte nonce used during encryption
/// * `aad` - Additional authenticated data used during encryption
/// * `ciphertext` - Data to decrypt (includes 16-byte auth tag)
///
/// # Errors
///
/// Returns `CryptoError::AuthenticationFailed` if the tag does not verify.
/// Returns `CryptoError::InvalidKeyLength` if the key is not 32 bytes.
/// Returns `CryptoError::InvalidNonceLength` if the nonce is not 24 bytes.
pub fn aead_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    validate_key_length(key)?;
    validate_nonce_length(nonce)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(CryptoError::DecryptionFailed(e.to_string())))?;

    let nonce = chacha20poly1305::XNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| Error::Crypto(CryptoError::AuthenticationFailed))
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305.
///
/// Uses the operating system's cryptographically secure random number
/// generator. The 192-bit nonce space makes random collisions
/// astronomically unlikely (birthday bound at ~2^96).
#[must_use]
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate a random Data Encryption Key (DEK).
///
/// Creates a fresh 256-bit random key for encrypting a single vault entry.
/// Each entry gets its own DEK to ensure compromise of one entry does not
/// affect others.
#[must_use]
pub fn generate_dek() -> SecretBuf {
    let mut dek = SecretBuf::new(KEY_SIZE);
    rand::rngs::OsRng.fill_bytes(dek.as_mut_slice());
    dek
}

/// Wrap (encrypt) a DEK using the KEK.
///
/// Encrypts the DEK with XChaCha20-Poly1305 using the KEK as the key
/// and a random nonce. Returns the wrapped DEK ciphertext and the nonce.
///
/// # Arguments
///
/// * `kek` - The Key Encryption Key (32 bytes)
/// * `dek` - The Data Encryption Key to wrap (32 bytes)
///
/// # Returns
///
/// A tuple of (wrapped_dek, nonce) where:
/// - `wrapped_dek` is 48 bytes (32 bytes DEK + 16 bytes auth tag)
/// - `nonce` is 24 bytes
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn wrap_dek(kek: &SecretBuf, dek: &SecretBuf) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
    let nonce = generate_nonce();
    let wrapped = aead_encrypt(kek, &nonce, &[], dek)?;
    Ok((wrapped, nonce))
}

/// Unwrap (decrypt) a DEK using the KEK.
///
/// Decrypts the wrapped DEK with XChaCha20-Poly1305 using the KEK.
///
/// # Arguments
///
/// * `kek` - The Key Encryption Key (32 bytes)
/// * `wrapped_dek` - The encrypted DEK (48 bytes)
/// * `nonce` - The nonce used during wrapping (24 bytes)
///
/// # Errors
///
/// Returns `CryptoError::AuthenticationFailed` if the KEK is wrong or data is corrupted.
pub fn unwrap_dek(
    kek: &SecretBuf,
    wrapped_dek: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<SecretBuf> {
    let plaintext = aead_decrypt(kek, nonce, &[], wrapped_dek)?;
    Ok(SecretBuf::from_bytes(&plaintext))
}

/// Validate that a key is the correct length (32 bytes).
fn validate_key_length(key: &[u8]) -> Result<()> {
    if key.len() != KEY_SIZE {
        return Err(Error::Crypto(CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        }));
    }
    Ok(())
}

/// Validate that a nonce is the correct length (24 bytes).
fn validate_nonce_length(nonce: &[u8]) -> Result<()> {
    if nonce.len() != NONCE_SIZE {
        return Err(Error::Crypto(CryptoError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_empty() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = b"";
        let ciphertext = aead_encrypt(&key, &nonce, &[], plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_small() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = b"hello world";
        let ciphertext = aead_encrypt(&key, &nonce, &[], plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
        let decrypted = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_large() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = vec![0xABu8; 10_000];
        let ciphertext = aead_encrypt(&key, &nonce, &[], &plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = b"secret data";
        let aad = b"authenticated metadata";
        let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        let nonce = generate_nonce();
        let ciphertext = aead_encrypt(&key1, &nonce, &[], b"secret").unwrap();
        let result = aead_decrypt(&key2, &nonce, &[], &ciphertext);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::Crypto(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = test_key();
        let nonce = generate_nonce();
        let ciphertext = aead_encrypt(&key, &nonce, b"correct aad", b"secret").unwrap();
        let result = aead_decrypt(&key, &nonce, b"wrong aad", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = generate_nonce();
        let mut ciphertext = aead_encrypt(&key, &nonce, &[], b"secret data").unwrap();
        // Flip a bit in the ciphertext
        ciphertext[0] ^= 1;
        let result = aead_decrypt(&key, &nonce, &[], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length_rejected() {
        let short_key = [0u8; 16];
        let nonce = generate_nonce();
        let result = aead_encrypt(&short_key, &nonce, &[], b"test");
        assert!(matches!(
            result.unwrap_err(),
            Error::Crypto(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_invalid_nonce_length_rejected() {
        let key = test_key();
        let short_nonce = [0u8; 12];
        let result = aead_encrypt(&key, &short_nonce, &[], b"test");
        assert!(matches!(
            result.unwrap_err(),
            Error::Crypto(CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 12
            })
        ));
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonces: HashSet<[u8; NONCE_SIZE]> = (0..1000).map(|_| generate_nonce()).collect();
        assert_eq!(nonces.len(), 1000, "all 1000 nonces must be unique");
    }

    #[test]
    fn test_generate_dek_length() {
        let dek = generate_dek();
        assert_eq!(dek.len(), KEY_SIZE, "DEK must be 32 bytes");
    }

    #[test]
    fn test_generate_dek_uniqueness() {
        let dek1 = generate_dek();
        let dek2 = generate_dek();
        assert_ne!(dek1, dek2, "generated DEKs must be unique");
    }

    #[test]
    fn test_dek_wrap_unwrap_round_trip() {
        let kek = SecretBuf::from_bytes(&test_key());
        let dek = generate_dek();
        let (wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
        assert_eq!(
            wrapped.len(),
            KEY_SIZE + TAG_SIZE,
            "wrapped DEK must be 48 bytes"
        );
        let unwrapped = unwrap_dek(&kek, &wrapped, &nonce).unwrap();
        assert_eq!(unwrapped, dek, "unwrapped DEK must match original");
    }

    #[test]
    fn test_dek_unwrap_wrong_kek_fails() {
        let kek1 = SecretBuf::from_bytes(&test_key());
        let kek2 = SecretBuf::from_bytes(&test_key());
        let dek = generate_dek();
        let (wrapped, nonce) = wrap_dek(&kek1, &dek).unwrap();
        let result = unwrap_dek(&kek2, &wrapped, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_dek_unwrap_tampered_data_fails() {
        let kek = SecretBuf::from_bytes(&test_key());
        let dek = generate_dek();
        let (mut wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
        wrapped[0] ^= 1;
        let result = unwrap_dek(&kek, &wrapped, &nonce);
        assert!(result.is_err());
    }
}

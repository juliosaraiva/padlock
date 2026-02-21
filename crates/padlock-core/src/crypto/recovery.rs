//! Recovery key cryptographic primitives.
//!
//! Provides generation, encoding/decoding, and key wrapping for vault
//! recovery keys. A recovery key is a 256-bit random secret that can
//! independently unlock the vault when the passphrase is forgotten.
//!
//! # Key Derivation
//!
//! ```text
//! Recovery Key (256-bit random)
//!       |
//!       | HKDF-SHA256(salt, info="padlock-recovery-wrap")
//!       v
//! Recovery Wrapping Key (256-bit)
//!       |
//!       | XChaCha20-Poly1305 encrypt(KEK || MACKEY)
//!       v
//! Recovery Blob (80 bytes: 64 plaintext + 16 auth tag)
//! ```

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use super::aead::{aead_decrypt, aead_encrypt, generate_nonce};
use super::secret_buf::SecretBuf;
use crate::error::{CryptoError, Error, Result};

/// Recovery key size in bytes (256 bits).
pub const RECOVERY_KEY_SIZE: usize = 32;

/// Recovery salt size in bytes (128 bits).
pub const RECOVERY_SALT_SIZE: usize = 16;

/// Recovery nonce size in bytes (192 bits).
pub const RECOVERY_NONCE_SIZE: usize = 24;

/// Recovery blob size in bytes (64 bytes plaintext + 16 bytes auth tag).
pub const RECOVERY_BLOB_SIZE: usize = 80;

/// HKDF info string for recovery wrapping key derivation.
const RECOVERY_WRAP_INFO: &[u8] = b"padlock-recovery-wrap";

/// Generate a random 256-bit recovery key.
///
/// Uses the OS CSPRNG to produce a full-entropy key. Unlike a passphrase,
/// this key has enough entropy that HKDF (without Argon2id) suffices
/// for deriving the wrapping key.
#[must_use]
pub fn generate_recovery_key() -> SecretBuf {
    let mut key = SecretBuf::new(RECOVERY_KEY_SIZE);
    rand::rngs::OsRng.fill_bytes(key.as_mut_slice());
    key
}

/// Encode a recovery key as uppercase hex with dash separators.
///
/// Format: 8 groups of 8 hex characters separated by dashes.
/// Example: `A1B2C3D4-E5F6A7B8-C9D0E1F2-A3B4C5D6-E7F8A9B0-C1D2E3F4-A5B6C7D8-E9F0A1B2`
#[must_use]
pub fn encode_recovery_key(key: &SecretBuf) -> String {
    use std::fmt::Write;
    let hex = key.iter().fold(String::with_capacity(64), |mut acc, b| {
        let _ = write!(acc, "{b:02X}");
        acc
    });
    hex.as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

/// Decode a recovery key from hex string.
///
/// Accepts uppercase or lowercase hex, with or without dashes.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKeyLength` if the decoded key is not 32 bytes.
/// Returns `CryptoError::InvalidEncoding` if the string contains non-UTF-8 or
/// non-hexadecimal characters.
pub fn decode_recovery_key(encoded: &str) -> Result<SecretBuf> {
    let hex: String = encoded.chars().filter(|c| *c != '-').collect();
    if hex.len() != RECOVERY_KEY_SIZE * 2 {
        return Err(Error::Crypto(CryptoError::InvalidKeyLength {
            expected: RECOVERY_KEY_SIZE,
            actual: hex.len() / 2,
        }));
    }

    let mut bytes = vec![0u8; RECOVERY_KEY_SIZE];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| {
            Error::Crypto(CryptoError::InvalidEncoding {
                reason: "recovery key contains non-UTF-8 characters".to_string(),
            })
        })?;
        bytes[i] = u8::from_str_radix(s, 16).map_err(|_| {
            Error::Crypto(CryptoError::InvalidEncoding {
                reason: "recovery key contains non-hexadecimal characters".to_string(),
            })
        })?;
    }

    let secret = SecretBuf::from_bytes(&bytes);
    bytes.zeroize();
    Ok(secret)
}

/// Derive a recovery wrapping key from the recovery key and salt.
///
/// Uses HKDF-SHA256 with an explicit salt and the info string
/// `"padlock-recovery-wrap"`. The salt provides domain separation
/// between different vaults that might use the same recovery key
/// (though in practice each vault generates its own).
///
/// # Errors
///
/// Returns `CryptoError::HkdfError` if key expansion fails.
pub fn derive_recovery_wrapping_key(
    recovery_key: &SecretBuf,
    salt: &[u8; RECOVERY_SALT_SIZE],
) -> Result<SecretBuf> {
    let hk = Hkdf::<Sha256>::new(Some(salt), recovery_key);
    let mut output = SecretBuf::new(RECOVERY_KEY_SIZE);
    hk.expand(RECOVERY_WRAP_INFO, output.as_mut_slice())
        .map_err(|_| Error::Crypto(CryptoError::HkdfError))?;
    Ok(output)
}

/// Wrap KEK and MACKEY for recovery storage.
///
/// Concatenates KEK (32 bytes) and MACKEY (32 bytes) into a 64-byte
/// plaintext, then encrypts with XChaCha20-Poly1305 using the recovery
/// wrapping key. Returns the nonce and ciphertext (blob).
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn wrap_keys_for_recovery(
    wrapping_key: &SecretBuf,
    kek: &SecretBuf,
    mackey: &SecretBuf,
) -> Result<([u8; RECOVERY_NONCE_SIZE], Vec<u8>)> {
    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(kek);
    plaintext.extend_from_slice(mackey);

    let nonce = generate_nonce();
    let blob = aead_encrypt(wrapping_key, &nonce, &[], &plaintext)?;

    // Zeroize the plaintext buffer
    plaintext.fill(0);

    Ok((nonce, blob))
}

/// Unwrap KEK and MACKEY from a recovery blob.
///
/// Decrypts the blob using the recovery wrapping key, then splits
/// the resulting 64-byte plaintext into KEK (first 32 bytes) and
/// MACKEY (last 32 bytes).
///
/// # Errors
///
/// Returns `CryptoError::AuthenticationFailed` if the wrapping key is wrong
/// or the blob is corrupted.
pub fn unwrap_keys_from_recovery(
    wrapping_key: &SecretBuf,
    nonce: &[u8; RECOVERY_NONCE_SIZE],
    blob: &[u8],
) -> Result<(SecretBuf, SecretBuf)> {
    let plaintext = aead_decrypt(wrapping_key, nonce, &[], blob)?;

    if plaintext.len() != 64 {
        return Err(Error::Crypto(CryptoError::InvalidKeyLength {
            expected: 64,
            actual: plaintext.len(),
        }));
    }

    let kek = SecretBuf::from_bytes(&plaintext[..32]);
    let mackey = SecretBuf::from_bytes(&plaintext[32..]);

    Ok((kek, mackey))
}

/// Generate a random 16-byte salt for recovery HKDF.
#[must_use]
pub fn generate_recovery_salt() -> [u8; RECOVERY_SALT_SIZE] {
    let mut salt = [0u8; RECOVERY_SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_key_length() {
        let key = generate_recovery_key();
        assert_eq!(key.len(), RECOVERY_KEY_SIZE);
    }

    #[test]
    fn test_generate_recovery_key_uniqueness() {
        let key1 = generate_recovery_key();
        let key2 = generate_recovery_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let key = generate_recovery_key();
        let encoded = encode_recovery_key(&key);
        let decoded = decode_recovery_key(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_encode_format() {
        let key = generate_recovery_key();
        let encoded = encode_recovery_key(&key);
        // 8 groups of 8 chars separated by 7 dashes = 64 + 7 = 71 chars
        assert_eq!(encoded.len(), 71);
        assert_eq!(encoded.matches('-').count(), 7);
        // All chars are uppercase hex or dashes
        assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(encoded
            .chars()
            .filter(char::is_ascii_alphabetic)
            .all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_decode_rejects_invalid_hex() {
        let result = decode_recovery_key(
            "ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ-ZZZZZZZZ",
        );
        assert!(matches!(
            result,
            Err(crate::error::Error::Crypto(
                crate::error::CryptoError::InvalidEncoding { .. }
            ))
        ));
    }

    #[test]
    fn test_decode_rejects_wrong_length() {
        let result = decode_recovery_key("AABBCCDD");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_accepts_lowercase_and_no_dashes() {
        let key = generate_recovery_key();
        let encoded = encode_recovery_key(&key);

        // Lowercase without dashes
        let lowercase_no_dashes: String = encoded.to_lowercase().replace('-', "");
        let decoded = decode_recovery_key(&lowercase_no_dashes).unwrap();
        assert_eq!(key, decoded);

        // Lowercase with dashes
        let lowercase = encoded.to_lowercase();
        let decoded = decode_recovery_key(&lowercase).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_derive_wrapping_key_deterministic() {
        let key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wk1 = derive_recovery_wrapping_key(&key, &salt).unwrap();
        let wk2 = derive_recovery_wrapping_key(&key, &salt).unwrap();
        assert_eq!(wk1, wk2);
    }

    #[test]
    fn test_derive_wrapping_key_different_salts() {
        let key = generate_recovery_key();
        let salt1 = [0x01u8; RECOVERY_SALT_SIZE];
        let salt2 = [0x02u8; RECOVERY_SALT_SIZE];
        let wk1 = derive_recovery_wrapping_key(&key, &salt1).unwrap();
        let wk2 = derive_recovery_wrapping_key(&key, &salt2).unwrap();
        assert_ne!(wk1, wk2);
    }

    #[test]
    fn test_wrap_unwrap_round_trip() {
        let recovery_key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &salt).unwrap();

        let kek = SecretBuf::from_bytes(&[0xAA; 32]);
        let mackey = SecretBuf::from_bytes(&[0xBB; 32]);

        let (nonce, blob) = wrap_keys_for_recovery(&wrapping_key, &kek, &mackey).unwrap();
        let (recovered_kek, recovered_mackey) =
            unwrap_keys_from_recovery(&wrapping_key, &nonce, &blob).unwrap();

        assert_eq!(kek, recovered_kek);
        assert_eq!(mackey, recovered_mackey);
    }

    #[test]
    fn test_wrap_blob_size() {
        let recovery_key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &salt).unwrap();

        let kek = SecretBuf::from_bytes(&[0xAA; 32]);
        let mackey = SecretBuf::from_bytes(&[0xBB; 32]);

        let (_nonce, blob) = wrap_keys_for_recovery(&wrapping_key, &kek, &mackey).unwrap();
        assert_eq!(blob.len(), RECOVERY_BLOB_SIZE);
    }

    #[test]
    fn test_unwrap_wrong_key_fails() {
        let recovery_key = generate_recovery_key();
        let wrong_key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &salt).unwrap();
        let wrong_wrapping_key = derive_recovery_wrapping_key(&wrong_key, &salt).unwrap();

        let kek = SecretBuf::from_bytes(&[0xAA; 32]);
        let mackey = SecretBuf::from_bytes(&[0xBB; 32]);

        let (nonce, blob) = wrap_keys_for_recovery(&wrapping_key, &kek, &mackey).unwrap();
        let result = unwrap_keys_from_recovery(&wrong_wrapping_key, &nonce, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_corrupted_blob_fails() {
        let recovery_key = generate_recovery_key();
        let salt = generate_recovery_salt();
        let wrapping_key = derive_recovery_wrapping_key(&recovery_key, &salt).unwrap();

        let kek = SecretBuf::from_bytes(&[0xAA; 32]);
        let mackey = SecretBuf::from_bytes(&[0xBB; 32]);

        let (nonce, mut blob) = wrap_keys_for_recovery(&wrapping_key, &kek, &mackey).unwrap();
        blob[0] ^= 0xFF; // Corrupt the blob
        let result = unwrap_keys_from_recovery(&wrapping_key, &nonce, &blob);
        assert!(result.is_err());
    }
}

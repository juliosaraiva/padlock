//! HKDF-SHA-256 subkey derivation from the Primary Derivation Key.
//!
//! Derives purpose-specific keys (KEK, MACKEY) from the PDK using
//! HKDF (RFC 5869) with distinct info strings to ensure cryptographic
//! separation between keys used for different purposes.
//!
//! # Key Separation
//!
//! - KEK (Key Encryption Key): info = "padlock-vault-kek"
//! - MACKEY (HMAC Key): info = "padlock-vault-mackey"
//!
//! Different info strings guarantee that KEK and MACKEY are
//! cryptographically independent even though they derive from the same PDK.

use hkdf::Hkdf;
use sha2::Sha256;

use super::secret_buf::SecretBuf;
use crate::error::{CryptoError, Error, Result};

/// HKDF info string for the Key Encryption Key.
pub const KEK_INFO: &[u8] = b"padlock-vault-kek";

/// HKDF info string for the HMAC key.
pub const MACKEY_INFO: &[u8] = b"padlock-vault-mackey";

/// Subkey length in bytes (256 bits).
pub const SUBKEY_LENGTH: usize = 32;

/// Derive the Key Encryption Key (KEK) from the PDK.
///
/// Uses HKDF-SHA-256 with info string "padlock-vault-kek" to derive
/// a 256-bit key used exclusively for wrapping/unwrapping Data Encryption
/// Keys (DEKs).
///
/// # Arguments
///
/// * `pdk` - The Primary Derivation Key (32 bytes)
///
/// # Errors
///
/// Returns `CryptoError::HkdfError` if key expansion fails.
pub fn derive_kek(pdk: &SecretBuf) -> Result<SecretBuf> {
    expand_key(pdk, KEK_INFO, SUBKEY_LENGTH)
}

/// Derive the HMAC key (MACKEY) from the PDK.
///
/// Uses HKDF-SHA-256 with info string "padlock-vault-mackey" to derive
/// a 256-bit key used for computing the vault integrity HMAC.
///
/// # Arguments
///
/// * `pdk` - The Primary Derivation Key (32 bytes)
///
/// # Errors
///
/// Returns `CryptoError::HkdfError` if key expansion fails.
pub fn derive_mackey(pdk: &SecretBuf) -> Result<SecretBuf> {
    expand_key(pdk, MACKEY_INFO, SUBKEY_LENGTH)
}

/// Generic HKDF-SHA-256 key expansion.
///
/// Expands the input key material using HKDF with the given info string
/// to produce a key of the specified length.
///
/// # Arguments
///
/// * `ikm` - Input key material (e.g., PDK)
/// * `info` - Context/purpose string for domain separation
/// * `length` - Desired output key length in bytes
///
/// # Errors
///
/// Returns `CryptoError::HkdfError` if expansion fails.
pub fn expand_key(ikm: &SecretBuf, info: &[u8], length: usize) -> Result<SecretBuf> {
    // HKDF with no explicit salt (uses zero-filled salt per RFC 5869)
    let hk = Hkdf::<Sha256>::new(None, ikm);

    let mut output = SecretBuf::new(length);
    hk.expand(info, output.as_mut_slice())
        .map_err(|_| Error::Crypto(CryptoError::HkdfError))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_pdk_for_testing;

    fn test_pdk() -> SecretBuf {
        let salt = [1u8; 16];
        derive_pdk_for_testing("test passphrase", &salt).unwrap()
    }

    #[test]
    fn test_derive_kek_deterministic() {
        let pdk = test_pdk();
        let kek1 = derive_kek(&pdk).unwrap();
        let kek2 = derive_kek(&pdk).unwrap();
        assert_eq!(kek1, kek2, "same PDK must produce same KEK");
    }

    #[test]
    fn test_derive_mackey_deterministic() {
        let pdk = test_pdk();
        let mackey1 = derive_mackey(&pdk).unwrap();
        let mackey2 = derive_mackey(&pdk).unwrap();
        assert_eq!(mackey1, mackey2, "same PDK must produce same MACKEY");
    }

    #[test]
    fn test_kek_and_mackey_are_different() {
        let pdk = test_pdk();
        let kek = derive_kek(&pdk).unwrap();
        let mackey = derive_mackey(&pdk).unwrap();
        assert_ne!(
            kek, mackey,
            "KEK and MACKEY must differ due to different info strings"
        );
    }

    #[test]
    fn test_derive_kek_output_length() {
        let pdk = test_pdk();
        let kek = derive_kek(&pdk).unwrap();
        assert_eq!(kek.len(), SUBKEY_LENGTH, "KEK must be 32 bytes");
    }

    #[test]
    fn test_derive_mackey_output_length() {
        let pdk = test_pdk();
        let mackey = derive_mackey(&pdk).unwrap();
        assert_eq!(mackey.len(), SUBKEY_LENGTH, "MACKEY must be 32 bytes");
    }

    #[test]
    fn test_different_pdks_produce_different_keks() {
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let pdk1 = derive_pdk_for_testing("pass1", &salt1).unwrap();
        let pdk2 = derive_pdk_for_testing("pass2", &salt2).unwrap();
        let kek1 = derive_kek(&pdk1).unwrap();
        let kek2 = derive_kek(&pdk2).unwrap();
        assert_ne!(kek1, kek2, "different PDKs must produce different KEKs");
    }

    #[test]
    fn test_expand_key_custom_info() {
        let pdk = test_pdk();
        let key1 = expand_key(&pdk, b"info-one", 32).unwrap();
        let key2 = expand_key(&pdk, b"info-two", 32).unwrap();
        assert_ne!(
            key1, key2,
            "different info strings must produce different keys"
        );
    }

    #[test]
    fn test_expand_key_custom_length() {
        let pdk = test_pdk();
        let key16 = expand_key(&pdk, b"test", 16).unwrap();
        let key64 = expand_key(&pdk, b"test", 64).unwrap();
        assert_eq!(key16.len(), 16);
        assert_eq!(key64.len(), 64);
    }
}

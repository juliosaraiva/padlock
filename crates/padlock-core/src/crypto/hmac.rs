//! HMAC-SHA-256 for vault integrity verification.
//!
//! Provides authenticated integrity checking for the vault file.
//! All comparisons use constant-time operations to prevent timing attacks.
//!
//! The HMAC is computed over the entire vault file (header + index + entries)
//! using the MACKEY derived from the PDK. This detects both accidental
//! corruption and intentional tampering.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CryptoError, Error, Result};

/// HMAC output size in bytes (256 bits).
pub const HMAC_SIZE: usize = 32;

/// Type alias for HMAC-SHA-256.
type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA-256 over the given data.
///
/// # Arguments
///
/// * `key` - HMAC key (MACKEY derived from PDK, typically 32 bytes)
/// * `data` - Data to authenticate
///
/// # Returns
///
/// A 32-byte HMAC tag.
#[must_use]
pub fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; HMAC_SIZE];
    output.copy_from_slice(&bytes);
    output
}

/// Verify HMAC-SHA-256 using constant-time comparison.
///
/// Computes the HMAC over the data and compares it with the expected
/// tag using constant-time comparison to prevent timing side channels.
///
/// # Arguments
///
/// * `key` - HMAC key (MACKEY derived from PDK)
/// * `data` - Data that was authenticated
/// * `expected_tag` - The expected HMAC tag to verify against
///
/// # Errors
///
/// Returns `CryptoError::AuthenticationFailed` if the HMAC does not match.
pub fn verify_hmac(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts any key length");
    mac.update(data);

    mac.verify_slice(expected_tag)
        .map_err(|_| Error::Crypto(CryptoError::AuthenticationFailed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]
    }

    #[test]
    fn test_compute_verify_round_trip() {
        let key = test_key();
        let data = b"vault data to authenticate";
        let tag = compute_hmac(&key, data);
        assert!(verify_hmac(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_compute_hmac_deterministic() {
        let key = test_key();
        let data = b"deterministic test";
        let tag1 = compute_hmac(&key, data);
        let tag2 = compute_hmac(&key, data);
        assert_eq!(tag1, tag2, "same inputs must produce same HMAC");
    }

    #[test]
    fn test_compute_hmac_output_length() {
        let key = test_key();
        let tag = compute_hmac(&key, b"test");
        assert_eq!(tag.len(), HMAC_SIZE);
    }

    #[test]
    fn test_verify_hmac_rejects_wrong_key() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 1;
        let data = b"test data";
        let tag = compute_hmac(&key1, data);
        let result = verify_hmac(&key2, data, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_rejects_tampered_data() {
        let key = test_key();
        let data = b"original data";
        let tag = compute_hmac(&key, data);
        let result = verify_hmac(&key, b"modified data", &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_rejects_single_bit_flip() {
        let key = test_key();
        let data = b"test data for bit flip";
        let mut tag = compute_hmac(&key, data);
        tag[0] ^= 1; // Flip one bit in the tag
        let result = verify_hmac(&key, data, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_rejects_wrong_length_tag() {
        let key = test_key();
        let data = b"test";
        let short_tag = [0u8; 16];
        let result = verify_hmac(&key, data, &short_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_hmac_different_data_different_tags() {
        let key = test_key();
        let tag1 = compute_hmac(&key, b"data one");
        let tag2 = compute_hmac(&key, b"data two");
        assert_ne!(tag1, tag2, "different data must produce different HMACs");
    }

    #[test]
    fn test_compute_hmac_different_keys_different_tags() {
        let mut key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF;
        let data = b"same data";
        let tag1 = compute_hmac(&key1, data);
        let tag2 = compute_hmac(&key2, data);
        assert_ne!(tag1, tag2, "different keys must produce different HMACs");
        // Suppress unused_assignments warning
        key1[0] = 0;
        let _ = key1;
    }

    #[test]
    fn test_compute_hmac_empty_data() {
        let key = test_key();
        let tag = compute_hmac(&key, b"");
        assert_eq!(tag.len(), HMAC_SIZE);
        // Empty data HMAC should still be a valid tag
        assert!(verify_hmac(&key, b"", &tag).is_ok());
    }
}

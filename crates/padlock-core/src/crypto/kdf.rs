//! Argon2id key derivation for passphrase-based key generation.
//!
//! Derives the Primary Derivation Key (PDK) from a user passphrase
//! using Argon2id with memory-hard parameters that resist GPU and
//! ASIC-based brute force attacks.
//!
//! # Parameters
//!
//! Production parameters (tuned for ~2-3 second derivation):
//! - Memory: 1 GiB (1,048,576 KiB)
//! - Time cost: 2 iterations
//! - Parallelism: 4 threads
//!
//! Test parameters (fast, for unit tests):
//! - Memory: 64 KiB
//! - Time cost: 1 iteration
//! - Parallelism: 1 thread

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use super::secret_buf::SecretBuf;
use crate::error::{CryptoError, Error, Result};

/// Salt length for Argon2id in bytes (128 bits).
pub const SALT_LENGTH: usize = 16;

/// Output key length for PDK in bytes (256 bits).
pub const PDK_LENGTH: usize = 32;

/// Argon2id memory cost in KiB for production (1 GiB).
pub const ARGON2_MEMORY_KIB: u32 = 1_048_576;

/// Argon2id time cost (iterations) for production.
pub const ARGON2_TIME_COST: u32 = 2;

/// Argon2id parallelism (threads) for production.
pub const ARGON2_PARALLELISM: u32 = 4;

/// Argon2id memory cost in KiB for testing (64 KiB).
const TEST_ARGON2_MEMORY_KIB: u32 = 64;

/// Argon2id time cost for testing.
const TEST_ARGON2_TIME_COST: u32 = 1;

/// Argon2id parallelism for testing.
const TEST_ARGON2_PARALLELISM: u32 = 1;

/// Derive the Primary Derivation Key (PDK) from a passphrase and salt.
///
/// Uses Argon2id with memory-hard parameters to produce a 256-bit key.
/// In production, this operation intentionally takes approximately 2-3
/// seconds to complete, making brute-force attacks impractical.
///
/// # Arguments
///
/// * `passphrase` - The user's passphrase (UTF-8)
/// * `salt` - 16-byte random salt (stored in vault header)
///
/// # Errors
///
/// Returns `CryptoError::InvalidSaltLength` if the salt is not 16 bytes.
/// Returns `CryptoError::Argon2Error` if key derivation fails.
pub fn derive_pdk(passphrase: &str, salt: &[u8]) -> Result<SecretBuf> {
    derive_pdk_with_params(
        passphrase,
        salt,
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
    )
}

/// Derive PDK with explicit Argon2id parameters.
///
/// This function is used internally and by tests to allow customizing
/// the memory/time/parallelism parameters.
///
/// # Errors
///
/// Returns `CryptoError::InvalidSaltLength` if the salt is not 16 bytes.
/// Returns `CryptoError::Argon2Error` if key derivation fails.
pub fn derive_pdk_with_params(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<SecretBuf> {
    if salt.len() != SALT_LENGTH {
        return Err(Error::Crypto(CryptoError::InvalidSaltLength {
            expected: SALT_LENGTH,
            actual: salt.len(),
        }));
    }

    let params = Params::new(memory_kib, time_cost, parallelism, Some(PDK_LENGTH))
        .map_err(|e| Error::Crypto(CryptoError::Argon2Error(e.to_string())))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = SecretBuf::new(PDK_LENGTH);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, output.as_mut_slice())
        .map_err(|e| Error::Crypto(CryptoError::Argon2Error(e.to_string())))?;

    Ok(output)
}

/// Derive PDK with reduced parameters suitable for testing.
///
/// Uses 64 KiB memory, 1 iteration, 1 thread for fast execution
/// in unit and integration tests.
///
/// # Errors
///
/// Returns errors if salt is invalid or derivation fails.
pub fn derive_pdk_for_testing(passphrase: &str, salt: &[u8]) -> Result<SecretBuf> {
    derive_pdk_with_params(
        passphrase,
        salt,
        TEST_ARGON2_MEMORY_KIB,
        TEST_ARGON2_TIME_COST,
        TEST_ARGON2_PARALLELISM,
    )
}

/// Generate a random 16-byte salt for Argon2id.
///
/// Uses the operating system's cryptographically secure random number
/// generator via `rand::OsRng`.
#[must_use]
pub fn generate_argon2_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; SALT_LENGTH] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    }

    #[test]
    fn test_derive_pdk_deterministic_same_inputs() {
        let salt = test_salt();
        let pdk1 = derive_pdk_for_testing("test passphrase", &salt).unwrap();
        let pdk2 = derive_pdk_for_testing("test passphrase", &salt).unwrap();
        assert_eq!(pdk1, pdk2, "same passphrase + salt must produce same PDK");
    }

    #[test]
    fn test_derive_pdk_different_salts_produce_different_keys() {
        let salt1 = [1u8; SALT_LENGTH];
        let salt2 = [2u8; SALT_LENGTH];
        let pdk1 = derive_pdk_for_testing("same passphrase", &salt1).unwrap();
        let pdk2 = derive_pdk_for_testing("same passphrase", &salt2).unwrap();
        assert_ne!(pdk1, pdk2, "different salts must produce different PDKs");
    }

    #[test]
    fn test_derive_pdk_different_passphrases_produce_different_keys() {
        let salt = test_salt();
        let pdk1 = derive_pdk_for_testing("passphrase one", &salt).unwrap();
        let pdk2 = derive_pdk_for_testing("passphrase two", &salt).unwrap();
        assert_ne!(
            pdk1, pdk2,
            "different passphrases must produce different PDKs"
        );
    }

    #[test]
    fn test_derive_pdk_output_length() {
        let salt = test_salt();
        let pdk = derive_pdk_for_testing("test", &salt).unwrap();
        assert_eq!(pdk.len(), PDK_LENGTH, "PDK must be 32 bytes");
    }

    #[test]
    fn test_derive_pdk_rejects_wrong_salt_length() {
        let short_salt = [0u8; 8];
        let result = derive_pdk_for_testing("test", &short_salt);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Crypto(CryptoError::InvalidSaltLength {
                expected: 16,
                actual: 8,
            }) => {}
            other => panic!("expected InvalidSaltLength, got: {other}"),
        }
    }

    #[test]
    fn test_derive_pdk_rejects_empty_salt() {
        let result = derive_pdk_for_testing("test", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_argon2_salt_is_unique() {
        let salt1 = generate_argon2_salt();
        let salt2 = generate_argon2_salt();
        assert_ne!(salt1, salt2, "generated salts must be unique");
    }

    #[test]
    fn test_generate_argon2_salt_length() {
        let salt = generate_argon2_salt();
        assert_eq!(salt.len(), SALT_LENGTH, "salt must be 16 bytes");
    }

    #[test]
    fn test_derive_pdk_empty_passphrase_still_works() {
        let salt = test_salt();
        let pdk = derive_pdk_for_testing("", &salt).unwrap();
        assert_eq!(pdk.len(), PDK_LENGTH);
    }

    #[test]
    fn test_derive_pdk_unicode_passphrase() {
        let salt = test_salt();
        let pdk = derive_pdk_for_testing("correct horse battery staple", &salt).unwrap();
        assert_eq!(pdk.len(), PDK_LENGTH);
    }
}

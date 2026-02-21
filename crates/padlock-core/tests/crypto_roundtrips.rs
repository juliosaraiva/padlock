//! Integration tests for cryptographic operations.
//!
//! Tests AEAD encrypt/decrypt round-trips, HMAC compute/verify,
//! KDF determinism, and rejection of wrong keys and tampered data.

use padlock_core::crypto::aead::{
    aead_decrypt, aead_encrypt, generate_dek, generate_nonce, unwrap_dek, wrap_dek, KEY_SIZE,
    NONCE_SIZE, TAG_SIZE,
};
use padlock_core::crypto::hmac::{compute_hmac, verify_hmac, HMAC_SIZE};
use padlock_core::crypto::kdf::{derive_pdk_for_testing, generate_argon2_salt, SALT_LENGTH};
use padlock_core::crypto::SecretBuf;
use rand::RngCore;

fn random_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn random_secret_buf() -> SecretBuf {
    SecretBuf::from_bytes(&random_key())
}

// ============================================================
// AEAD Encrypt/Decrypt Round-Trips
// ============================================================

#[test]
fn test_aead_roundtrip_empty_payload() {
    let key = random_key();
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(&key, &nonce, &[], b"").unwrap();
    assert_eq!(ciphertext.len(), TAG_SIZE); // only tag, no data
    let plaintext = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
    assert!(plaintext.is_empty());
}

#[test]
fn test_aead_roundtrip_small_payload() {
    let key = random_key();
    let nonce = generate_nonce();
    let data = b"short message";
    let ciphertext = aead_encrypt(&key, &nonce, &[], data).unwrap();
    let plaintext = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_aead_roundtrip_large_payload() {
    let key = random_key();
    let nonce = generate_nonce();
    let data = vec![0xCDu8; 1_000_000]; // 1 MB
    let ciphertext = aead_encrypt(&key, &nonce, &[], &data).unwrap();
    assert_eq!(ciphertext.len(), data.len() + TAG_SIZE);
    let plaintext = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_aead_roundtrip_with_aad() {
    let key = random_key();
    let nonce = generate_nonce();
    let data = b"secret payload";
    let aad = b"authenticated-but-not-encrypted metadata";
    let ciphertext = aead_encrypt(&key, &nonce, aad, data).unwrap();
    let plaintext = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_aead_roundtrip_binary_payload() {
    let key = random_key();
    let nonce = generate_nonce();
    // All possible byte values
    let data: Vec<u8> = (0u8..=255).collect();
    let ciphertext = aead_encrypt(&key, &nonce, &[], &data).unwrap();
    let plaintext = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
    assert_eq!(plaintext, data);
}

// ============================================================
// AEAD Wrong Key Rejection
// ============================================================

#[test]
fn test_aead_decrypt_wrong_key_fails() {
    let key1 = random_key();
    let key2 = random_key();
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(&key1, &nonce, &[], b"secret data").unwrap();
    let result = aead_decrypt(&key2, &nonce, &[], &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_aead_decrypt_wrong_nonce_fails() {
    let key = random_key();
    let nonce1 = generate_nonce();
    let nonce2 = generate_nonce();
    let ciphertext = aead_encrypt(&key, &nonce1, &[], b"secret data").unwrap();
    let result = aead_decrypt(&key, &nonce2, &[], &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_aead_decrypt_wrong_aad_fails() {
    let key = random_key();
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(&key, &nonce, b"correct-aad", b"data").unwrap();
    let result = aead_decrypt(&key, &nonce, b"wrong-aad", &ciphertext);
    assert!(result.is_err());
}

// ============================================================
// AEAD Tampered Ciphertext Rejection
// ============================================================

#[test]
fn test_aead_tampered_ciphertext_first_byte_fails() {
    let key = random_key();
    let nonce = generate_nonce();
    let mut ciphertext = aead_encrypt(&key, &nonce, &[], b"secret data").unwrap();
    ciphertext[0] ^= 0x01;
    let result = aead_decrypt(&key, &nonce, &[], &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_aead_tampered_ciphertext_last_byte_fails() {
    let key = random_key();
    let nonce = generate_nonce();
    let mut ciphertext = aead_encrypt(&key, &nonce, &[], b"secret data").unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;
    let result = aead_decrypt(&key, &nonce, &[], &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_aead_tampered_tag_fails() {
    let key = random_key();
    let nonce = generate_nonce();
    let mut ciphertext = aead_encrypt(&key, &nonce, &[], b"secret data").unwrap();
    // Tag is the last 16 bytes
    let tag_start = ciphertext.len() - TAG_SIZE;
    ciphertext[tag_start] ^= 0xFF;
    let result = aead_decrypt(&key, &nonce, &[], &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_aead_truncated_ciphertext_fails() {
    let key = random_key();
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(&key, &nonce, &[], b"secret data").unwrap();
    // Remove last byte (truncate tag)
    let truncated = &ciphertext[..ciphertext.len() - 1];
    let result = aead_decrypt(&key, &nonce, &[], truncated);
    assert!(result.is_err());
}

// ============================================================
// DEK Wrap/Unwrap
// ============================================================

#[test]
fn test_dek_wrap_unwrap_roundtrip() {
    let kek = random_secret_buf();
    let dek = generate_dek();
    let (wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
    assert_eq!(wrapped.len(), KEY_SIZE + TAG_SIZE);
    let unwrapped = unwrap_dek(&kek, &wrapped, &nonce).unwrap();
    assert_eq!(unwrapped, dek);
}

#[test]
fn test_dek_unwrap_wrong_kek_fails() {
    let kek1 = random_secret_buf();
    let kek2 = random_secret_buf();
    let dek = generate_dek();
    let (wrapped, nonce) = wrap_dek(&kek1, &dek).unwrap();
    let result = unwrap_dek(&kek2, &wrapped, &nonce);
    assert!(result.is_err());
}

#[test]
fn test_dek_unwrap_tampered_data_fails() {
    let kek = random_secret_buf();
    let dek = generate_dek();
    let (mut wrapped, nonce) = wrap_dek(&kek, &dek).unwrap();
    wrapped[0] ^= 0x01;
    let result = unwrap_dek(&kek, &wrapped, &nonce);
    assert!(result.is_err());
}

// ============================================================
// HMAC Compute/Verify Round-Trip
// ============================================================

#[test]
fn test_hmac_compute_verify_roundtrip() {
    let key = random_key();
    let data = b"vault header || index || entries blob";
    let tag = compute_hmac(&key, data);
    assert_eq!(tag.len(), HMAC_SIZE);
    assert!(verify_hmac(&key, data, &tag).is_ok());
}

#[test]
fn test_hmac_verify_empty_data() {
    let key = random_key();
    let tag = compute_hmac(&key, b"");
    assert!(verify_hmac(&key, b"", &tag).is_ok());
}

#[test]
fn test_hmac_verify_large_data() {
    let key = random_key();
    let data = vec![0xABu8; 100_000];
    let tag = compute_hmac(&key, &data);
    assert!(verify_hmac(&key, &data, &tag).is_ok());
}

// ============================================================
// HMAC Wrong Key Rejection
// ============================================================

#[test]
fn test_hmac_wrong_key_fails() {
    let key1 = random_key();
    let mut key2 = random_key();
    // Ensure keys differ
    key2[0] = key1[0].wrapping_add(1);
    let data = b"authenticated data";
    let tag = compute_hmac(&key1, data);
    let result = verify_hmac(&key2, data, &tag);
    assert!(result.is_err());
}

// ============================================================
// HMAC Tampered Data Rejection
// ============================================================

#[test]
fn test_hmac_tampered_data_fails() {
    let key = random_key();
    let tag = compute_hmac(&key, b"original data");
    let result = verify_hmac(&key, b"modified data", &tag);
    assert!(result.is_err());
}

#[test]
fn test_hmac_tampered_tag_single_bit_fails() {
    let key = random_key();
    let data = b"data to authenticate";
    let mut tag = compute_hmac(&key, data);
    tag[0] ^= 0x01; // single bit flip
    let result = verify_hmac(&key, data, &tag);
    assert!(result.is_err());
}

#[test]
fn test_hmac_wrong_tag_length_fails() {
    let key = random_key();
    let data = b"test data";
    let short_tag = [0u8; 16]; // wrong length
    let result = verify_hmac(&key, data, &short_tag);
    assert!(result.is_err());
}

// ============================================================
// HMAC Determinism
// ============================================================

#[test]
fn test_hmac_deterministic() {
    let key = random_key();
    let data = b"deterministic test data";
    let tag1 = compute_hmac(&key, data);
    let tag2 = compute_hmac(&key, data);
    assert_eq!(tag1, tag2);
}

#[test]
fn test_hmac_different_data_different_tags() {
    let key = random_key();
    let tag1 = compute_hmac(&key, b"data one");
    let tag2 = compute_hmac(&key, b"data two");
    assert_ne!(tag1, tag2);
}

// ============================================================
// KDF Determinism
// ============================================================

#[test]
fn test_kdf_same_inputs_same_output() {
    let salt = [42u8; SALT_LENGTH];
    let pdk1 = derive_pdk_for_testing("my-passphrase", &salt).unwrap();
    let pdk2 = derive_pdk_for_testing("my-passphrase", &salt).unwrap();
    assert_eq!(pdk1, pdk2);
}

#[test]
fn test_kdf_different_passphrases_different_output() {
    let salt = [42u8; SALT_LENGTH];
    let pdk1 = derive_pdk_for_testing("passphrase-one", &salt).unwrap();
    let pdk2 = derive_pdk_for_testing("passphrase-two", &salt).unwrap();
    assert_ne!(pdk1, pdk2);
}

#[test]
fn test_kdf_different_salts_different_output() {
    let salt1 = [1u8; SALT_LENGTH];
    let salt2 = [2u8; SALT_LENGTH];
    let pdk1 = derive_pdk_for_testing("same-passphrase", &salt1).unwrap();
    let pdk2 = derive_pdk_for_testing("same-passphrase", &salt2).unwrap();
    assert_ne!(pdk1, pdk2);
}

#[test]
fn test_kdf_empty_passphrase_produces_valid_key() {
    let salt = [42u8; SALT_LENGTH];
    let pdk = derive_pdk_for_testing("", &salt).unwrap();
    assert_eq!(pdk.len(), 32);
}

#[test]
fn test_kdf_unicode_passphrase_produces_valid_key() {
    let salt = [42u8; SALT_LENGTH];
    let pdk = derive_pdk_for_testing("correct horse battery staple", &salt).unwrap();
    assert_eq!(pdk.len(), 32);
}

#[test]
fn test_kdf_rejects_wrong_salt_length() {
    let result = derive_pdk_for_testing("pass", &[0u8; 8]);
    assert!(result.is_err());
}

#[test]
fn test_kdf_rejects_empty_salt() {
    let result = derive_pdk_for_testing("pass", &[]);
    assert!(result.is_err());
}

// ============================================================
// Salt generation uniqueness
// ============================================================

#[test]
fn test_salt_generation_unique() {
    let salt1 = generate_argon2_salt();
    let salt2 = generate_argon2_salt();
    assert_ne!(salt1, salt2);
    assert_eq!(salt1.len(), SALT_LENGTH);
}

// ============================================================
// Nonce generation uniqueness
// ============================================================

#[test]
fn test_nonce_generation_unique() {
    use std::collections::HashSet;
    let nonces: HashSet<[u8; NONCE_SIZE]> = (0..1000).map(|_| generate_nonce()).collect();
    assert_eq!(nonces.len(), 1000);
}

// ============================================================
// Cross-module: full entry encrypt/decrypt cycle
// ============================================================

#[test]
fn test_entry_encrypt_decrypt_full_cycle() {
    use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};

    let kek = random_secret_buf();
    let plaintext = b"username=admin\npassword=P@ssw0rd!\nurl=https://example.com";
    let encrypted = encrypt_entry(plaintext, &kek).unwrap();
    let decrypted = decrypt_entry(&encrypted, &kek).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_entry_encrypt_decrypt_wrong_kek_fails() {
    use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};

    let kek1 = random_secret_buf();
    let kek2 = random_secret_buf();
    let encrypted = encrypt_entry(b"secret", &kek1).unwrap();
    let result = decrypt_entry(&encrypted, &kek2);
    assert!(result.is_err());
}

#[test]
fn test_entry_encrypt_decrypt_tampered_blob_fails() {
    use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};

    let kek = random_secret_buf();
    let mut encrypted = encrypt_entry(b"secret data", &kek).unwrap();
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01;
    let result = decrypt_entry(&encrypted, &kek);
    assert!(result.is_err());
}

#[test]
fn test_entry_encrypt_produces_unique_blobs() {
    use padlock_core::vault::entries::encrypt_entry;

    let kek = random_secret_buf();
    let blob1 = encrypt_entry(b"same data", &kek).unwrap();
    let blob2 = encrypt_entry(b"same data", &kek).unwrap();
    // Different DEKs and nonces each time
    assert_ne!(blob1, blob2);
}

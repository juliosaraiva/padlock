//! Property-based tests for cryptographic operations.
//!
//! Verifies invariants that must hold for all inputs:
//! - encrypt/decrypt round-trip identity
//! - KDF determinism
//! - KDF collision resistance

use padlock_core::crypto::aead::{aead_decrypt, aead_encrypt, generate_nonce, KEY_SIZE};
use padlock_core::crypto::kdf::{derive_pdk_for_testing, SALT_LENGTH};
use padlock_core::crypto::SecretBuf;
use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};
use proptest::prelude::*;
use rand::RngCore;

fn random_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

// ============================================================
// AEAD encrypt/decrypt round-trip for arbitrary payloads
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_aead_encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..10_000)) {
        let key = random_key();
        let nonce = generate_nonce();
        let ciphertext = aead_encrypt(&key, &nonce, &[], &plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &[], &ciphertext).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn prop_aead_encrypt_decrypt_with_aad(
        plaintext in proptest::collection::vec(any::<u8>(), 0..1_000),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let key = random_key();
        let nonce = generate_nonce();
        let ciphertext = aead_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn prop_aead_wrong_key_always_fails(plaintext in proptest::collection::vec(any::<u8>(), 1..1_000)) {
        let key1 = random_key();
        let key2 = random_key();
        // Keys will differ with overwhelming probability
        let nonce = generate_nonce();
        let ciphertext = aead_encrypt(&key1, &nonce, &[], &plaintext).unwrap();
        let result = aead_decrypt(&key2, &nonce, &[], &ciphertext);
        prop_assert!(result.is_err());
    }
}

// ============================================================
// Entry-level encrypt/decrypt round-trip
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_entry_encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..50_000)) {
        let kek = SecretBuf::from_bytes(&random_key());
        let encrypted = encrypt_entry(&plaintext, &kek).unwrap();
        let decrypted = decrypt_entry(&encrypted, &kek).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }
}

// ============================================================
// KDF determinism
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_kdf_same_inputs_same_output(passphrase in ".{0,64}", salt in proptest::collection::vec(any::<u8>(), SALT_LENGTH..=SALT_LENGTH)) {
        let salt_arr: [u8; SALT_LENGTH] = salt.try_into().unwrap();
        let pdk1 = derive_pdk_for_testing(&passphrase, &salt_arr).unwrap();
        let pdk2 = derive_pdk_for_testing(&passphrase, &salt_arr).unwrap();
        prop_assert_eq!(pdk1, pdk2);
    }

    #[test]
    fn prop_kdf_different_passphrases_different_output(
        pass1 in "[a-zA-Z0-9]{1,32}",
        pass2 in "[a-zA-Z0-9]{1,32}",
        salt in proptest::collection::vec(any::<u8>(), SALT_LENGTH..=SALT_LENGTH),
    ) {
        prop_assume!(pass1 != pass2);
        let salt_arr: [u8; SALT_LENGTH] = salt.try_into().unwrap();
        let pdk1 = derive_pdk_for_testing(&pass1, &salt_arr).unwrap();
        let pdk2 = derive_pdk_for_testing(&pass2, &salt_arr).unwrap();
        prop_assert_ne!(pdk1, pdk2);
    }
}

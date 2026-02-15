//! Cryptographic engine for the Padlock credential manager.
//!
//! This module implements all encryption, decryption, key derivation,
//! HMAC operations, and secure memory management. It provides the
//! cryptographic foundation that all other modules depend upon.
//!
//! # Key Hierarchy
//!
//! ```text
//! User Passphrase
//!       |
//!       | Argon2id (1GiB, t=2, p=4)
//!       v
//!     PDK (Primary Derivation Key)
//!       |
//!       +-- HKDF("padlock-vault-kek") --> KEK (wraps DEKs)
//!       +-- HKDF("padlock-vault-mackey") --> MACKEY (vault HMAC)
//! ```
//!
//! # Algorithms
//!
//! - **AEAD**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce)
//! - **KDF**: Argon2id (RFC 9106)
//! - **HKDF**: HKDF-SHA-256 (RFC 5869)
//! - **HMAC**: HMAC-SHA-256 (RFC 2104)

pub mod aead;
pub mod hkdf_keys;
pub mod hmac;
pub mod kdf;
pub mod memory;
pub mod secret_buf;

pub use aead::{aead_decrypt, aead_encrypt, generate_dek, generate_nonce, unwrap_dek, wrap_dek};
pub use hkdf_keys::{derive_kek, derive_mackey, expand_key};
pub use hmac::{compute_hmac, verify_hmac};
pub use kdf::{derive_pdk, derive_pdk_for_testing, generate_argon2_salt};
pub use memory::secure_compare;
pub use secret_buf::SecretBuf;

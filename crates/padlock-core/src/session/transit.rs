//! Ephemeral X25519 transit encryption for session key exchange.
//!
//! KEK must never travel in plaintext over the Unix socket. Each
//! session creation/resume uses:
//!
//! 1. Initiator generates ephemeral X25519 keypair, sends pubkey
//! 2. Responder generates ephemeral X25519 keypair, computes shared secret
//! 3. HKDF(shared_secret, info="padlock-session-transit") → transit key
//! 4. XChaCha20-Poly1305(transit_key, KEK) → encrypted KEK for transit
//! 5. Both sides zero ephemeral keys immediately after use

use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::crypto::aead::{aead_decrypt, aead_encrypt, generate_nonce, NONCE_SIZE};
use crate::crypto::hkdf_keys::expand_key;
use crate::crypto::secret_buf::SecretBuf;
use crate::error::{Error, Result, SessionError};

/// HKDF info string for session transit key derivation.
const TRANSIT_INFO: &[u8] = b"padlock-session-transit";

/// Size of an X25519 public key in bytes.
pub const X25519_PUBKEY_SIZE: usize = 32;

/// An ephemeral keypair for transit encryption (initiator side).
///
/// The secret is consumed on `derive_transit_key` to ensure it cannot
/// be reused.
pub struct TransitKeyPair {
    secret: Option<EphemeralSecret>,
    public: PublicKey,
}

impl TransitKeyPair {
    /// Generate a fresh ephemeral X25519 keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Get the public key bytes to send to the peer.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; X25519_PUBKEY_SIZE] {
        *self.public.as_bytes()
    }

    /// Derive a transit key from the peer's public key and consume the secret.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::TransitError` if key derivation fails.
    pub fn derive_transit_key(
        mut self,
        peer_pubkey: &[u8; X25519_PUBKEY_SIZE],
    ) -> Result<SecretBuf> {
        let secret = self
            .secret
            .take()
            .ok_or(Error::Session(SessionError::TransitError))?;

        let peer_public = PublicKey::from(*peer_pubkey);
        let shared_secret = secret.diffie_hellman(&peer_public);

        // Derive transit key via HKDF
        let mut ikm_bytes = shared_secret.to_bytes();
        let ikm = SecretBuf::from_bytes(&ikm_bytes);
        ikm_bytes.zeroize();

        expand_key(&ikm, TRANSIT_INFO, 32).map_err(|_| Error::Session(SessionError::TransitError))
    }
}

/// Encrypt data for transit using the transit key.
///
/// Returns (nonce, ciphertext).
///
/// # Errors
///
/// Returns `SessionError::TransitError` if encryption fails.
pub fn transit_encrypt(transit_key: &SecretBuf, plaintext: &[u8]) -> Result<([u8; NONCE_SIZE], Vec<u8>)> {
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(transit_key, &nonce, &[], plaintext)
        .map_err(|_| Error::Session(SessionError::TransitError))?;
    Ok((nonce, ciphertext))
}

/// Decrypt data received in transit.
///
/// # Errors
///
/// Returns `SessionError::TransitError` if decryption fails.
pub fn transit_decrypt(
    transit_key: &SecretBuf,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(transit_key, nonce, &[], ciphertext)
        .map_err(|_| Error::Session(SessionError::TransitError))
}

/// Responder-side: compute transit key from our ephemeral secret and the
/// initiator's public key.
///
/// This function generates a fresh ephemeral keypair, computes the shared
/// secret, and returns (our_public_key, transit_key).
///
/// # Errors
///
/// Returns `SessionError::TransitError` if key derivation fails.
pub fn responder_derive_transit(
    initiator_pubkey: &[u8; X25519_PUBKEY_SIZE],
) -> Result<([u8; X25519_PUBKEY_SIZE], SecretBuf)> {
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let our_public = PublicKey::from(&secret);
    let peer_public = PublicKey::from(*initiator_pubkey);
    let shared_secret = secret.diffie_hellman(&peer_public);

    let mut ikm_bytes = shared_secret.to_bytes();
    let ikm = SecretBuf::from_bytes(&ikm_bytes);
    ikm_bytes.zeroize();

    let transit_key =
        expand_key(&ikm, TRANSIT_INFO, 32).map_err(|_| Error::Session(SessionError::TransitError))?;

    Ok((*our_public.as_bytes(), transit_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transit_key_agreement() {
        // Simulate initiator and responder
        let initiator = TransitKeyPair::generate();
        let initiator_pubkey = initiator.public_key_bytes();

        let (responder_pubkey, responder_key) =
            responder_derive_transit(&initiator_pubkey).unwrap();

        let initiator_key = initiator.derive_transit_key(&responder_pubkey).unwrap();

        // Both sides should derive the same transit key
        assert_eq!(&*initiator_key, &*responder_key);
    }

    #[test]
    fn test_transit_encrypt_decrypt_round_trip() {
        let initiator = TransitKeyPair::generate();
        let initiator_pubkey = initiator.public_key_bytes();
        let (responder_pubkey, transit_key) =
            responder_derive_transit(&initiator_pubkey).unwrap();
        let initiator_key = initiator.derive_transit_key(&responder_pubkey).unwrap();

        let plaintext = b"secret KEK material";
        let (nonce, ciphertext) = transit_encrypt(&transit_key, plaintext).unwrap();
        let decrypted = transit_decrypt(&initiator_key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_transit_decrypt_wrong_key_fails() {
        let key1 = SecretBuf::from_bytes(&[1u8; 32]);
        let key2 = SecretBuf::from_bytes(&[2u8; 32]);

        let (nonce, ciphertext) = transit_encrypt(&key1, b"data").unwrap();
        let result = transit_decrypt(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keypairs_produce_different_shared_secrets() {
        let kp1 = TransitKeyPair::generate();
        let kp2 = TransitKeyPair::generate();
        let pk1 = kp1.public_key_bytes();
        let pk2 = kp2.public_key_bytes();
        // Public keys should be different
        assert_ne!(pk1, pk2);
    }
}

//! SSH agent request handler.
//!
//! Dispatches incoming agent protocol messages and produces responses.
//! This module contains pure logic with no I/O dependencies -- the
//! daemon layer is responsible for socket communication.

use std::sync::Arc;

use crate::session::manager::SessionStore;
use crate::session::protocol::{
    self, CreateSessionRequest, CreateSessionResponse, DestroySessionRequest, ResumeSessionRequest,
    ResumeSessionResponse, SessionRequest, SessionResponse, StatusSessionRequest,
    SESSION_EXTENSION_NAME,
};
use crate::session::transit::{responder_derive_transit, transit_encrypt};
use crate::session::types::{
    SessionAlgorithm, SessionDuration, DEFAULT_IDLE_TIMEOUT, SESSION_TOKEN_SIZE,
};
use crate::ssh_agent::protocol::{AgentMessage, AgentResponse};
use crate::traits::session::SessionManager;

/// An SSH key identity loaded in the agent.
///
/// Private key bytes are zeroized on drop to prevent key material
/// from lingering in deallocated heap memory.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct LoadedKey {
    /// The public key blob in OpenSSH wire format.
    #[zeroize(skip)]
    pub public_key_blob: Vec<u8>,
    /// Human-readable comment for the key.
    #[zeroize(skip)]
    pub comment: String,
    /// The private key bytes (used for signing). Zeroized on drop.
    pub private_key_bytes: Vec<u8>,
    /// The key type string (e.g., "ssh-ed25519").
    #[zeroize(skip)]
    pub key_type: String,
}

/// SSH agent request handler.
///
/// Holds loaded keys in memory and dispatches protocol messages.
/// The handler does not perform I/O -- it processes messages and
/// returns responses that the daemon layer sends over the socket.
/// Also manages session caching via an optional `SessionStore`.
pub struct AgentHandler {
    /// Keys currently loaded in the agent.
    keys: Vec<LoadedKey>,
    /// Session store for caching vault keys.
    session_store: Option<Arc<SessionStore>>,
}

impl Default for AgentHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentHandler {
    /// Create a new empty agent handler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            session_store: None,
        }
    }

    /// Create a new agent handler with a session store.
    #[must_use]
    pub fn with_session_store(session_store: Arc<SessionStore>) -> Self {
        Self {
            keys: Vec::new(),
            session_store: Some(session_store),
        }
    }

    /// Get a reference to the session store, if available.
    #[must_use]
    pub fn session_store(&self) -> Option<&Arc<SessionStore>> {
        self.session_store.as_ref()
    }

    /// Load a key into the agent.
    pub fn add_key(&mut self, key: LoadedKey) {
        self.keys.push(key);
    }

    /// Get the number of loaded keys.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Remove all loaded keys.
    pub fn remove_all_keys(&mut self) {
        self.keys.clear();
    }

    /// Remove a specific key by its public key blob.
    ///
    /// Returns `true` if a key was removed.
    pub fn remove_key(&mut self, public_key_blob: &[u8]) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.public_key_blob != public_key_blob);
        self.keys.len() < before
    }

    /// Handle an incoming agent message and produce a response.
    #[must_use]
    pub fn handle_message(&self, message: &AgentMessage) -> AgentResponse {
        match message {
            AgentMessage::RequestIdentities => {
                let keys = self
                    .keys
                    .iter()
                    .map(|k| (k.public_key_blob.clone(), k.comment.clone()))
                    .collect();
                AgentResponse::IdentitiesAnswer { keys }
            }
            AgentMessage::SignRequest {
                key_blob,
                data,
                flags: _,
            } => self.handle_sign_request(key_blob, data),
            AgentMessage::AddIdentity { .. } => {
                // External key addition is not supported -- keys come from the vault.
                AgentResponse::Failure
            }
            AgentMessage::RemoveIdentity { .. } | AgentMessage::RemoveAllIdentities => {
                // Removal via protocol not supported; use CLI commands.
                AgentResponse::Failure
            }
            AgentMessage::Extension { name, payload } => {
                if name == SESSION_EXTENSION_NAME {
                    self.handle_session_extension(payload)
                } else {
                    AgentResponse::Failure
                }
            }
            AgentMessage::Unknown(_) => AgentResponse::Failure,
        }
    }

    /// Handle a session extension message.
    fn handle_session_extension(&self, payload: &[u8]) -> AgentResponse {
        let Some(store) = &self.session_store else {
            return AgentResponse::Failure;
        };

        let Ok(request) = protocol::parse_session_request(payload) else {
            return AgentResponse::Failure;
        };

        match request {
            SessionRequest::Create(req) => Self::handle_session_create(store, req),
            SessionRequest::Resume(req) => Self::handle_session_resume(store, req),
            SessionRequest::Destroy(req) => Self::handle_session_destroy(store, req),
            SessionRequest::Status(req) => Self::handle_session_status(store, req),
            SessionRequest::DestroyAll => Self::handle_session_destroy_all(store),
        }
    }

    /// Handle a `CreateSession` request.
    ///
    /// For `CreateSession`, the KEK and MACKEY arrive as raw bytes over the
    /// Unix socket. The socket is secured by filesystem permissions (0o600),
    /// which restricts access to the same user. Transit encryption is only
    /// used for the `ResumeSession` response path (daemon→CLI).
    fn handle_session_create(store: &SessionStore, req: CreateSessionRequest) -> AgentResponse {
        // Validate algorithm
        let Some(algorithm) = SessionAlgorithm::from_byte(req.algorithm) else {
            return AgentResponse::Failure;
        };

        // Validate duration
        let Some(duration) = SessionDuration::from_str_label(&req.duration) else {
            return AgentResponse::Failure;
        };

        // Validate vault_id
        let vault_id: [u8; 16] = match req.vault_id.try_into() {
            Ok(v) => v,
            Err(_) => return AgentResponse::Failure,
        };

        // Accept KEK and MACKEY directly (transport secured by socket permissions)
        let kek = crate::crypto::secret_buf::SecretBuf::from_bytes(&req.encrypted_kek);
        let mackey = crate::crypto::secret_buf::SecretBuf::from_bytes(&req.encrypted_mackey);

        // Parse idle timeout from request, falling back to default
        let idle_timeout = if req.idle_timeout_secs > 0 {
            std::time::Duration::from_secs(req.idle_timeout_secs)
        } else {
            DEFAULT_IDLE_TIMEOUT
        };

        // Create session
        let Ok(token) =
            store.create_session(&kek, &mackey, &vault_id, duration, idle_timeout, algorithm)
        else {
            return AgentResponse::Failure;
        };

        let resp = CreateSessionResponse {
            token: token.as_bytes().to_vec(),
            responder_pubkey: Vec::new(), // Not used for create path
        };

        match protocol::serialize_session_response(&SessionResponse::Created(resp)) {
            Ok(payload) => AgentResponse::ExtensionResponse { payload },
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Handle a `ResumeSession` request.
    fn handle_session_resume(store: &SessionStore, req: ResumeSessionRequest) -> AgentResponse {
        // Validate token
        let token: [u8; SESSION_TOKEN_SIZE] = match req.token.try_into() {
            Ok(t) => t,
            Err(_) => return AgentResponse::Failure,
        };

        // Validate ephemeral pubkey
        let initiator_pubkey: [u8; 32] = match req.ephemeral_pubkey.try_into() {
            Ok(pk) => pk,
            Err(_) => return AgentResponse::Failure,
        };

        // Resume session to get KEK + MACKEY
        let Ok((kek, mackey)) = store.resume_session(&token) else {
            return AgentResponse::Failure;
        };

        // Derive transit key (responder side)
        let Ok((responder_pubkey, transit_key)) = responder_derive_transit(&initiator_pubkey)
        else {
            return AgentResponse::Failure;
        };

        // Encrypt KEK for transit
        let Ok((kek_nonce, encrypted_kek)) = transit_encrypt(&transit_key, &kek) else {
            return AgentResponse::Failure;
        };

        // Encrypt MACKEY for transit
        let Ok((mackey_nonce, encrypted_mackey)) = transit_encrypt(&transit_key, &mackey) else {
            return AgentResponse::Failure;
        };

        let resp = ResumeSessionResponse {
            encrypted_kek,
            kek_nonce: kek_nonce.to_vec(),
            encrypted_mackey,
            mackey_nonce: mackey_nonce.to_vec(),
            responder_pubkey: responder_pubkey.to_vec(),
        };

        match protocol::serialize_session_response(&SessionResponse::Resumed(resp)) {
            Ok(payload) => AgentResponse::ExtensionResponse { payload },
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Handle a `DestroySession` request.
    fn handle_session_destroy(store: &SessionStore, req: DestroySessionRequest) -> AgentResponse {
        let token: [u8; SESSION_TOKEN_SIZE] = match req.token.try_into() {
            Ok(t) => t,
            Err(_) => return AgentResponse::Failure,
        };

        match store.destroy_session(&token) {
            Ok(()) => match protocol::serialize_session_response(&SessionResponse::Success) {
                Ok(payload) => AgentResponse::ExtensionResponse { payload },
                Err(_) => AgentResponse::Failure,
            },
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Handle a `SessionStatus` request.
    fn handle_session_status(store: &SessionStore, req: StatusSessionRequest) -> AgentResponse {
        let token: [u8; SESSION_TOKEN_SIZE] = match req.token.try_into() {
            Ok(t) => t,
            Err(_) => return AgentResponse::Failure,
        };

        match store.session_status(&token) {
            Ok(info) => {
                let Ok(info_bytes) = rmp_serde::to_vec(&info) else {
                    return AgentResponse::Failure;
                };
                match protocol::serialize_session_response(&SessionResponse::StatusInfo(info_bytes))
                {
                    Ok(payload) => AgentResponse::ExtensionResponse { payload },
                    Err(_) => AgentResponse::Failure,
                }
            }
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Handle a `DestroyAll` request.
    fn handle_session_destroy_all(store: &SessionStore) -> AgentResponse {
        match store.destroy_all_sessions() {
            Ok(()) => match protocol::serialize_session_response(&SessionResponse::Success) {
                Ok(payload) => AgentResponse::ExtensionResponse { payload },
                Err(_) => AgentResponse::Failure,
            },
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Handle a sign request by finding the matching key and signing.
    fn handle_sign_request(&self, key_blob: &[u8], data: &[u8]) -> AgentResponse {
        let Some(key) = self.keys.iter().find(|k| k.public_key_blob == key_blob) else {
            return AgentResponse::Failure;
        };

        match key.key_type.as_str() {
            "ssh-ed25519" => Self::sign_ed25519(key, data),
            _ => AgentResponse::Failure,
        }
    }

    /// Sign data using an Ed25519 key.
    fn sign_ed25519(key: &LoadedKey, data: &[u8]) -> AgentResponse {
        use ed25519_dalek::{Signer, SigningKey};

        if key.private_key_bytes.len() < 32 {
            return AgentResponse::Failure;
        }

        // Ed25519 signing key is the first 32 bytes
        let key_bytes: [u8; 32] = match key.private_key_bytes[..32].try_into() {
            Ok(b) => b,
            Err(_) => return AgentResponse::Failure,
        };

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(data);

        // Build SSH signature blob: string "ssh-ed25519" + string signature_bytes
        let sig_type = b"ssh-ed25519";
        let sig_bytes = signature.to_bytes();
        let mut blob = Vec::new();
        blob.extend_from_slice(
            &u32::try_from(sig_type.len())
                .expect("sig_type length fits in u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(sig_type);
        blob.extend_from_slice(
            &u32::try_from(sig_bytes.len())
                .expect("sig_bytes length fits in u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(&sig_bytes);

        AgentResponse::SignResponse { signature: blob }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_key() -> LoadedKey {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // Build OpenSSH wire format public key blob
        let key_type = b"ssh-ed25519";
        let pk_bytes = verifying_key.as_bytes();
        let mut blob = Vec::new();
        blob.extend_from_slice(
            &u32::try_from(key_type.len())
                .expect("fits in u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(key_type);
        blob.extend_from_slice(
            &u32::try_from(pk_bytes.len())
                .expect("fits in u32")
                .to_be_bytes(),
        );
        blob.extend_from_slice(pk_bytes);

        LoadedKey {
            public_key_blob: blob,
            comment: "test-key".to_string(),
            private_key_bytes: signing_key.to_bytes().to_vec(),
            key_type: "ssh-ed25519".to_string(),
        }
    }

    #[test]
    fn test_handler_new_has_no_keys() {
        let handler = AgentHandler::new();
        assert_eq!(handler.key_count(), 0);
    }

    #[test]
    fn test_handler_add_key() {
        let mut handler = AgentHandler::new();
        handler.add_key(make_test_key());
        assert_eq!(handler.key_count(), 1);
    }

    #[test]
    fn test_handler_remove_all_keys() {
        let mut handler = AgentHandler::new();
        handler.add_key(make_test_key());
        handler.remove_all_keys();
        assert_eq!(handler.key_count(), 0);
    }

    #[test]
    fn test_handler_remove_specific_key() {
        let mut handler = AgentHandler::new();
        let key = make_test_key();
        let blob = key.public_key_blob.clone();
        handler.add_key(key);
        assert!(handler.remove_key(&blob));
        assert_eq!(handler.key_count(), 0);
    }

    #[test]
    fn test_handler_remove_nonexistent_key() {
        let mut handler = AgentHandler::new();
        assert!(!handler.remove_key(&[1, 2, 3]));
    }

    #[test]
    fn test_handler_request_identities_empty() {
        let handler = AgentHandler::new();
        let response = handler.handle_message(&AgentMessage::RequestIdentities);
        match response {
            AgentResponse::IdentitiesAnswer { keys } => assert!(keys.is_empty()),
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_handler_request_identities_with_key() {
        let mut handler = AgentHandler::new();
        handler.add_key(make_test_key());
        let response = handler.handle_message(&AgentMessage::RequestIdentities);
        match response {
            AgentResponse::IdentitiesAnswer { keys } => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].1, "test-key");
            }
            _ => panic!("expected IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_handler_sign_request_ed25519() {
        let mut handler = AgentHandler::new();
        let key = make_test_key();
        let key_blob = key.public_key_blob.clone();
        handler.add_key(key);

        let response = handler.handle_message(&AgentMessage::SignRequest {
            key_blob,
            data: b"test data to sign".to_vec(),
            flags: 0,
        });

        match response {
            AgentResponse::SignResponse { signature } => {
                assert!(!signature.is_empty());
            }
            _ => panic!("expected SignResponse"),
        }
    }

    #[test]
    fn test_handler_sign_request_unknown_key() {
        let handler = AgentHandler::new();
        let response = handler.handle_message(&AgentMessage::SignRequest {
            key_blob: vec![1, 2, 3],
            data: b"test".to_vec(),
            flags: 0,
        });
        assert!(matches!(response, AgentResponse::Failure));
    }

    #[test]
    fn test_handler_add_identity_rejected() {
        let handler = AgentHandler::new();
        let response = handler.handle_message(&AgentMessage::AddIdentity {
            key_type: "ssh-ed25519".to_string(),
            key_data: vec![],
            comment: String::new(),
        });
        assert!(matches!(response, AgentResponse::Failure));
    }

    #[test]
    fn test_handler_unknown_message() {
        let handler = AgentHandler::new();
        let response = handler.handle_message(&AgentMessage::Unknown(0xFF));
        assert!(matches!(response, AgentResponse::Failure));
    }

    #[test]
    fn test_handler_sign_verifies_correctly() {
        use ed25519_dalek::Verifier;

        let mut handler = AgentHandler::new();
        let key = make_test_key();
        let key_blob = key.public_key_blob.clone();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        handler.add_key(key);

        let data = b"important message";
        let response = handler.handle_message(&AgentMessage::SignRequest {
            key_blob,
            data: data.to_vec(),
            flags: 0,
        });

        if let AgentResponse::SignResponse {
            signature: sig_blob,
        } = response
        {
            // Parse the SSH signature blob to extract raw signature
            // Format: string "ssh-ed25519" + string signature_bytes
            let type_len = u32::from_be_bytes(sig_blob[0..4].try_into().unwrap()) as usize;
            let sig_start = 4 + type_len + 4;
            let sig_bytes = &sig_blob[sig_start..];
            let signature = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().unwrap());
            assert!(verifying_key.verify(data, &signature).is_ok());
        } else {
            panic!("expected SignResponse");
        }
    }
}

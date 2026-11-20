//! Session protocol wire format over SSH agent EXTENSION messages.
//!
//! Uses `SSH_AGENTC_EXTENSION` (type 27) with the extension name
//! `padlock-session@padlock.dev`. The payload is:
//!
//! ```text
//! [1 byte]  protocol version = 1
//! [1 byte]  session message type
//! [...]     MessagePack-serialized payload
//! ```
//!
//! Responses use `SSH_AGENT_EXTENSION_RESPONSE` (type 28) with the
//! same protocol version prefix, or `SSH_AGENT_FAILURE` (5) on error.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{aead::KEY_SIZE, secret_buf::SecretBuf};

use crate::error::{AgentError, Error, Result, SessionError};

/// Extension name for session protocol messages.
pub const SESSION_EXTENSION_NAME: &str = "padlock-session@padlock.dev";

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// SSH agent extension message type (RFC draft).
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// SSH agent extension response type.
pub const SSH_AGENT_EXTENSION_RESPONSE: u8 = 28;

/// Session message types within the extension payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionMessageType {
    /// Create a new session.
    Create = 1,
    /// Resume an existing session.
    Resume = 2,
    /// Destroy a session.
    Destroy = 3,
    /// Query session status.
    Status = 4,
    /// Destroy all sessions.
    DestroyAll = 5,
}

impl SessionMessageType {
    /// Parse a message type from its wire byte.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Create),
            2 => Some(Self::Resume),
            3 => Some(Self::Destroy),
            4 => Some(Self::Status),
            5 => Some(Self::DestroyAll),
            _ => None,
        }
    }
}

/// Request to create a new session over the permission-restricted socket.
#[derive(Serialize, Deserialize)]
pub struct CreateSessionRequest {
    /// Algorithm identifier byte.
    pub algorithm: u8,
    /// Raw KEK bytes. Field name is kept for wire compatibility.
    #[serde(with = "raw_session_key")]
    pub encrypted_kek: SecretBuf,
    /// Nonce for KEK transit encryption.
    pub kek_nonce: Vec<u8>,
    /// Raw MACKEY bytes. Field name is kept for wire compatibility.
    #[serde(with = "raw_session_key")]
    pub encrypted_mackey: SecretBuf,
    /// Nonce for MACKEY transit encryption.
    pub mackey_nonce: Vec<u8>,
    /// Initiator's ephemeral X25519 public key.
    pub ephemeral_pubkey: Vec<u8>,
    /// Requested session duration label (e.g., "1h").
    pub duration: String,
    /// Vault identifier.
    pub vault_id: Vec<u8>,
    /// Idle timeout in seconds. Session expires if unused for this long.
    /// Defaults to 900 (15 minutes) if not present (backward compat).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl std::fmt::Debug for CreateSessionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateSessionRequest")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// Preserve the existing MessagePack sequence of bytes. Decode directly
// into a wiping allocation, including when a later field fails to decode.
mod raw_session_key {
    use super::{SecretBuf, KEY_SIZE};
    use serde::{de, Serialize};

    pub(super) fn serialize<S: serde::Serializer>(
        key: &SecretBuf,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if key.len() != KEY_SIZE {
            return Err(serde::ser::Error::custom("invalid session key length"));
        }
        key[..].serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: de::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretBuf, D::Error> {
        struct KeyVisitor;

        impl<'de> de::Visitor<'de> for KeyVisitor {
            type Value = SecretBuf;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a sequence of {KEY_SIZE} key bytes")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<SecretBuf, A::Error> {
                let mut key = SecretBuf::new(KEY_SIZE);
                for (index, byte) in key.as_mut_slice().iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(KEY_SIZE + 1, &self));
                }
                Ok(key)
            }
        }

        deserializer.deserialize_seq(KeyVisitor)
    }
}

/// Default idle timeout for backward compatibility with older clients.
fn default_idle_timeout_secs() -> u64 {
    900
}

/// Response to a successful session creation.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    /// Session token (32 bytes).
    pub token: Vec<u8>,
    /// Responder's ephemeral X25519 public key.
    pub responder_pubkey: Vec<u8>,
}

/// Request to resume an existing session.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResumeSessionRequest {
    /// Session token.
    pub token: Vec<u8>,
    /// Initiator's ephemeral X25519 public key for transit encryption.
    pub ephemeral_pubkey: Vec<u8>,
}

/// Response to a successful session resume.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResumeSessionResponse {
    /// KEK encrypted with transit key.
    pub encrypted_kek: Vec<u8>,
    /// Nonce for KEK transit encryption.
    pub kek_nonce: Vec<u8>,
    /// MACKEY encrypted with transit key.
    pub encrypted_mackey: Vec<u8>,
    /// Nonce for MACKEY transit encryption.
    pub mackey_nonce: Vec<u8>,
    /// Responder's ephemeral X25519 public key.
    pub responder_pubkey: Vec<u8>,
}

/// Request to destroy a session.
#[derive(Debug, Serialize, Deserialize)]
pub struct DestroySessionRequest {
    /// Session token.
    pub token: Vec<u8>,
}

/// Request for session status.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusSessionRequest {
    /// Session token.
    pub token: Vec<u8>,
}

/// Parsed session protocol message.
#[derive(Debug)]
pub enum SessionRequest {
    /// Create a new session.
    Create(CreateSessionRequest),
    /// Resume an existing session.
    Resume(ResumeSessionRequest),
    /// Destroy a session.
    Destroy(DestroySessionRequest),
    /// Query session status.
    Status(StatusSessionRequest),
    /// Destroy all sessions.
    DestroyAll,
}

/// Serialized session protocol response.
#[derive(Debug)]
pub enum SessionResponse {
    /// Session created successfully.
    Created(CreateSessionResponse),
    /// Session resumed successfully.
    Resumed(ResumeSessionResponse),
    /// Operation succeeded (destroy, destroy-all).
    Success,
    /// Session status info (serialized as `MessagePack`).
    StatusInfo(Vec<u8>),
    /// Operation failed.
    Failure,
}

/// Parse the extension payload (after the extension name) into a `SessionRequest`.
///
/// Expected format: [version: u8] [`msg_type`: u8] [msgpack payload...]
///
/// # Errors
///
/// Returns errors for unsupported versions, unknown message types, or
/// malformed payloads.
pub fn parse_session_request(payload: &[u8]) -> Result<SessionRequest> {
    if payload.len() < 2 {
        return Err(Error::Agent(AgentError::ProtocolError(
            "session payload too short".to_string(),
        )));
    }

    let version = payload[0];
    if version != PROTOCOL_VERSION {
        return Err(Error::Session(SessionError::UnsupportedVersion { version }));
    }

    let msg_type = SessionMessageType::from_byte(payload[1]).ok_or_else(|| {
        Error::Agent(AgentError::ProtocolError(format!(
            "unknown session message type: {}",
            payload[1]
        )))
    })?;

    let body = &payload[2..];

    match msg_type {
        SessionMessageType::Create => {
            let req: CreateSessionRequest = rmp_serde::from_slice(body).map_err(|_| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid CreateSession payload".to_owned(),
                ))
            })?;
            Ok(SessionRequest::Create(req))
        }
        SessionMessageType::Resume => {
            let req: ResumeSessionRequest = rmp_serde::from_slice(body).map_err(|e| {
                Error::Agent(AgentError::ProtocolError(format!(
                    "invalid ResumeSession payload: {e}"
                )))
            })?;
            Ok(SessionRequest::Resume(req))
        }
        SessionMessageType::Destroy => {
            let req: DestroySessionRequest = rmp_serde::from_slice(body).map_err(|e| {
                Error::Agent(AgentError::ProtocolError(format!(
                    "invalid DestroySession payload: {e}"
                )))
            })?;
            Ok(SessionRequest::Destroy(req))
        }
        SessionMessageType::Status => {
            let req: StatusSessionRequest = rmp_serde::from_slice(body).map_err(|e| {
                Error::Agent(AgentError::ProtocolError(format!(
                    "invalid StatusSession payload: {e}"
                )))
            })?;
            Ok(SessionRequest::Status(req))
        }
        SessionMessageType::DestroyAll => Ok(SessionRequest::DestroyAll),
    }
}

/// Serialize a session response into wire bytes for the extension response.
///
/// Returns the payload to embed in `SSH_AGENT_EXTENSION_RESPONSE`.
/// Format: [version: u8] [msgpack payload...]
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize_session_response(response: &SessionResponse) -> Result<Vec<u8>> {
    let mut out = vec![PROTOCOL_VERSION];

    match response {
        SessionResponse::Created(resp) => {
            let body = rmp_serde::to_vec(resp).map_err(|e| {
                Error::Agent(AgentError::ProtocolError(format!(
                    "failed to serialize CreateSessionResponse: {e}"
                )))
            })?;
            out.extend_from_slice(&body);
        }
        SessionResponse::Resumed(resp) => {
            let body = rmp_serde::to_vec(resp).map_err(|e| {
                Error::Agent(AgentError::ProtocolError(format!(
                    "failed to serialize ResumeSessionResponse: {e}"
                )))
            })?;
            out.extend_from_slice(&body);
        }
        SessionResponse::Success => {
            // Just the version byte is enough for success
        }
        SessionResponse::StatusInfo(info_bytes) => {
            out.extend_from_slice(info_bytes);
        }
        SessionResponse::Failure => {
            // Return empty — caller should use SSH_AGENT_FAILURE instead
            return Ok(Vec::new());
        }
    }

    Ok(out)
}

/// Build a complete SSH agent EXTENSION message for a session request.
///
/// Format:
/// ```text
/// [4 bytes] total length
/// [1 byte]  SSH_AGENTC_EXTENSION (27)
/// [4 bytes] extension name length
/// [N bytes] extension name
/// [...]     session payload (version + type + msgpack)
/// ```
///
/// # Panics
///
/// Panics if the message or extension name exceeds `u32::MAX` bytes (not
/// possible in practice).
#[must_use]
pub fn build_extension_message(session_payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let name_bytes = SESSION_EXTENSION_NAME.as_bytes();
    let payload_len = 1 + 4 + name_bytes.len() + session_payload.len();

    let mut msg = Zeroizing::new(Vec::with_capacity(4 + payload_len));
    msg.extend_from_slice(
        &u32::try_from(payload_len)
            .expect("payload length fits in u32")
            .to_be_bytes(),
    );
    msg.push(SSH_AGENTC_EXTENSION);
    msg.extend_from_slice(
        &u32::try_from(name_bytes.len())
            .expect("name length fits in u32")
            .to_be_bytes(),
    );
    msg.extend_from_slice(name_bytes);
    msg.extend_from_slice(session_payload);
    msg
}

/// Build a session request payload (version + type + msgpack body).
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn build_create_request(req: &CreateSessionRequest) -> Result<Zeroizing<Vec<u8>>> {
    // MessagePack uses at most two bytes per u8 and five bytes per sequence
    // or string header. Reserve fixed overhead for all headers and scalars.
    let sequence_bytes = 2 * KEY_SIZE
        + req.kek_nonce.len()
        + req.mackey_nonce.len()
        + req.ephemeral_pubkey.len()
        + req.vault_id.len();
    let capacity = 64 + 2 * sequence_bytes + req.duration.len();
    let mut payload = Zeroizing::new(vec![0; capacity]);
    payload[..2].copy_from_slice(&[PROTOCOL_VERSION, SessionMessageType::Create as u8]);
    let mut writer = &mut payload[2..];
    rmp_serde::encode::write(&mut writer, req).map_err(|e| {
        Error::Agent(AgentError::ProtocolError(format!(
            "failed to serialize CreateSessionRequest: {e}"
        )))
    })?;
    let used = capacity - writer.len();
    payload.truncate(used);
    Ok(payload)
}

/// Build a resume session request payload.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn build_resume_request(req: &ResumeSessionRequest) -> Result<Vec<u8>> {
    let mut payload = vec![PROTOCOL_VERSION, SessionMessageType::Resume as u8];
    let body = rmp_serde::to_vec(req).map_err(|e| {
        Error::Agent(AgentError::ProtocolError(format!(
            "failed to serialize ResumeSessionRequest: {e}"
        )))
    })?;
    payload.extend_from_slice(&body);
    Ok(payload)
}

/// Build a destroy session request payload.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn build_destroy_request(req: &DestroySessionRequest) -> Result<Vec<u8>> {
    let mut payload = vec![PROTOCOL_VERSION, SessionMessageType::Destroy as u8];
    let body = rmp_serde::to_vec(req).map_err(|e| {
        Error::Agent(AgentError::ProtocolError(format!(
            "failed to serialize DestroySessionRequest: {e}"
        )))
    })?;
    payload.extend_from_slice(&body);
    Ok(payload)
}

/// Build a destroy-all request payload (no body needed).
#[must_use]
pub fn build_destroy_all_request() -> Vec<u8> {
    vec![PROTOCOL_VERSION, SessionMessageType::DestroyAll as u8]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::NONCE_SIZE;
    use crate::session::transit::X25519_PUBKEY_SIZE;
    use crate::session::types::SESSION_TOKEN_SIZE;

    fn create_request() -> CreateSessionRequest {
        CreateSessionRequest {
            algorithm: 1,
            encrypted_kek: SecretBuf::from_bytes(&[0xD1; KEY_SIZE]),
            kek_nonce: vec![0; NONCE_SIZE],
            encrypted_mackey: SecretBuf::from_bytes(&[0xE2; KEY_SIZE]),
            mackey_nonce: vec![0; NONCE_SIZE],
            ephemeral_pubkey: vec![0; X25519_PUBKEY_SIZE],
            duration: "1h".to_string(),
            vault_id: vec![0; 16],
            idle_timeout_secs: 900,
        }
    }

    #[test]
    fn create_request_preserves_wire_bytes_and_borrows_extension() {
        use crate::ssh_agent::protocol::{parse_message, AgentMessage};

        let req = create_request();
        let payload = build_create_request(&req).unwrap();
        let old_body = rmp_serde::to_vec(&(
            req.algorithm,
            &req.encrypted_kek[..],
            &req.kek_nonce,
            &req.encrypted_mackey[..],
            &req.mackey_nonce,
            &req.ephemeral_pubkey,
            &req.duration,
            &req.vault_id,
            req.idle_timeout_secs,
        ))
        .unwrap();
        assert_eq!(&payload[2..], old_body);

        let frame = build_extension_message(&payload);
        let msg = parse_message(&frame[4..]).unwrap();
        assert!(!format!("{msg:?}").contains("209"));
        let AgentMessage::Extension {
            payload: extension, ..
        } = msg
        else {
            panic!("expected an extension");
        };
        let offset = frame.len() - payload.len();
        assert!(std::ptr::eq(extension.as_bytes(), &frame[offset..]));
        let SessionRequest::Create(parsed) = parse_session_request(extension.as_bytes()).unwrap()
        else {
            panic!("expected a create-session request");
        };
        assert_eq!(&parsed.encrypted_kek[..], &req.encrypted_kek[..]);
        assert_eq!(&parsed.encrypted_mackey[..], &req.encrypted_mackey[..]);
    }

    #[test]
    fn create_request_rejects_partial_input_and_invalid_key_lengths() {
        let mut req = create_request();
        let payload = build_create_request(&req).unwrap();
        for end in 0..payload.len() {
            assert!(
                parse_session_request(&payload[..end]).is_err(),
                "offset {end}"
            );
        }

        req.encrypted_mackey = SecretBuf::new(KEY_SIZE - 1);
        assert!(build_create_request(&req).is_err());

        // A legacy-shaped request can carry keys of any length on the wire.
        let body = rmp_serde::to_vec(&(
            req.algorithm,
            &req.encrypted_kek[..],
            &req.kek_nonce,
            &req.encrypted_mackey[..],
            &req.mackey_nonce,
            &req.ephemeral_pubkey,
            &req.duration,
            &req.vault_id,
        ))
        .unwrap();
        let mut payload = vec![PROTOCOL_VERSION, SessionMessageType::Create as u8];
        payload.extend_from_slice(&body);
        assert!(parse_session_request(&payload).is_err());
    }

    #[test]
    fn test_parse_resume_session_request() {
        let req = ResumeSessionRequest {
            token: vec![0; SESSION_TOKEN_SIZE],
            ephemeral_pubkey: vec![0; X25519_PUBKEY_SIZE],
        };

        let payload = build_resume_request(&req).unwrap();
        let parsed = parse_session_request(&payload).unwrap();
        assert!(matches!(parsed, SessionRequest::Resume(_)));
    }

    #[test]
    fn test_parse_destroy_request() {
        let req = DestroySessionRequest {
            token: vec![0; SESSION_TOKEN_SIZE],
        };
        let payload = build_destroy_request(&req).unwrap();
        let parsed = parse_session_request(&payload).unwrap();
        assert!(matches!(parsed, SessionRequest::Destroy(_)));
    }

    #[test]
    fn test_parse_destroy_all_request() {
        let payload = build_destroy_all_request();
        let parsed = parse_session_request(&payload).unwrap();
        assert!(matches!(parsed, SessionRequest::DestroyAll));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let payload = [99, 1]; // version 99, type 1
        let result = parse_session_request(&payload);
        assert!(matches!(
            result.unwrap_err(),
            Error::Session(SessionError::UnsupportedVersion { version: 99 })
        ));
    }

    #[test]
    fn test_unknown_message_type_rejected() {
        let payload = [1, 99]; // version 1, type 99
        let result = parse_session_request(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_extension_message_format() {
        let session_payload = vec![1, 1, 42];
        let msg = build_extension_message(&session_payload);

        // Verify structure: length prefix + type 27 + name + payload
        let total_len = u32::from_be_bytes(msg[0..4].try_into().unwrap()) as usize;
        assert_eq!(msg.len(), 4 + total_len);
        assert_eq!(msg[4], SSH_AGENTC_EXTENSION);
    }

    #[test]
    fn test_serialize_success_response() {
        let resp = SessionResponse::Success;
        let bytes = serialize_session_response(&resp).unwrap();
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(bytes.len(), 1);
    }

    #[test]
    fn test_serialize_created_response() {
        let resp = SessionResponse::Created(CreateSessionResponse {
            token: vec![0; 32],
            responder_pubkey: vec![0; 32],
        });
        let bytes = serialize_session_response(&resp).unwrap();
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert!(bytes.len() > 1);
    }
}

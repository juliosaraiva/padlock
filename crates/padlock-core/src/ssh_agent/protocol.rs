//! SSH agent protocol message parsing and serialization.
//!
//! Implements the binary wire format for the OpenSSH agent protocol.
//! All multi-byte integers use big-endian (network) byte order.

use crate::error::{AgentError, Error};

// Protocol message type constants
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 28;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_FAILURE: u8 = 5;

/// Parsed SSH agent request message.
#[derive(Debug, Clone)]
pub enum AgentMessage {
    /// Request list of available identities (keys).
    RequestIdentities,
    /// Request a signature using a specific key.
    SignRequest {
        /// The public key blob identifying which key to use.
        key_blob: Vec<u8>,
        /// The data to be signed.
        data: Vec<u8>,
        /// Signature flags.
        flags: u32,
    },
    /// Add a key identity to the agent.
    AddIdentity {
        /// Key type string (e.g., "ssh-ed25519").
        key_type: String,
        /// Raw key data.
        key_data: Vec<u8>,
        /// Comment associated with the key.
        comment: String,
    },
    /// Remove a specific key identity.
    RemoveIdentity {
        /// Public key blob to remove.
        key_blob: Vec<u8>,
    },
    /// Remove all identities.
    RemoveAllIdentities,
    /// SSH agent extension message.
    Extension {
        /// Extension name.
        name: String,
        /// Extension payload (after the name).
        payload: Vec<u8>,
    },
    /// Unknown or unsupported message type.
    Unknown(u8),
}

/// SSH agent response to send back to the client.
#[derive(Debug, Clone)]
pub enum AgentResponse {
    /// List of available identities.
    IdentitiesAnswer {
        /// List of (`public_key_blob`, comment) pairs.
        keys: Vec<(Vec<u8>, String)>,
    },
    /// Signature response.
    SignResponse {
        /// The signature blob.
        signature: Vec<u8>,
    },
    /// Generic success.
    Success,
    /// Extension response.
    ExtensionResponse {
        /// Serialized extension response payload.
        payload: Vec<u8>,
    },
    /// Generic failure.
    Failure,
}

/// Read a big-endian u32 from a byte slice.
fn read_u32(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Read a length-prefixed string/blob from a byte slice.
/// Returns (`value`, `bytes_consumed`).
fn read_string(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let len = read_u32(data)? as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some((data[4..4 + len].to_vec(), 4 + len))
}

/// Parse a raw SSH agent message from wire bytes.
///
/// The input should be the message payload (after the 4-byte length
/// prefix has been stripped).
///
/// # Errors
///
/// Returns `AgentError::ProtocolError` if the message is malformed.
pub fn parse_message(data: &[u8]) -> crate::error::Result<AgentMessage> {
    if data.is_empty() {
        return Err(Error::Agent(AgentError::ProtocolError(
            "empty message".to_string(),
        )));
    }

    let msg_type = data[0];
    let payload = &data[1..];

    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(AgentMessage::RequestIdentities),

        SSH_AGENTC_SIGN_REQUEST => {
            let (key_blob, consumed) = read_string(payload).ok_or_else(|| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid sign request: missing key blob".to_string(),
                ))
            })?;
            let rest = &payload[consumed..];
            let (sign_data, consumed2) = read_string(rest).ok_or_else(|| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid sign request: missing data".to_string(),
                ))
            })?;
            let rest2 = &rest[consumed2..];
            let flags = if rest2.len() >= 4 {
                read_u32(rest2).unwrap_or(0)
            } else {
                0
            };
            Ok(AgentMessage::SignRequest {
                key_blob,
                data: sign_data,
                flags,
            })
        }

        SSH_AGENTC_ADD_IDENTITY => {
            let (key_type_bytes, consumed) = read_string(payload).ok_or_else(|| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid add identity: missing key type".to_string(),
                ))
            })?;
            let key_type = String::from_utf8(key_type_bytes).map_err(|_| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid key type encoding".to_string(),
                ))
            })?;
            let rest = &payload[consumed..];
            // Simplified: treat remaining as key_data + comment
            let key_data = rest.to_vec();
            Ok(AgentMessage::AddIdentity {
                key_type,
                key_data,
                comment: String::new(),
            })
        }

        SSH_AGENTC_REMOVE_IDENTITY => {
            let (key_blob, _) = read_string(payload).ok_or_else(|| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid remove identity: missing key blob".to_string(),
                ))
            })?;
            Ok(AgentMessage::RemoveIdentity { key_blob })
        }

        SSH_AGENTC_REMOVE_ALL_IDENTITIES => Ok(AgentMessage::RemoveAllIdentities),

        SSH_AGENTC_EXTENSION => {
            let (name_bytes, consumed) = read_string(payload).ok_or_else(|| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid extension: missing name".to_string(),
                ))
            })?;
            let name = String::from_utf8(name_bytes).map_err(|_| {
                Error::Agent(AgentError::ProtocolError(
                    "invalid extension name encoding".to_string(),
                ))
            })?;
            let extension_payload = payload[consumed..].to_vec();
            Ok(AgentMessage::Extension {
                name,
                payload: extension_payload,
            })
        }

        other => Ok(AgentMessage::Unknown(other)),
    }
}

/// Serialize an SSH agent response to wire bytes.
///
/// Returns the complete message including the 4-byte length prefix.
///
/// # Panics
///
/// Panics if any field length exceeds `u32::MAX` bytes (not possible in
/// practice for valid SSH agent messages).
#[must_use]
pub fn serialize_response(response: &AgentResponse) -> Vec<u8> {
    let mut payload = Vec::new();

    match response {
        AgentResponse::IdentitiesAnswer { keys } => {
            payload.push(SSH_AGENT_IDENTITIES_ANSWER);
            payload.extend_from_slice(&u32::try_from(keys.len()).expect("key count fits in u32").to_be_bytes());
            for (blob, comment) in keys {
                payload.extend_from_slice(&u32::try_from(blob.len()).expect("blob length fits in u32").to_be_bytes());
                payload.extend_from_slice(blob);
                let comment_bytes = comment.as_bytes();
                payload.extend_from_slice(&u32::try_from(comment_bytes.len()).expect("comment length fits in u32").to_be_bytes());
                payload.extend_from_slice(comment_bytes);
            }
        }
        AgentResponse::SignResponse { signature } => {
            payload.push(SSH_AGENT_SIGN_RESPONSE);
            payload.extend_from_slice(&u32::try_from(signature.len()).expect("signature length fits in u32").to_be_bytes());
            payload.extend_from_slice(signature);
        }
        AgentResponse::ExtensionResponse {
            payload: ext_payload,
        } => {
            payload.push(SSH_AGENT_EXTENSION_RESPONSE);
            payload.extend_from_slice(ext_payload);
        }
        AgentResponse::Success => {
            payload.push(SSH_AGENT_SUCCESS);
        }
        AgentResponse::Failure => {
            payload.push(SSH_AGENT_FAILURE);
        }
    }

    // Prepend length
    let len = u32::try_from(payload.len()).expect("payload length fits in u32");
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_identities() {
        let data = [SSH_AGENTC_REQUEST_IDENTITIES];
        let msg = parse_message(&data).unwrap();
        assert!(matches!(msg, AgentMessage::RequestIdentities));
    }

    #[test]
    fn test_parse_remove_all_identities() {
        let data = [SSH_AGENTC_REMOVE_ALL_IDENTITIES];
        let msg = parse_message(&data).unwrap();
        assert!(matches!(msg, AgentMessage::RemoveAllIdentities));
    }

    #[test]
    fn test_parse_unknown_message() {
        let data = [0xFF];
        let msg = parse_message(&data).unwrap();
        assert!(matches!(msg, AgentMessage::Unknown(0xFF)));
    }

    #[test]
    fn test_parse_empty_message_fails() {
        let result = parse_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sign_request() {
        let mut data = vec![SSH_AGENTC_SIGN_REQUEST];
        // key blob: 4 bytes
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(b"key1");
        // data to sign: 5 bytes
        data.extend_from_slice(&5u32.to_be_bytes());
        data.extend_from_slice(b"hello");
        // flags
        data.extend_from_slice(&0u32.to_be_bytes());

        let msg = parse_message(&data).unwrap();
        match msg {
            AgentMessage::SignRequest {
                key_blob,
                data: sign_data,
                flags,
            } => {
                assert_eq!(key_blob, b"key1");
                assert_eq!(sign_data, b"hello");
                assert_eq!(flags, 0);
            }
            _ => panic!("expected SignRequest"),
        }
    }

    #[test]
    fn test_serialize_identities_answer_empty() {
        let response = AgentResponse::IdentitiesAnswer { keys: vec![] };
        let bytes = serialize_response(&response);
        // length prefix (4) + type (1) + count (4) = 9 total, payload = 5
        assert_eq!(bytes.len(), 9);
        assert_eq!(read_u32(&bytes), Some(5));
        assert_eq!(bytes[4], SSH_AGENT_IDENTITIES_ANSWER);
    }

    #[test]
    fn test_serialize_identities_answer_with_keys() {
        let response = AgentResponse::IdentitiesAnswer {
            keys: vec![(b"pubkey1".to_vec(), "comment1".to_string())],
        };
        let bytes = serialize_response(&response);
        assert!(bytes.len() > 9);
        assert_eq!(bytes[4], SSH_AGENT_IDENTITIES_ANSWER);
    }

    #[test]
    fn test_serialize_success() {
        let response = AgentResponse::Success;
        let bytes = serialize_response(&response);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[4], SSH_AGENT_SUCCESS);
    }

    #[test]
    fn test_serialize_failure() {
        let response = AgentResponse::Failure;
        let bytes = serialize_response(&response);
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[4], SSH_AGENT_FAILURE);
    }

    #[test]
    fn test_serialize_sign_response() {
        let response = AgentResponse::SignResponse {
            signature: vec![1, 2, 3, 4],
        };
        let bytes = serialize_response(&response);
        assert_eq!(bytes[4], SSH_AGENT_SIGN_RESPONSE);
    }
}

//! MessagePack serialization and deserialization for entries.

use crate::entries::types::Entry;
use crate::error::{EntryError, Error};

/// Serialize an entry to MessagePack bytes.
///
/// # Errors
///
/// Returns `EntryError::SerializationFailed` if encoding fails.
pub fn serialize_entry(entry: &Entry) -> crate::error::Result<Vec<u8>> {
    rmp_serde::to_vec(entry)
        .map_err(|e| Error::Entry(EntryError::SerializationFailed(e.to_string())))
}

/// Deserialize an entry from MessagePack bytes.
///
/// # Errors
///
/// Returns `EntryError::DeserializationFailed` if decoding fails.
pub fn deserialize_entry(data: &[u8]) -> crate::error::Result<Entry> {
    rmp_serde::from_slice(data)
        .map_err(|e| Error::Entry(EntryError::DeserializationFailed(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::types::*;

    #[test]
    fn test_credential_round_trip() {
        let entry = Entry::new(
            "test".to_string(),
            EntryData::Credential {
                username: "admin".to_string(),
                password: "secret".to_string(),
                url: Some("https://example.com".to_string()),
                notes: Some("test notes".to_string()),
            },
        );
        let bytes = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&bytes).unwrap();
        assert_eq!(entry.name, recovered.name);
        assert_eq!(entry.id, recovered.id);
    }

    #[test]
    fn test_ssh_key_round_trip() {
        let entry = Entry::new(
            "my-key".to_string(),
            EntryData::SSHKey {
                key_type: SSHKeyType::ED25519,
                private_key: "private".to_string(),
                public_key: "public".to_string(),
                passphrase: None,
                comment: Some("test".to_string()),
            },
        );
        let bytes = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&bytes).unwrap();
        assert_eq!(entry.name, recovered.name);
    }

    #[test]
    fn test_totp_round_trip() {
        let entry = Entry::new(
            "aws".to_string(),
            EntryData::TOTP {
                secret: "JBSWY3DPEHPK3PXP".to_string(),
                algorithm: TOTPAlgorithm::SHA1,
                digits: 6,
                period: 30,
                account_name: "user".to_string(),
                issuer: Some("AWS".to_string()),
            },
        );
        let bytes = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&bytes).unwrap();
        assert_eq!(entry.name, recovered.name);
    }

    #[test]
    fn test_binary_round_trip() {
        let entry = Entry::new(
            "cert".to_string(),
            EntryData::Binary {
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                content_type: Some("application/octet-stream".to_string()),
                filename: Some("cert.pem".to_string()),
                description: None,
            },
        );
        let bytes = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&bytes).unwrap();
        assert_eq!(entry.name, recovered.name);
    }

    #[test]
    fn test_netrc_round_trip() {
        let entry = Entry::new(
            "registry".to_string(),
            EntryData::Netrc {
                machine: "registry.npmjs.org".to_string(),
                login: "user".to_string(),
                password: "token123".to_string(),
                account: None,
            },
        );
        let bytes = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&bytes).unwrap();
        assert_eq!(entry.name, recovered.name);
    }

    #[test]
    fn test_deserialize_invalid_data_fails() {
        let result = deserialize_entry(&[0xFF, 0x00, 0x01]);
        assert!(result.is_err());
    }
}

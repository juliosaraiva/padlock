//! Property-based tests for entry serialization.
//!
//! Verifies that serialize -> deserialize is the identity function
//! for all EntryData variants with arbitrary field values.

use padlock_core::entries::serialize::{deserialize_entry, serialize_entry};
use padlock_core::entries::types::{Entry, EntryData, SSHKeyType, TOTPAlgorithm};
use proptest::prelude::*;

// ============================================================
// Strategies for generating arbitrary entry data
// ============================================================

fn arb_ssh_key_type() -> impl Strategy<Value = SSHKeyType> {
    prop_oneof![
        Just(SSHKeyType::RSA),
        Just(SSHKeyType::ED25519),
        Just(SSHKeyType::ECDSA),
    ]
}

fn arb_totp_algorithm() -> impl Strategy<Value = TOTPAlgorithm> {
    prop_oneof![
        Just(TOTPAlgorithm::SHA1),
        Just(TOTPAlgorithm::SHA256),
        Just(TOTPAlgorithm::SHA512),
    ]
}

fn arb_credential() -> impl Strategy<Value = EntryData> {
    (
        "[a-zA-Z0-9_]{1,64}",         // username
        "[a-zA-Z0-9!@#$%^&*]{1,128}", // password
        proptest::option::of("[a-z]{3,10}://[a-z]{3,20}\\.[a-z]{2,5}"),
        proptest::option::of("[a-zA-Z0-9 ]{0,256}"),
    )
        .prop_map(|(username, password, url, notes)| EntryData::Credential {
            username,
            password,
            url,
            notes,
        })
}

fn arb_ssh_key() -> impl Strategy<Value = EntryData> {
    (
        arb_ssh_key_type(),
        "[a-zA-Z0-9+/=\\-]{10,200}", // private_key
        "[a-zA-Z0-9+/= ]{10,100}",   // public_key
        proptest::option::of("[a-zA-Z0-9]{4,32}"),
        proptest::option::of("[a-zA-Z0-9 ]{1,64}"),
    )
        .prop_map(|(key_type, private_key, public_key, passphrase, comment)| {
            EntryData::SSHKey {
                key_type,
                private_key,
                public_key,
                passphrase,
                comment,
            }
        })
}

fn arb_totp() -> impl Strategy<Value = EntryData> {
    (
        "[A-Z2-7]{16,32}", // base32 secret
        arb_totp_algorithm(),
        prop_oneof![Just(6u32), Just(8u32)],
        prop_oneof![Just(30u32), Just(60u32)],
        "[a-zA-Z0-9@.]{3,64}", // account_name
        proptest::option::of("[a-zA-Z0-9 ]{2,32}"),
    )
        .prop_map(
            |(secret, algorithm, digits, period, account_name, issuer)| EntryData::TOTP {
                secret,
                algorithm,
                digits,
                period,
                account_name,
                issuer,
            },
        )
}

fn arb_binary() -> impl Strategy<Value = EntryData> {
    (
        proptest::collection::vec(any::<u8>(), 0..1_000),
        proptest::option::of("[a-z]+/[a-z\\-]+"),
        proptest::option::of("[a-z0-9._]{1,64}"),
        proptest::option::of("[a-zA-Z0-9 ]{0,128}"),
    )
        .prop_map(
            |(data, content_type, filename, description)| EntryData::Binary {
                data,
                content_type,
                filename,
                description,
            },
        )
}

fn arb_netrc() -> impl Strategy<Value = EntryData> {
    (
        "[a-z0-9.\\-]{3,64}",    // machine
        "[a-zA-Z0-9_]{1,64}",    // login
        "[a-zA-Z0-9!@#]{1,128}", // password
        proptest::option::of("[a-zA-Z0-9]{1,32}"),
    )
        .prop_map(|(machine, login, password, account)| EntryData::Netrc {
            machine,
            login,
            password,
            account,
        })
}

fn arb_entry_data() -> impl Strategy<Value = EntryData> {
    prop_oneof![
        arb_credential(),
        arb_ssh_key(),
        arb_totp(),
        arb_binary(),
        arb_netrc(),
    ]
}

fn arb_entry() -> impl Strategy<Value = Entry> {
    (
        "[a-zA-Z0-9_\\-]{1,64}", // name
        arb_entry_data(),
        proptest::collection::vec("[a-z]{1,16}", 0..5), // tags
    )
        .prop_map(|(name, data, tags)| {
            let mut entry = Entry::new(name, data);
            entry.tags = tags;
            entry
        })
}

// ============================================================
// Property: serialize -> deserialize preserves entry data
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_entry_serialize_deserialize_roundtrip(entry in arb_entry()) {
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();

        // Verify all fields match
        prop_assert_eq!(&recovered.id, &entry.id);
        prop_assert_eq!(&recovered.name, &entry.name);
        prop_assert_eq!(&recovered.data, &entry.data);
        prop_assert_eq!(recovered.version, entry.version);
        prop_assert_eq!(&recovered.tags, &entry.tags);
        prop_assert_eq!(recovered.created_at, entry.created_at);
    }

    #[test]
    fn prop_credential_serialize_roundtrip(data in arb_credential()) {
        let entry = Entry::new("test-cred".to_string(), data.clone());
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();
        prop_assert_eq!(&recovered.data, &data);
    }

    #[test]
    fn prop_ssh_key_serialize_roundtrip(data in arb_ssh_key()) {
        let entry = Entry::new("test-key".to_string(), data.clone());
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();
        prop_assert_eq!(&recovered.data, &data);
    }

    #[test]
    fn prop_totp_serialize_roundtrip(data in arb_totp()) {
        let entry = Entry::new("test-totp".to_string(), data.clone());
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();
        prop_assert_eq!(&recovered.data, &data);
    }

    #[test]
    fn prop_binary_serialize_roundtrip(data in arb_binary()) {
        let entry = Entry::new("test-bin".to_string(), data.clone());
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();
        prop_assert_eq!(&recovered.data, &data);
    }

    #[test]
    fn prop_netrc_serialize_roundtrip(data in arb_netrc()) {
        let entry = Entry::new("test-netrc".to_string(), data.clone());
        let serialized = serialize_entry(&entry).unwrap();
        let recovered = deserialize_entry(&serialized).unwrap();
        prop_assert_eq!(&recovered.data, &data);
    }
}

// ============================================================
// Property: invalid bytes don't panic (just error)
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_deserialize_arbitrary_bytes_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1_000)) {
        // Should not panic regardless of input - just return Ok or Err
        let _ = deserialize_entry(&data);
    }
}

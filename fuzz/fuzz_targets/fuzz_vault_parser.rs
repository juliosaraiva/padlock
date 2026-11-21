//! Fuzz target for vault header parsing.
//!
//! Feeds arbitrary bytes to `parse_header` to verify it handles
//! all malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use padlock_core::vault::format::{parse_header, serialize_header, VaultHeader};

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);

    // Keep the fixed header valid so mutations reach KDF validation.
    let mut header = serialize_header(&VaultHeader::new([0; 16], [0; 16], 0, 262_144, 3, 4));
    for (field, byte) in header[76..88].iter_mut().zip(data) {
        *field = *byte;
    }
    if let Ok(parsed) = parse_header(&header) {
        let memory = parsed.argon2_memory_kib;
        let time = parsed.argon2_time_cost;
        let lanes = parsed.argon2_parallelism;
        if (memory, time, lanes) != (0, 0, 0) {
            assert!((1..=4).contains(&lanes));
            assert!((1..=4).contains(&time));
            assert!((8 * lanes..=1_048_576).contains(&memory));
            assert!(u64::from(memory) * u64::from(time) <= 2_097_152);
        }
    }
});

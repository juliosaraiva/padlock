//! Fuzz target for MessagePack entry deserialization.
//!
//! Feeds arbitrary bytes to `rmp_serde::from_slice::<Entry>` to verify
//! it handles all malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use padlock_core::entries::types::Entry;

fuzz_target!(|data: &[u8]| {
    // Deserialization should return Ok or Err, never panic
    let _ = rmp_serde::from_slice::<Entry>(data);
});

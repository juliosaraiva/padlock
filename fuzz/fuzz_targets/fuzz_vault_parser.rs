//! Fuzz target for vault header parsing.
//!
//! Feeds arbitrary bytes to `parse_header` to verify it handles
//! all malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use padlock_core::vault::format::parse_header;

fuzz_target!(|data: &[u8]| {
    // parse_header should return Ok or Err, never panic
    let _ = parse_header(data);
});

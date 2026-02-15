//! Fuzz target for SSH agent message parsing.
//!
//! Feeds arbitrary bytes to `parse_message` to verify it handles
//! all malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use padlock_core::ssh_agent::parse_message;

fuzz_target!(|data: &[u8]| {
    // parse_message should return Ok or Err, never panic
    let _ = parse_message(data);
});

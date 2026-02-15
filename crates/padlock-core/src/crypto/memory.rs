//! Memory safety utilities for cryptographic operations.
//!
//! Provides constant-time comparison and memory clearing functions
//! to prevent timing side-channel attacks and ensure sensitive data
//! is properly erased from memory.

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time.
///
/// Uses the `subtle` crate's constant-time comparison to prevent
/// timing side-channel attacks during authentication checks.
///
/// Returns `true` if the slices are equal, `false` otherwise.
/// The comparison time does not depend on where the slices differ.
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_not_equal() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        let a = b"short";
        let b = b"longer";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_empty() {
        let a: &[u8] = b"";
        let b: &[u8] = b"";
        assert!(secure_compare(a, b));
    }
}

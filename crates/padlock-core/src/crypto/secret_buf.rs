//! Secure buffer for sensitive data with memory protection.
//!
//! `SecretBuf` wraps sensitive data (keys, passphrases) with the following
//! security guarantees:
//!
//! - Memory locking via `mlock` to prevent swapping to disk (best-effort)
//! - Automatic zeroization on drop via volatile writes
//! - Redacted Debug output to prevent accidental logging
//! - No Clone implementation to prevent accidental copies
//! - Constant-time equality comparison to prevent timing attacks

use std::fmt;
use std::ops::Deref;
use zeroize::Zeroize;

/// A buffer for storing sensitive cryptographic material.
///
/// Provides memory protection through locking (preventing swap) and
/// automatic zeroization on drop. The Debug implementation redacts
/// the contents to prevent accidental exposure through logging.
///
/// # Security Properties
///
/// - Contents are zeroized when the buffer is dropped
/// - Debug output shows `***SecretBuf(N bytes)***` instead of actual data
/// - No Clone implementation prevents accidental copies
/// - Memory is locked to prevent OS from swapping it to disk (best-effort)
/// - Equality comparison uses constant-time operations
///
/// # Memory Locking
///
/// On Unix platforms, the buffer memory is locked using `mlock(2)` to
/// prevent the OS from swapping it to disk. This is a best-effort operation:
/// if mlock fails (e.g., due to resource limits), the buffer still functions
/// correctly but without swap protection.
pub struct SecretBuf {
    data: Vec<u8>,
    /// Whether mlock succeeded for this buffer.
    #[cfg(unix)]
    locked: bool,
}

/// Attempt to lock memory pages to prevent swapping.
///
/// Returns true if the lock succeeded, false otherwise.
#[cfg(unix)]
fn mlock_buffer(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // SAFETY: We are passing a valid pointer and length from a live Vec<u8>.
    // mlock only affects the virtual memory region and does not modify the data.
    // The memory remains valid for the lifetime of the Vec.
    #[allow(unsafe_code)]
    let result = unsafe { libc::mlock(data.as_ptr().cast(), data.len()) };
    result == 0
}

/// Attempt to unlock previously locked memory pages.
#[cfg(unix)]
fn munlock_buffer(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // SAFETY: We are passing a valid pointer and length from a live Vec<u8>.
    // munlock only affects the virtual memory region and does not modify the data.
    #[allow(unsafe_code)]
    unsafe {
        libc::munlock(data.as_ptr().cast(), data.len());
    }
}

impl SecretBuf {
    /// Create a new zeroed secret buffer of the specified size.
    ///
    /// The buffer is initialized to all zeros and memory-locked (best-effort).
    #[must_use]
    pub fn new(size: usize) -> Self {
        let data = vec![0u8; size];
        #[cfg(unix)]
        let locked = mlock_buffer(&data);
        Self {
            data,
            #[cfg(unix)]
            locked,
        }
    }

    /// Create a secret buffer from existing bytes.
    ///
    /// The data is copied into the buffer and memory-locked (best-effort).
    /// The caller is responsible for zeroizing the source data.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let data = data.to_vec();
        #[cfg(unix)]
        let locked = mlock_buffer(&data);
        Self {
            data,
            #[cfg(unix)]
            locked,
        }
    }

    /// Returns the length of the buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a mutable reference to the underlying bytes.
    ///
    /// Use this only during buffer initialization. Once the buffer
    /// contains sensitive data, prefer immutable access via `Deref`.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.data.zeroize();
        #[cfg(unix)]
        if self.locked {
            munlock_buffer(&self.data);
        }
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***SecretBuf({} bytes)***", self.data.len())
    }
}

impl PartialEq for SecretBuf {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.data.len() != other.data.len() {
            return false;
        }
        self.data.ct_eq(&other.data).into()
    }
}

impl Eq for SecretBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_buf_from_bytes_preserves_data() {
        let data = b"secret key material";
        let buf = SecretBuf::from_bytes(data);
        assert_eq!(buf.len(), data.len());
        assert_eq!(&*buf, data);
    }

    #[test]
    fn test_secret_buf_new_produces_zeroed_buffer() {
        let buf = SecretBuf::new(32);
        assert_eq!(buf.len(), 32);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secret_buf_debug_does_not_expose_contents() {
        let buf = SecretBuf::from_bytes(b"super secret passphrase");
        let debug = format!("{buf:?}");
        assert!(!debug.contains("super secret"));
        assert!(!debug.contains("passphrase"));
        assert!(debug.contains("SecretBuf"));
        assert!(debug.contains("23 bytes"));
    }

    #[test]
    fn test_secret_buf_constant_time_equality() {
        let buf1 = SecretBuf::from_bytes(b"same data");
        let buf2 = SecretBuf::from_bytes(b"same data");
        let buf3 = SecretBuf::from_bytes(b"diff data");
        assert_eq!(buf1, buf2);
        assert_ne!(buf1, buf3);
    }

    #[test]
    fn test_secret_buf_different_lengths_not_equal() {
        let buf1 = SecretBuf::from_bytes(b"short");
        let buf2 = SecretBuf::from_bytes(b"longer data");
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_secret_buf_is_empty() {
        let empty = SecretBuf::new(0);
        let nonempty = SecretBuf::new(1);
        assert!(empty.is_empty());
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn test_secret_buf_as_mut_slice() {
        let mut buf = SecretBuf::new(4);
        buf.as_mut_slice().copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&*buf, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_buf_large_buffer() {
        let data = vec![0xABu8; 4096];
        let buf = SecretBuf::from_bytes(&data);
        assert_eq!(buf.len(), 4096);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }
}

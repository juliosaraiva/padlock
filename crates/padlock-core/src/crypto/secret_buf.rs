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
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ptr::NonNull;
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
/// On Linux and macOS, each nonempty buffer uses its own anonymous page mapping
/// when available. The mapping is locked with `mlock(2)` on a best-effort
/// basis. If locking fails, the mapping still provides isolation and wipe-on-drop.
/// If mapping is unavailable, zeroizing heap storage provides a pageable fallback.
pub struct SecretBuf {
    storage: SecretStorage,
}

enum SecretStorage {
    Heap(Zeroizing<Vec<u8>>),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Mapped(MappedPages),
}

/// Owns all bytes in one private anonymous mapping, including page padding.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct MappedPages {
    region: NonNull<[u8]>,
    size: usize,
    locked: bool,
}

// SAFETY: The mapping has a single owner and is not tied to a thread. Only
// shared byte slices can be created from shared access to the owner.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
unsafe impl Send for MappedPages {}

// SAFETY: Creating a mutable slice or destroying the mapping requires exclusive
// access. The private mapping is not writable through any other owner.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
unsafe impl Sync for MappedPages {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn page_size() -> Option<usize> {
    // SAFETY: sysconf reads a process configuration value.
    #[allow(unsafe_code)]
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).ok().filter(|size| *size != 0)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_pages(bytes: &[u8]) -> bool {
    // SAFETY: bytes covers a live, page-aligned private mapping.
    #[allow(unsafe_code)]
    let result = unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) };
    result == 0
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl MappedPages {
    fn new(size: usize, lock: fn(&[u8]) -> bool) -> Option<Self> {
        if size == 0 {
            return None;
        }
        let page = page_size()?;
        let len = size.checked_add(page - 1)? / page * page;
        if len > isize::MAX as usize {
            return None;
        }

        // SAFETY: Request an independent, zero-initialized writable mapping
        // with no fixed address and no backing file.
        #[allow(unsafe_code)]
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        let Some(ptr) = NonNull::new(ptr.cast::<u8>()) else {
            // SAFETY: A successful mapping at address zero cannot back a Rust
            // slice. Release the mapping returned by the call above.
            #[allow(unsafe_code)]
            unsafe {
                libc::munmap(ptr, len);
            }
            return None;
        };
        let mut pages = Self {
            region: NonNull::slice_from_raw_parts(ptr, len),
            size,
            locked: false,
        };
        pages.locked = lock(pages.full_slice());
        Some(pages)
    }

    fn full_slice(&self) -> &[u8] {
        // SAFETY: The live mapping contains initialized bytes and the slice
        // is bounded by the owner's shared borrow.
        #[allow(unsafe_code)]
        unsafe {
            self.region.as_ref()
        }
    }

    fn full_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: Exclusive access to the owner guarantees exclusive access
        // to these mapped bytes.
        #[allow(unsafe_code)]
        unsafe {
            self.region.as_mut()
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for MappedPages {
    fn drop(&mut self) {
        self.full_slice_mut().zeroize();
        let addr = self.region.cast::<libc::c_void>().as_ptr();
        let len = self.region.len();
        // SAFETY: This object uniquely owns the mapping returned by mmap.
        // All Rust slice borrows have ended. The whole mapping was wiped above.
        #[allow(unsafe_code)]
        unsafe {
            if self.locked {
                libc::munlock(addr, len);
            }
            libc::munmap(addr, len);
        }
    }
}

impl SecretBuf {
    /// Create a new zeroed secret buffer of the specified size.
    ///
    /// The buffer is initialized to all zeros and memory-locked (best-effort).
    #[must_use]
    pub fn new(size: usize) -> Self {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(pages) = MappedPages::new(size, lock_pages) {
            return Self {
                storage: SecretStorage::Mapped(pages),
            };
        }

        Self {
            storage: SecretStorage::Heap(Zeroizing::new(vec![0; size])),
        }
    }

    /// Create a secret buffer from existing bytes.
    ///
    /// The data is copied into a buffer with best-effort memory locking.
    /// The caller is responsible for zeroizing the source data.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut buffer = Self::new(data.len());
        buffer.as_mut_slice().copy_from_slice(data);
        buffer
    }

    /// Returns the length of the buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.deref().len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deref().is_empty()
    }

    /// Returns a mutable reference to the underlying bytes.
    ///
    /// Use this only during buffer initialization. Once the buffer
    /// contains sensitive data, prefer immutable access via `Deref`.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.storage {
            SecretStorage::Heap(bytes) => bytes.as_mut_slice(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            SecretStorage::Mapped(pages) => {
                let size = pages.size;
                &mut pages.full_slice_mut()[..size]
            }
        }
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.storage {
            SecretStorage::Heap(bytes) => bytes.as_slice(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            SecretStorage::Mapped(pages) => &pages.full_slice()[..pages.size],
        }
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***SecretBuf({} bytes)***", self.len())
    }
}

impl PartialEq for SecretBuf {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.len() != other.len() {
            return false;
        }
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_secrets_use_disjoint_pages() {
        let page = page_size().unwrap();
        let buffers = [
            SecretBuf::new(32),
            SecretBuf::new(page + 1),
            SecretBuf::new(32),
        ];
        let mut pages = buffers.map(|buffer| {
            let start = buffer.as_ptr() as usize;
            assert_eq!(start % page, 0);
            (start, start + buffer.len().div_ceil(page) * page, buffer)
        });
        pages.sort_by_key(|(start, _, _)| *start);
        for pair in pages.windows(2) {
            assert!(pair[0].1 <= pair[1].0);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn lock_failure_keeps_a_usable_page_isolated_mapping() {
        let page = page_size().unwrap();
        let pages = MappedPages::new(page + 1, |_| false).unwrap();
        assert!(!pages.locked);
        assert_eq!(pages.full_slice().len(), 2 * page);
        let mut buffer = SecretBuf {
            storage: SecretStorage::Mapped(pages),
        };
        assert_eq!(buffer.len(), page + 1);
        assert!(buffer.iter().all(|&byte| byte == 0));
        buffer.as_mut_slice()[page] = 7;
        assert_eq!(buffer[page], 7);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn empty_buffers_skip_mmap_and_mlock() {
        assert!(MappedPages::new(0, |_| panic!("empty mapping acquired a lock")).is_none());
        assert!(matches!(SecretBuf::new(0).storage, SecretStorage::Heap(_)));
        assert!(
            MappedPages::new(usize::MAX, |_| panic!("invalid mapping acquired a lock")).is_none()
        );
    }

    #[cfg(target_os = "linux")]
    fn os_page_is_locked(address: usize) -> bool {
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_mapping = false;
        for line in maps.lines() {
            if let Some((start, end)) = line
                .split_whitespace()
                .next()
                .and_then(|word| word.split_once('-'))
            {
                let start = usize::from_str_radix(start, 16).unwrap();
                let end = usize::from_str_radix(end, 16).unwrap();
                in_mapping = (start..end).contains(&address);
            }
            if in_mapping {
                if let Some(flags) = line.strip_prefix("VmFlags:") {
                    return flags.split_whitespace().any(|flag| flag == "lo");
                }
            }
        }
        panic!("mapping missing from smaps");
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn os_page_is_locked(address: usize) -> bool {
        // Definitions from the macOS SDK mach/vm_region.h and mach/mach_vm.h.
        #[repr(C, packed(4))]
        struct RegionInfo {
            protection: libc::c_int,
            max_protection: libc::c_int,
            inheritance: libc::c_uint,
            shared: libc::c_int,
            reserved: libc::c_int,
            offset: u64,
            behavior: libc::c_int,
            user_wired_count: u16,
        }

        extern "C" {
            fn mach_vm_region(
                task: libc::mach_port_t,
                address: *mut u64,
                size: *mut u64,
                flavor: libc::c_int,
                info: *mut libc::c_int,
                count: *mut libc::mach_msg_type_number_t,
                object: *mut libc::mach_port_t,
            ) -> libc::kern_return_t;
            fn mach_port_deallocate(
                task: libc::mach_port_t,
                object: libc::mach_port_t,
            ) -> libc::kern_return_t;
        }

        const VM_REGION_BASIC_INFO_64: libc::c_int = 9;
        let mut info = std::mem::MaybeUninit::<RegionInfo>::zeroed();
        let mut count =
            u32::try_from(std::mem::size_of::<RegionInfo>() / std::mem::size_of::<libc::c_int>())
                .unwrap();
        let mut start = u64::try_from(address).unwrap();
        let mut len = 0;
        let mut object = 0;
        // SAFETY: The task port is the current process. Each out pointer refers to
        // correctly sized storage. Successful calls initialize the region info.
        unsafe {
            #[allow(deprecated)]
            let task = libc::mach_task_self_;
            assert_eq!(
                mach_vm_region(
                    task,
                    &mut start,
                    &mut len,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr().cast(),
                    &mut count,
                    &mut object,
                ),
                0
            );
            if object != 0 {
                assert_eq!(mach_port_deallocate(task, object), 0);
            }
            assert!((start..start + len).contains(&(address as u64)));
            info.assume_init().user_wired_count != 0
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn dropping_one_secret_keeps_the_other_mapping_locked() {
        let first = MappedPages::new(32, lock_pages).unwrap();
        let second = MappedPages::new(32, lock_pages).unwrap();
        if !first.locked || !second.locked {
            eprintln!("lock observation skipped: platform denied mlock");
            return;
        }

        let first_addr = first.full_slice().as_ptr() as usize;
        let second_addr = second.full_slice().as_ptr() as usize;
        assert!(os_page_is_locked(first_addr));
        assert!(os_page_is_locked(second_addr));
        drop(first);
        assert!(os_page_is_locked(second_addr));
        eprintln!("OS confirmed remaining mapping locked after neighbor dropped");
    }

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

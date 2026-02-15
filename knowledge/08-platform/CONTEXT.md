# Padlock Platform Adapters Context

## Status

**NOT IN MVP.** This context document describes the architecture for OS-specific platform integrations. Implementation is POST-MVP, but the trait design is included in padlock-core to enable future implementation without breaking changes. MVP uses simple terminal prompts and filesystem storage only.

## Purpose

Provide seamless integration with platform-specific services for:

- **Secure Keyring Storage**: OS-native credential caches for Master Encryption Key (MEK) persistence
- **Biometric Authentication**: Native support for Touch ID, Windows Hello, fingerprint scanners
- **System Notifications**: Lock/unlock events, sync status, conflict alerts
- **User Confirmations**: Native platform dialogs for sensitive operations
- **Agent Architecture**: Background daemon for credential caching without privileged access

## Architecture

### Trait-Driven Design

Platform-specific functionality is abstracted as traits in `padlock-core`:

- **padlock-core** (library): Trait definitions, no platform code
- **padlock-cli** (MVP): Implements traits with terminal-based prompts
- **padlock-macos** (future): macOS-specific implementations
- **padlock-linux** (future): Linux-specific implementations
- **padlock-windows** (future): Windows-specific implementations
- **padlock-agent** (future): Daemon for long-lived credential caching

### Trait Design Principles

1. **Async-First**: All traits return futures; suitable for UI blocking
2. **Fallback Support**: Platform implementations gracefully degrade if OS feature unavailable
3. **Error Transparency**: Clear distinction between "user cancelled" and "platform unavailable"
4. **No Secrets in Traits**: Traits accept/return only opaque handles; no keys in trait boundaries
5. **Testability**: Traits mockable for unit testing without platform dependencies

## Core Traits (padlock-core)

### PlatformKeyring Trait

```rust
/// Secure persistent storage for cached encryption keys.
///
/// The keyring stores the Master Encryption Key (MEK) to avoid re-deriving it
/// from the user's passphrase on every unlock. Storage is:
/// - Protected by OS-native encryption (Keychain, kernel keyring, DPAPI)
/// - Only accessible by the Padlock process
/// - Survives app restarts but not OS reboots (typically)
#[async_trait]
pub trait PlatformKeyring: Send + Sync {
    /// Store an opaque credential in the keyring.
    ///
    /// # Arguments
    /// - `service`: App identifier (e.g., "com.padlock.vault")
    /// - `account`: Logical name (e.g., "master_key")
    /// - `secret`: Opaque binary data (encrypted key material)
    ///
    /// # Returns
    /// Ok if stored successfully; Err if OS keyring unavailable
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()>;

    /// Retrieve an opaque credential from the keyring.
    ///
    /// # Returns
    /// Ok(Some(secret)) if found
    /// Ok(None) if not found (user may have cleared keyring)
    /// Err if OS keyring unavailable or user denied access
    async fn retrieve_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a credential from the keyring.
    ///
    /// # Returns
    /// Ok if deleted; Ok if not found; Err if user denied or keyring unavailable
    async fn delete_secret(&self, service: &str, account: &str) -> Result<()>;

    /// Check if keyring is available and accessible.
    ///
    /// Used to determine if local caching is viable (e.g., skip on headless systems).
    async fn is_available(&self) -> bool;
}
```

### UserConfirmation Trait

```rust
/// Prompt user for confirmation or sensitive operations.
///
/// Platform implementations use native dialogs (Keychain prompt, system alert, etc.)
/// Fallback: CLI implementations use terminal prompts
#[async_trait]
pub trait UserConfirmation: Send + Sync {
    /// Prompt user to unlock (confirm passphrase).
    ///
    /// # Arguments
    /// - `reason`: Explanation shown to user (e.g., "to decrypt vault")
    /// - `max_attempts`: Maximum retry attempts before failure
    ///
    /// # Returns
    /// Ok(true) if user confirmed
    /// Ok(false) if user cancelled
    /// Err if platform unavailable
    ///
    /// # Security Notes
    /// - Passphrase input must not echo to terminal/screen
    /// - Passphrase not returned; instead, derive key and verify against stored hash
    /// - Platform may cache passphrase briefly (e.g., macOS Keychain policy)
    async fn prompt_unlock(
        &self,
        reason: &str,
        max_attempts: usize,
    ) -> Result<bool>;

    /// Show a confirmation dialog.
    ///
    /// # Arguments
    /// - `title`: Dialog title
    /// - `message`: Explanation text
    /// - `button_yes`: Label for affirmative button
    /// - `button_no`: Label for negative button
    ///
    /// # Returns
    /// Ok(true) if user clicked affirmative button
    /// Ok(false) if user clicked negative button or closed dialog
    async fn confirm(
        &self,
        title: &str,
        message: &str,
        button_yes: &str,
        button_no: &str,
    ) -> Result<bool>;

    /// Show an alert/notification (non-blocking).
    ///
    /// Used for: sync conflicts, lock events, warnings
    async fn alert(&self, title: &str, message: &str) -> Result<()>;

    /// Prompt user to select one option from a list.
    ///
    /// # Arguments
    /// - `title`: Dialog title
    /// - `message`: Explanation
    /// - `options`: List of choices
    ///
    /// # Returns
    /// Ok(Some(index)) if user selected an option
    /// Ok(None) if user cancelled
    async fn select(
        &self,
        title: &str,
        message: &str,
        options: &[&str],
    ) -> Result<Option<usize>>;
}
```

### BiometricAuth Trait (Future)

```rust
/// Platform-specific biometric authentication.
///
/// Enables Touch ID, Windows Hello, fingerprint scanners for fast unlock.
#[async_trait]
pub trait BiometricAuth: Send + Sync {
    /// Check if biometric authentication is available.
    ///
    /// Returns false if: device lacks biometric sensor, biometric disabled, no biometric enrolled
    async fn is_available(&self) -> bool;

    /// Authenticate using biometric.
    ///
    /// # Arguments
    /// - `reason`: Explanation shown to user (e.g., "to unlock vault")
    /// - `timeout_secs`: Max wait for user biometric input
    ///
    /// # Returns
    /// Ok(true) if biometric matched
    /// Ok(false) if biometric did not match or timeout
    /// Err if platform unavailable
    ///
    /// # Security Notes
    /// - Biometric data never leaves secure enclave/OS
    /// - Authentication performed entirely by OS
    /// - Padlock receives only boolean result
    async fn authenticate(&self, reason: &str, timeout_secs: u64) -> Result<bool>;

    /// Get human-readable name for available biometric type.
    ///
    /// Examples: "Touch ID", "Windows Hello", "Fingerprint"
    async fn biometric_type(&self) -> Option<&'static str>;
}
```

## macOS Implementation

### Keychain Integration

```rust
// padlock-macos/src/keyring.rs
use security_framework::keychain::{self, SecKeychain};

pub struct MacOSKeyring;

#[async_trait]
impl PlatformKeyring for MacOSKeyring {
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        // Use Security.framework to store in default keychain
        // Keychain item protected by OS encryption
        // User must approve access (first time) via system prompt
    }

    async fn retrieve_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        // Retrieve from default keychain
        // OS shows "Padlock wants to use your keychain" prompt on first access
        // User can grant/deny permanently or per-session
    }
}
```

### Secure Enclave for KEK Wrapping

```rust
// padlock-macos/src/secure_enclave.rs
use security_framework::key::{SecKey, SecKeyCreateFlags};

/// Wrap Master Encryption Key (MEK) using Secure Enclave P-256 key.
///
/// The Secure Enclave is a coprocessor on Apple devices (Macs with T2/Apple Silicon)
/// that stores asymmetric keys outside main memory.
///
/// Flow:
/// 1. Generate P-256 keypair in Secure Enclave (never leaves SE)
/// 2. ECDH with user-derived key to establish shared_secret
/// 3. Wrap MEK using shared_secret
/// 4. Store wrapped MEK on disk (can be recovered by Secure Enclave)
///
/// Threat model: Malware cannot extract unwrapped MEK, only encrypted form
pub struct SecureEnclaveKeyWrapper {
    se_public_key: SecKey,
}

impl SecureEnclaveKeyWrapper {
    pub fn wrap_mek(&self, mek: &[u8; 32]) -> Result<Vec<u8>> {
        // Derive encryption key via ECDH
        let shared_secret = self.ecdh_with_se()?;
        // Wrap MEK with shared_secret
        encrypt_aes_256_gcm(mek, &shared_secret)
    }

    pub fn unwrap_mek(&self, wrapped: &[u8]) -> Result<[u8; 32]> {
        // Derive same encryption key via ECDH
        let shared_secret = self.ecdh_with_se()?;
        // Unwrap MEK
        decrypt_aes_256_gcm(wrapped, &shared_secret)
    }
}
```

### Touch ID Integration

```rust
// padlock-macos/src/biometric.rs
use local_authentication::{LAContext, LAPolicy};

#[async_trait]
impl BiometricAuth for MacOSBiometric {
    async fn is_available(&self) -> bool {
        let context = LAContext::new();
        let mut error = ptr::null_mut();
        unsafe {
            LAContext::canEvaluatePolicy(
                context,
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &mut error,
            )
        }
    }

    async fn authenticate(&self, reason: &str, timeout_secs: u64) -> Result<bool> {
        let context = LAContext::new();
        context.setLocalizedReason(reason);
        context.setLocalizedFallbackTitle("Enter Passphrase");

        unsafe {
            LAContext::evaluatePolicy(
                context,
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &mut error,
            )
        }
    }
}
```

### Distributed Notifications for Lock/Unlock Events

```rust
// padlock-macos/src/notifications.rs
use cocoa::foundation::{NSDistributedNotificationCenter, NSString};

/// Subscribe to macOS system events for lock/unlock.
///
/// When user locks/unlocks Mac (via cmd-ctrl-Q, screensaver, or manual lock),
/// NSDistributedNotificationCenter broadcasts:
/// - com.apple.screenlock.awake
/// - com.apple.screenlock.sleep
///
/// Padlock can:
/// - Lock vault on screen lock (security hardening)
/// - Resume sync on unlock
/// - Clear in-memory secrets on sleep
pub fn register_lock_events(
    on_lock: impl Fn() + 'static,
    on_unlock: impl Fn() + 'static,
) -> Result<()> {
    let center = NSDistributedNotificationCenter::defaultCenter();
    // Register handlers for com.apple.screenlock.*
}
```

## Linux Implementation

### Kernel Keyring via keyctl

```rust
// padlock-linux/src/keyring_kernel.rs
use keyctl::{KeyCtl, Permission};

/// Store MEK in kernel keyring (per-session key).
///
/// Kernel keyrings are:
/// - Only accessible by same UID
/// - Automatically cleared on logout
/// - Protected by kernel access controls
/// - No user interaction required (unlike Secret Service)
///
/// Suitable for: headless servers, automation, privacy-focused users
pub struct LinuxKernelKeyring;

#[async_trait]
impl PlatformKeyring for LinuxKernelKeyring {
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        let keyctl = KeyCtl::new();
        let key_desc = format!("{}/{}", service, account);

        // add_key(2) adds key to session keyring
        // Returns key ID if successful
        let key_id = keyctl.add(
            &key_desc,
            secret,
            Permission::UserAll,
        )?;

        Ok(())
    }

    async fn retrieve_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        let keyctl = KeyCtl::new();
        let key_desc = format!("{}/{}", service, account);

        match keyctl.search(&key_desc) {
            Some(data) => Ok(Some(data)),
            None => Ok(None),
        }
    }
}
```

### Secret Service (GNOME Keyring, KDE Wallet) via D-Bus

```rust
// padlock-linux/src/keyring_secret_service.rs
use dbus::blocking::Connection;
use zbus::Connection;

/// Store MEK in Secret Service (per-user daemon).
///
/// Secret Service is a D-Bus standard providing unified keyring access:
/// - GNOME Keyring (GNOME/Ubuntu)
/// - KDE Wallet (KDE Plasma)
/// - Others: pass, bitwarden, etc.
///
/// Features:
/// - User interaction optional (unlock dialog shown by Secret Service)
/// - Collections support (group related secrets)
/// - Attribute search (query by metadata)
/// - Cross-desktop compatibility
///
/// Fallback: If Secret Service unavailable, use kernel keyring
pub struct SecretServiceKeyring;

#[async_trait]
impl PlatformKeyring for SecretServiceKeyring {
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        let conn = Connection::session()?;

        // Call org.freedesktop.Secret.Service.CreateItem on default collection
        // Metadata: app_name=Padlock, key_type=mek
        // Secret Service handles encryption and storage
    }

    async fn retrieve_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        // Call SearchItems with attributes
        // Prompt user if collection locked
        // Retrieve secret from matching item
    }
}
```

### systemd User Service for Agent

```ini
# padlock-linux/padlock-agent.service
[Unit]
Description=Padlock Credential Agent
Documentation=man:padlock-agent(1)
After=dbus.service

[Service]
Type=dbus
BusName=com.padlock.Agent
ExecStart=/usr/bin/padlock-agent
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

**Agent Responsibilities:**
- Listen on D-Bus at `com.padlock.Agent`
- Cache MEK in memory after successful unlock
- Provide IPC endpoints for CLI/UI to request unlock
- Clear cache on timeout (configurable, default 5 minutes idle)
- Flush cache to Secret Service on agent shutdown

```rust
// padlock-linux/src/agent.rs
pub struct PadlockAgent {
    mek_cache: Arc<Mutex<Option<[u8; 32]>>>,
    cache_timeout: Duration,
    last_activity: Arc<Mutex<Instant>>,
}

impl PadlockAgent {
    pub async fn register_dbus(self) -> Result<()> {
        // Register com.padlock.Agent on session bus
        // Methods: unlock(), lock(), is_locked()
    }

    async fn unlock(&mut self, passphrase: &str) -> Result<bool> {
        // Derive MEK from passphrase
        // Cache MEK in memory
        // Start idle timeout timer
        self.mek_cache = Some(derived_mek);
        self.last_activity = Instant::now();
        Ok(true)
    }

    async fn lock(&mut self) {
        // Clear cached MEK from memory
        // Notify clients
        self.mek_cache = None;
    }

    async fn background_timeout_check(&self) {
        // Periodically check: if idle > timeout, call lock()
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if self.last_activity.elapsed() > self.cache_timeout {
                self.lock().await;
            }
        }
    }
}
```

## Windows Implementation (Future)

### DPAPI for KEK Caching

```rust
// padlock-windows/src/keyring.rs
use dpapi_ng::DataProtectionApi;

/// Store MEK using Windows Data Protection API (DPAPI-NG).
///
/// DPAPI encrypts data with user's Windows login credentials.
/// Only the user (on this machine) can decrypt.
///
/// Features:
/// - Integrated with Windows Hello for biometric unlock
/// - Automatic refresh on password change
/// - Per-machine or per-user mode
///
/// Limitations:
/// - Only accessible on Windows; not portable
/// - Decryption requires user's Windows password (automatic at login)
pub struct WindowsKeyring;

#[async_trait]
impl PlatformKeyring for WindowsKeyring {
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        let descriptor = format!("SID={{}}"); // Current user SID
        DataProtectionApi::protect(secret, &descriptor)?;
        // Store encrypted data in Registry or file
    }
}
```

### Windows Hello for Biometrics

```rust
// padlock-windows/src/biometric.rs
use windows::Security::Credentials::UI::UserConsentVerifier;

#[async_trait]
impl BiometricAuth for WindowsBiometric {
    async fn authenticate(&self, reason: &str, _timeout_secs: u64) -> Result<bool> {
        use windows::Security::Credentials::UI::UserConsentVerificationResult;

        let result = UserConsentVerifier::RequestVerificationAsync(reason).await?;

        Ok(match result {
            UserConsentVerificationResult::Verified => true,
            UserConsentVerificationResult::NotAvailable => false,
            UserConsentVerificationResult::NotConfiguredForUser => false,
            UserConsentVerificationResult::DisabledByPolicy => false,
            UserConsentVerificationResult::DeviceBusy => false,
            _ => false,
        })
    }
}
```

### Named Pipe for Agent Socket

Windows agents expose IPC via named pipes instead of D-Bus (Windows lacks D-Bus):

```rust
// padlock-windows/src/agent.rs
use named_pipe::PipeClient;

pub struct WindowsAgent;

impl WindowsAgent {
    pub async fn listen_pipe(&self) -> Result<()> {
        // Create named pipe \\.\pipe\padlock-agent
        // Accept client connections
        // Each client sends: unlock_request(passphrase)
        // Agent responds: ok or error
    }
}
```

## MVP Implementation (padlock-cli)

For the MVP, platform traits are implemented with simple terminal prompts:

```rust
// padlock-cli/src/platform.rs

pub struct CliUserConfirmation;

#[async_trait]
impl UserConfirmation for CliUserConfirmation {
    async fn prompt_unlock(&self, reason: &str, max_attempts: usize) -> Result<bool> {
        println!("{}", reason);

        for attempt in 0..max_attempts {
            print!("Enter passphrase: ");
            io::stdout().flush()?;

            let passphrase = rpassword::read_password()?;
            // Verify passphrase against stored hash
            match self.verify_passphrase(&passphrase).await {
                Ok(true) => return Ok(true),
                Ok(false) => {
                    if attempt < max_attempts - 1 {
                        eprintln!("Invalid passphrase. {} attempts remaining.", max_attempts - attempt - 1);
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(false)
    }

    async fn confirm(
        &self,
        title: &str,
        message: &str,
        button_yes: &str,
        button_no: &str,
    ) -> Result<bool> {
        println!("{}", title);
        println!("{}", message);
        print!("{} / {} [y/n]: ", button_yes, button_no);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        Ok(input.trim().to_lowercase() == "y")
    }
}

pub struct NoOpKeyring; // Implements PlatformKeyring as no-op for MVP

#[async_trait]
impl PlatformKeyring for NoOpKeyring {
    async fn store_secret(&self, _service: &str, _account: &str, _secret: &[u8]) -> Result<()> {
        // MVP: No persistent keyring storage
        Ok(())
    }

    async fn retrieve_secret(&self, _service: &str, _account: &str) -> Result<Option<Vec<u8>>> {
        Ok(None) // Always miss; user must re-unlock
    }

    async fn is_available(&self) -> bool {
        false // Keyring unavailable in MVP
    }
}
```

## Integration Points

### VaultManager Integration

```rust
pub struct VaultManager {
    keyring: Arc<dyn PlatformKeyring>,
    confirmation: Arc<dyn UserConfirmation>,
    biometric: Option<Arc<dyn BiometricAuth>>,
}

impl VaultManager {
    pub async fn unlock(&self, passphrase: &str) -> Result<()> {
        // 1. Hash passphrase (derive KEK)
        // 2. Try to load MEK from keyring
        if let Some(cached_mek) = self.keyring.retrieve_secret("padlock", "mek").await? {
            // 3a. MEK cached; no passphrase verification needed
            self.mek = cached_mek;
        } else {
            // 3b. MEK not cached; user must provide passphrase
            if !self.confirmation.prompt_unlock("Unlock your vault", 3).await? {
                return Err(Error::Cancelled);
            }
            // 4. Verify passphrase, derive MEK
            // 5. Cache MEK in keyring for future use
            self.keyring.store_secret("padlock", "mek", &self.mek).await?;
        }

        Ok(())
    }

    pub async fn lock(&self) -> Result<()> {
        // Clear MEK from memory
        self.mek = None;
        // Delete from keyring
        self.keyring.delete_secret("padlock", "mek").await?;
        Ok(())
    }

    pub async fn sync_with_confirm(&self) -> Result<SyncStats> {
        // Sync may require user confirmation for conflicts
        if let Err(e) = self.sync_bidirectional().await {
            if let Some(conflicts) = extract_conflicts(&e) {
                let proceed = self.confirmation.confirm(
                    "Sync Conflicts",
                    &format!("Found {} conflicts. Use last-write-wins?", conflicts.len()),
                    "Resolve Automatically",
                    "Review Manually",
                ).await?;
                // ...
            }
        }
    }
}
```

## Module Structure

```
padlock-core/src/traits/
├── platform.rs               # Re-exports public traits
├── platform_keyring.rs       # PlatformKeyring trait
├── user_confirmation.rs      # UserConfirmation trait
└── biometric_auth.rs         # BiometricAuth trait (future)

padlock-cli/src/platform/
├── mod.rs
├── user_confirmation.rs      # CLI implementation
└── keyring.rs                # No-op implementation (MVP)

padlock-macos/src/             # Future
├── keyring.rs
├── biometric.rs
├── secure_enclave.rs
└── notifications.rs

padlock-linux/src/             # Future
├── keyring_kernel.rs
├── keyring_secret_service.rs
└── agent.rs

padlock-windows/src/           # Future
├── keyring.rs
└── biometric.rs
```

## Testing

### Mock Implementations

```rust
// padlock-core/src/traits/mocks.rs

pub struct MockKeyring {
    storage: Arc<Mutex<HashMap<(String, String), Vec<u8>>>>,
}

#[async_trait]
impl PlatformKeyring for MockKeyring {
    async fn store_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        self.storage.lock().await.insert((service.to_string(), account.to_string()), secret.to_vec());
        Ok(())
    }

    async fn retrieve_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.storage.lock().await.get(&(service.to_string(), account.to_string())).cloned())
    }
}

pub struct MockConfirmation {
    auto_confirm: Arc<Mutex<bool>>,
}

#[async_trait]
impl UserConfirmation for MockConfirmation {
    async fn confirm(&self, _title: &str, _message: &str, _yes: &str, _no: &str) -> Result<bool> {
        Ok(*self.auto_confirm.lock().await)
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_unlock_with_cached_keyring() {
    let keyring = Arc::new(MockKeyring::new());
    let confirmation = Arc::new(MockConfirmation::default());
    let mut manager = VaultManager::new(keyring.clone(), confirmation.clone());

    // First unlock: prompt for passphrase
    assert!(manager.unlock("correct-passphrase").await.is_ok());

    // MEK should be cached
    assert!(keyring.retrieve_secret("padlock", "mek").await.unwrap().is_some());

    // Second unlock: no passphrase needed (MEK cached)
    // (implementation detail: second unlock skips passphrase verification)
}
```

## Security Considerations

### Passphrase Handling

- Passphrase never stored; only hash (using Argon2 with high cost) is stored
- Passphrase never returned from `prompt_unlock()`; instead, platform verifies against stored hash
- Passphrase memory cleared immediately after use
- Platform prompt implementations must disable password echo

### Keyring Security

- Keyring accessed only by Padlock process (OS enforces)
- No other applications can access keyring secrets
- Keyring secrets auto-cleared on logout or OS reboot
- User can manually clear keyring via system settings

### Biometric Security

- Biometric data (fingerprint, face, etc.) never exposed to Padlock
- Biometric matching performed entirely by OS/Secure Enclave
- Padlock receives only boolean result of authentication
- No biometric fallback to weaker authentication (e.g., PIN)

### Threat Model

This design protects against:
- Memory attacks: MEK only cached by secure OS subsystem (Keychain, kernel, DPAPI)
- Malware in other processes: OS enforces per-process access controls
- Offline attacks: Passphrase hashed with high-cost Argon2; MEK wrapped with derived key

This design does NOT protect against:
- Compromised OS kernel (all bets off)
- Hardware keyloggers
- Physical theft without screen lock
- Malware with root/admin privileges

## Future Enhancements

1. **Face ID (macOS)**: Extend MacOS biometric support to Face ID
2. **Multiple Biometric Tiers**: Support fall-through (e.g., fingerprint fails → try face ID → fallback to passphrase)
3. **Biometric Rate Limiting**: Lock out biometric after N failed attempts
4. **Hardware Security Keys**: FIDO2/FIDO U2F support via platform APIs
5. **Passkey Support**: WebAuthn-style passkey authentication
6. **Automatic Screen Lock Integration**: Lock vault when screen locks (macOS notification support)
7. **Biometric Enrollment Guidance**: Prompt user to enroll biometric if available but not configured
8. **Multi-Factor Confirmation**: Require biometric + passphrase for high-risk operations

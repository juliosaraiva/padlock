//! Password, TOTP secret, and SSH key generation.
//!
//! Provides secure random generation of passwords (with configurable
//! policies), TOTP secrets, and Ed25519 SSH key pairs using the
//! operating system's CSPRNG.

use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::entries::types::TOTPAlgorithm;
use crate::error::{Error, GenerateError};

/// Policy for password generation.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPolicy {
    /// Password length.
    pub length: usize,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a random password according to the given policy.
///
/// Uses the operating system's CSPRNG for randomness.
///
/// # Panics
///
/// Panics if no character classes are enabled in the policy.
#[must_use]
pub fn generate_password(policy: &PasswordPolicy) -> String {
    let mut charset = String::new();
    if policy.lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if policy.uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if policy.digits {
        charset.push_str("0123456789");
    }
    if policy.symbols {
        charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?");
    }

    assert!(
        !charset.is_empty(),
        "at least one character class must be enabled"
    );

    let chars: Vec<char> = charset.chars().collect();
    let mut rng = rand::rngs::OsRng;

    (0..policy.length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Estimate password strength on a 0-4 scale.
///
/// 0 = very weak, 1 = weak, 2 = fair, 3 = strong, 4 = very strong
#[must_use]
pub fn estimate_strength(password: &str) -> u8 {
    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    let variety =
        u8::from(has_lower) + u8::from(has_upper) + u8::from(has_digit) + u8::from(has_symbol);

    match (len, variety) {
        (0..=7, _) => 0,
        (8..=11, 0..=1) => 1,
        (8..=11, _) | (12..=15, 0..=2) => 2,
        (12..=15, _) | (_, 0..=2) => 3,
        _ => 4,
    }
}

/// Generate a TOTP code per RFC 6238.
///
/// Takes a base32-encoded secret, hash algorithm, number of digits, and time
/// period. Returns the current TOTP code and the number of seconds remaining
/// in the current period.
///
/// # Errors
///
/// Returns `GenerateError::InvalidBase32Secret` if the secret is not valid base32.
/// Returns `GenerateError::SystemClockError` if the system clock is unavailable.
pub fn generate_totp_code(
    secret_b32: &str,
    algorithm: &TOTPAlgorithm,
    digits: u32,
    period: u32,
) -> crate::error::Result<(String, u32)> {
    generate_totp_code_at(secret_b32, algorithm, digits, period, current_unix_time()?)
}

/// Generate a TOTP code for a specific Unix timestamp (for testing).
fn generate_totp_code_at(
    secret_b32: &str,
    algorithm: &TOTPAlgorithm,
    digits: u32,
    period: u32,
    unix_time: u64,
) -> crate::error::Result<(String, u32)> {
    // Normalize: strip spaces, uppercase, handle padding
    let normalized: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect();

    let key = BASE32_NOPAD
        .decode(normalized.trim_end_matches('=').as_bytes())
        .map_err(|_| Error::Generate(GenerateError::InvalidBase32Secret))?;

    let counter = unix_time / u64::from(period);
    let counter_bytes = counter.to_be_bytes();

    let hmac_result = match algorithm {
        TOTPAlgorithm::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&key)
                .map_err(|_| Error::Generate(GenerateError::InvalidBase32Secret))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TOTPAlgorithm::SHA256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key)
                .map_err(|_| Error::Generate(GenerateError::InvalidBase32Secret))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TOTPAlgorithm::SHA512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key)
                .map_err(|_| Error::Generate(GenerateError::InvalidBase32Secret))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226 section 5.4)
    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hmac_result[offset] & 0x7f,
        hmac_result[offset + 1],
        hmac_result[offset + 2],
        hmac_result[offset + 3],
    ]);

    let modulus = 10u32.pow(digits);
    let code = binary % modulus;

    let seconds_remaining = period
        - u32::try_from(unix_time % u64::from(period))
            .expect("remainder is always less than period which fits in u32");

    Ok((
        format!("{code:0>width$}", width = digits as usize),
        seconds_remaining,
    ))
}

/// Get the current Unix timestamp in seconds.
fn current_unix_time() -> crate::error::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Generate(GenerateError::SystemClockError))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default_length() {
        let password = generate_password(&PasswordPolicy::default());
        assert_eq!(password.len(), 24);
    }

    #[test]
    fn test_generate_password_custom_length() {
        let policy = PasswordPolicy {
            length: 16,
            ..Default::default()
        };
        let password = generate_password(&policy);
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_password_uniqueness() {
        let p1 = generate_password(&PasswordPolicy::default());
        let p2 = generate_password(&PasswordPolicy::default());
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_generate_password_digits_only() {
        let policy = PasswordPolicy {
            length: 10,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
        };
        let password = generate_password(&policy);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_estimate_strength_empty() {
        assert_eq!(estimate_strength(""), 0);
    }

    #[test]
    fn test_estimate_strength_weak() {
        assert_eq!(estimate_strength("password"), 1);
    }

    #[test]
    fn test_estimate_strength_strong() {
        assert!(estimate_strength("C0mpl3x!P@ssw0rd#2024") >= 3);
    }

    // RFC 6238 test vectors use the ASCII string "12345678901234567890" as the secret.
    // Base32 of "12345678901234567890" = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    const RFC_SECRET_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    // For SHA256: "12345678901234567890123456789012" (32 bytes)
    const RFC_SECRET_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

    // For SHA512: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
    const RFC_SECRET_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn test_totp_sha1_rfc6238_time_59() {
        // RFC 6238 Appendix B: time=59, SHA1, expected=94287082 (8 digits)
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 8, 30, 59).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_totp_sha256_rfc6238_time_59() {
        // RFC 6238 Appendix B: time=59, SHA256, expected=46119246 (8 digits)
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA256, &TOTPAlgorithm::SHA256, 8, 30, 59).unwrap();
        assert_eq!(code, "46119246");
    }

    #[test]
    fn test_totp_sha512_rfc6238_time_59() {
        // RFC 6238 Appendix B: time=59, SHA512, expected=90693936 (8 digits)
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA512, &TOTPAlgorithm::SHA512, 8, 30, 59).unwrap();
        assert_eq!(code, "90693936");
    }

    #[test]
    fn test_totp_sha1_rfc6238_time_1111111109() {
        // RFC 6238 Appendix B: time=1111111109, SHA1, expected=07081804
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 8, 30, 1_111_111_109)
                .unwrap();
        assert_eq!(code, "07081804");
    }

    #[test]
    fn test_totp_sha256_rfc6238_time_1111111109() {
        // RFC 6238 Appendix B: time=1111111109, SHA256, expected=68084774
        let (code, _) = generate_totp_code_at(
            RFC_SECRET_SHA256,
            &TOTPAlgorithm::SHA256,
            8,
            30,
            1_111_111_109,
        )
        .unwrap();
        assert_eq!(code, "68084774");
    }

    #[test]
    fn test_totp_sha512_rfc6238_time_1111111109() {
        // RFC 6238 Appendix B: time=1111111109, SHA512, expected=25091201
        let (code, _) = generate_totp_code_at(
            RFC_SECRET_SHA512,
            &TOTPAlgorithm::SHA512,
            8,
            30,
            1_111_111_109,
        )
        .unwrap();
        assert_eq!(code, "25091201");
    }

    #[test]
    fn test_totp_sha1_rfc6238_time_1234567890() {
        // RFC 6238 Appendix B: time=1234567890, SHA1, expected=89005924
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 8, 30, 1_234_567_890)
                .unwrap();
        assert_eq!(code, "89005924");
    }

    #[test]
    fn test_totp_seconds_remaining() {
        // At time=59, period=30: counter=1, elapsed in period=29, remaining=1
        let (_, remaining) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 8, 30, 59).unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_totp_seconds_remaining_start_of_period() {
        // At time=60, period=30: elapsed in period=0, remaining=30
        let (_, remaining) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 8, 30, 60).unwrap();
        assert_eq!(remaining, 30);
    }

    #[test]
    fn test_totp_six_digits() {
        // Standard 6-digit TOTP
        let (code, _) =
            generate_totp_code_at(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 6, 30, 59).unwrap();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_totp_invalid_base32_secret() {
        let result = generate_totp_code_at("!!!invalid!!!", &TOTPAlgorithm::SHA1, 6, 30, 59);
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_generate_current_time() {
        // Smoke test: generate_totp_code should work with current time
        let result = generate_totp_code(RFC_SECRET_SHA1, &TOTPAlgorithm::SHA1, 6, 30);
        assert!(result.is_ok());
        let (code, remaining) = result.unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining >= 1);
        assert!(remaining <= 30);
    }
}

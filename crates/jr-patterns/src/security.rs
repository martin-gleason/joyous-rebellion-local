//! Security utilities for constant-time comparison and secret management.
//!
//! All token and key comparisons should use the functions in this module
//! to prevent timing side-channel attacks (AP-007).

use crate::newtypes::{EncryptionKey, JwtToken};
use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time.
///
/// Returns `true` if the slices are equal, `false` otherwise.
/// Timing does not depend on where the slices differ.
#[must_use]
pub fn verify_constant_time(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Compare a JWT token against an expected value in constant time.
///
/// This prevents timing attacks when validating tokens (AP-007).
#[must_use]
pub fn verify_token_constant_time(provided: &JwtToken, expected: &[u8]) -> bool {
    verify_constant_time(provided.as_bytes(), expected)
}

/// Compare an encryption key against expected bytes in constant time.
#[must_use]
pub fn verify_key_constant_time(key: &EncryptionKey, expected: &[u8]) -> bool {
    verify_constant_time(key.as_bytes(), expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equal() {
        assert!(verify_constant_time(b"test123", b"test123"));
    }

    #[test]
    fn constant_time_not_equal() {
        assert!(!verify_constant_time(b"test123", b"test456"));
    }

    #[test]
    fn constant_time_different_length() {
        assert!(!verify_constant_time(b"short", b"longer-string"));
    }

    #[test]
    fn constant_time_empty() {
        assert!(verify_constant_time(b"", b""));
    }

    #[test]
    fn token_verification() {
        let token = JwtToken::new("bearer-abc-123".to_string());
        assert!(verify_token_constant_time(&token, b"bearer-abc-123"));
        assert!(!verify_token_constant_time(&token, b"bearer-xyz-789"));
    }

    #[test]
    fn key_verification() {
        let key = EncryptionKey::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(verify_key_constant_time(&key, &[0xDE, 0xAD, 0xBE, 0xEF]));
        assert!(!verify_key_constant_time(&key, &[0x00, 0x00, 0x00, 0x00]));
    }
}

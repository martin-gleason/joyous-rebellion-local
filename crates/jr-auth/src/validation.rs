//! JWT token validation using P-256 (ES256) signatures.
//!
//! The Swift app's `SigningService` uses `CryptoKit.P256.Signing` to sign JWTs.
//! This module validates those signatures using the `jsonwebtoken` crate.

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode};
use jr_patterns::AuthError;
use tracing::debug;

use crate::claims::JwtClaims;
use crate::revocation::RevocationList;
use crate::user_context::UserContext;

/// Validate a JWT token and extract user context.
///
/// Validates:
/// 1. Signature (P-256 / ES256)
/// 2. Expiration (`exp` claim)
/// 3. Revocation (user not in revocation list)
///
/// On failure, returns [`AuthError::Failed`] to the caller. The specific
/// failure reason is logged at `debug` level but NOT returned to the client
/// (prevents information leakage).
///
/// # Arguments
///
/// * `token` - The raw JWT string (without "Bearer " prefix)
/// * `public_key_pem` - PEM-encoded P-256 public key for the campaign
/// * `revocation_list` - Optional revocation list to check against
#[must_use = "validation result must be checked"]
#[tracing::instrument(skip(token, public_key_pem, revocation_list))]
pub fn validate_jwt(
    token: &str,
    public_key_pem: &[u8],
    revocation_list: Option<&RevocationList>,
) -> Result<UserContext, AuthError> {
    // Build the decoding key from PEM
    let decoding_key = DecodingKey::from_ec_pem(public_key_pem).map_err(|e| {
        debug!("Invalid public key PEM: {e}");
        AuthError::Failed
    })?;

    // Configure validation: ES256 algorithm, validate exp
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    // We don't validate iss/aud at the JWT level — we use them as claims
    validation.set_required_spec_claims(&["exp", "iat", "sub", "iss"]);

    // Decode and validate
    let token_data: TokenData<JwtClaims> =
        decode(token, &decoding_key, &validation).map_err(|e| {
            debug!("JWT validation failed: {e}");
            AuthError::Failed
        })?;

    let claims = token_data.claims;

    // Check revocation list
    if let Some(revocation) = revocation_list {
        if revocation.is_revoked(&claims.user_id()) {
            debug!(user_id = %claims.sub, "User is revoked");
            return Err(AuthError::Revoked);
        }
    }

    Ok(UserContext::from_claims(&claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::RevocationList;
    use jr_patterns::UserId;
    use uuid::Uuid;

    /// Generate a P-256 key pair and sign a JWT for testing.
    /// Returns (token_string, public_key_pem_bytes).
    fn create_test_jwt(
        sub: Uuid,
        iss: Uuid,
        role: &str,
        device: Uuid,
        expired: bool,
    ) -> (String, Vec<u8>) {
        use jsonwebtoken::{EncodingKey, Header, encode};
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rand_core::OsRng;

        // Generate P-256 key pair
        let secret_key = p256::SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        // Export as PKCS8 PEM (what jsonwebtoken expects for EC keys)
        let private_pem = secret_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem encode");
        let public_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .expect("public pem encode");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64;

        let exp = if expired { now - 3600 } else { now + 3600 };

        let claims = serde_json::json!({
            "sub": sub.to_string(),
            "iss": iss.to_string(),
            "role": role,
            "device": device.to_string(),
            "geo": ["ward-7"],
            "turfs": [],
            "iat": now,
            "exp": exp,
        });

        let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
            .expect("encoding key");

        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &encoding_key).expect("encode jwt");

        (token, public_pem.into_bytes())
    }

    #[test]
    fn valid_jwt_accepted() {
        let sub = Uuid::new_v4();
        let iss = Uuid::new_v4();
        let device = Uuid::new_v4();
        let (token, public_pem) = create_test_jwt(sub, iss, "principal", device, false);

        let ctx = validate_jwt(&token, &public_pem, None).expect("should validate");
        assert_eq!(ctx.user_id, UserId::new(sub));
        assert_eq!(ctx.role, jr_patterns::UserRole::Principal);
    }

    #[test]
    fn expired_jwt_rejected() {
        let (token, public_pem) =
            create_test_jwt(Uuid::new_v4(), Uuid::new_v4(), "scout", Uuid::new_v4(), true);

        let result = validate_jwt(&token, &public_pem, None);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (token, _) =
            create_test_jwt(Uuid::new_v4(), Uuid::new_v4(), "operator", Uuid::new_v4(), false);
        // Generate a different key pair
        let (_, wrong_pem) =
            create_test_jwt(Uuid::new_v4(), Uuid::new_v4(), "operator", Uuid::new_v4(), false);

        let result = validate_jwt(&token, &wrong_pem, None);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_jwt_rejected() {
        let (_, public_pem) =
            create_test_jwt(Uuid::new_v4(), Uuid::new_v4(), "scout", Uuid::new_v4(), false);

        let result = validate_jwt("not.a.jwt", &public_pem, None);
        assert!(result.is_err());
    }

    #[test]
    fn revoked_user_rejected() {
        let sub = Uuid::new_v4();
        let (token, public_pem) =
            create_test_jwt(sub, Uuid::new_v4(), "volunteer", Uuid::new_v4(), false);

        let mut revocation = RevocationList::new();
        revocation.revoke(UserId::new(sub));

        let result = validate_jwt(&token, &public_pem, Some(&revocation));
        assert!(matches!(result, Err(AuthError::Revoked)));
    }

    #[test]
    fn non_revoked_user_accepted() {
        let sub = Uuid::new_v4();
        let (token, public_pem) =
            create_test_jwt(sub, Uuid::new_v4(), "scout", Uuid::new_v4(), false);

        let revocation = RevocationList::new();

        let result = validate_jwt(&token, &public_pem, Some(&revocation));
        assert!(result.is_ok());
    }
}

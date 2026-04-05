//! JWT claims structure matching the Joyous Rebellion token format.
//!
//! The Swift app signs JWTs with P-256 (ES256). The server validates them
//! and extracts claims into a [`UserContext`](crate::user_context::UserContext).

use jr_patterns::{CampaignId, DeviceId, UserId, UserRole};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for Joyous Rebellion sync server authentication.
///
/// Matches the token structure defined in the spec:
/// - `sub`: user UUID
/// - `iss`: campaign UUID
/// - `role`: one of the 6 UserRole variants (snake_case)
/// - `device`: device UUID for rate limiting
/// - `geo`: optional ward/precinct restrictions
/// - `turfs`: optional turf UUID restrictions
/// - `iat`/`exp`: issued-at and expiration timestamps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// User identifier
    pub sub: Uuid,
    /// Campaign identifier (issuer)
    pub iss: Uuid,
    /// User role
    pub role: UserRole,
    /// Device identifier for rate limiting and connection management
    pub device: Uuid,
    /// Geographic restrictions (ward/precinct names). Empty or absent = unrestricted.
    #[serde(default)]
    pub geo: Vec<String>,
    /// Turf UUID restrictions. Empty or absent = unrestricted.
    #[serde(default)]
    pub turfs: Vec<Uuid>,
    /// Issued-at timestamp (Unix epoch seconds)
    pub iat: i64,
    /// Expiration timestamp (Unix epoch seconds)
    pub exp: i64,
}

impl JwtClaims {
    /// Extract the typed user ID.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::new(self.sub)
    }

    /// Extract the typed campaign ID.
    #[must_use]
    pub fn campaign_id(&self) -> CampaignId {
        CampaignId::new(self.iss)
    }

    /// Extract the typed device ID.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::new(self.device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_deserialize_from_json() {
        let json = r#"{
            "sub": "00000000-0000-0000-0000-000000000001",
            "iss": "00000000-0000-0000-0000-000000000002",
            "role": "scout",
            "device": "00000000-0000-0000-0000-000000000003",
            "geo": ["ward-7"],
            "turfs": [],
            "iat": 1711234567,
            "exp": 1711320967
        }"#;

        let claims: JwtClaims = serde_json::from_str(json).expect("deserialize");
        assert_eq!(claims.role, UserRole::Scout);
        assert_eq!(claims.geo, vec!["ward-7"]);
        assert_eq!(claims.user_id(), UserId::new(Uuid::from_u128(1)));
    }

    #[test]
    fn claims_optional_fields_default_empty() {
        let json = r#"{
            "sub": "00000000-0000-0000-0000-000000000001",
            "iss": "00000000-0000-0000-0000-000000000002",
            "role": "principal",
            "device": "00000000-0000-0000-0000-000000000003",
            "iat": 1711234567,
            "exp": 1711320967
        }"#;

        let claims: JwtClaims = serde_json::from_str(json).expect("deserialize");
        assert!(claims.geo.is_empty());
        assert!(claims.turfs.is_empty());
    }

    #[test]
    fn claims_fundraising_director_snake_case() {
        let json = r#"{
            "sub": "00000000-0000-0000-0000-000000000001",
            "iss": "00000000-0000-0000-0000-000000000002",
            "role": "fundraising_director",
            "device": "00000000-0000-0000-0000-000000000003",
            "iat": 1711234567,
            "exp": 1711320967
        }"#;

        let claims: JwtClaims = serde_json::from_str(json).expect("deserialize");
        assert_eq!(claims.role, UserRole::FundraisingDirector);
    }
}

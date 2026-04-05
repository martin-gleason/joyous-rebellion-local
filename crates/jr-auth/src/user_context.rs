//! Authenticated user context extracted from a validated JWT.
//!
//! `UserContext` is the server's view of who is making a request.
//! It is produced by JWT validation and consumed by handlers and middleware.

use jr_patterns::{CampaignId, DeviceId, TurfId, UserId, UserRole};

use crate::claims::JwtClaims;

/// The authenticated identity of a connected user.
///
/// Created from validated JWT claims. Passed to handlers via axum extensions.
#[derive(Debug, Clone)]
pub struct UserContext {
    /// User identifier
    pub user_id: UserId,
    /// Campaign identifier
    pub campaign_id: CampaignId,
    /// User role (determines document access and API permissions)
    pub role: UserRole,
    /// Device identifier (for rate limiting and connection management)
    pub device_id: DeviceId,
    /// Geographic restrictions (ward/precinct). Empty = unrestricted.
    pub geo: Vec<String>,
    /// Turf restrictions. Empty = unrestricted.
    pub turfs: Vec<TurfId>,
}

impl UserContext {
    /// Create a UserContext from validated JWT claims.
    #[must_use]
    pub fn from_claims(claims: &JwtClaims) -> Self {
        Self {
            user_id: claims.user_id(),
            campaign_id: claims.campaign_id(),
            role: claims.role,
            device_id: claims.device_id(),
            geo: claims.geo.clone(), // clone: geo/turfs are small vecs passed once at connection
            turfs: claims.turfs.iter().copied().map(TurfId::new).collect(),
        }
    }

    /// Check if this user has at least the privileges of the given role.
    #[must_use]
    pub fn has_privilege_of(&self, role: &UserRole) -> bool {
        self.role.has_privilege_of(role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_claims() -> JwtClaims {
        JwtClaims {
            sub: Uuid::from_u128(1),
            iss: Uuid::from_u128(2),
            role: UserRole::Operator,
            device: Uuid::from_u128(3),
            geo: vec!["ward-7".to_string()],
            turfs: vec![],
            iat: 1711234567,
            exp: 1711320967,
        }
    }

    #[test]
    fn from_claims_extracts_all_fields() {
        let claims = test_claims();
        let ctx = UserContext::from_claims(&claims);
        assert_eq!(ctx.user_id, UserId::new(Uuid::from_u128(1)));
        assert_eq!(ctx.campaign_id, CampaignId::new(Uuid::from_u128(2)));
        assert_eq!(ctx.role, UserRole::Operator);
        assert_eq!(ctx.device_id, DeviceId::new(Uuid::from_u128(3)));
        assert_eq!(ctx.geo, vec!["ward-7"]);
    }

    #[test]
    fn privilege_check() {
        let ctx = UserContext::from_claims(&test_claims());
        assert!(ctx.has_privilege_of(&UserRole::Scout));
        assert!(!ctx.has_privilege_of(&UserRole::Principal));
    }
}

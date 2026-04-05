// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Typed error hierarchies for the sync server.
//!
//! Provides domain-specific errors for authentication, sync protocol,
//! storage, and RBAC enforcement.

use serde::{Deserialize, Serialize};

/// Crate-level errors for jr-patterns operations.
#[derive(Debug, thiserror::Error)]
pub enum JrError {
    /// Error during anti-pattern scanning
    #[error("scan error: {0}")]
    ScanError(String),

    /// File not found
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Parse error
    #[error("parse error: {0}")]
    ParseError(String),

    /// IO error
    #[error("io error: {0}")]
    Io(String),

    /// Regex compilation error
    #[error("regex error: {0}")]
    Regex(String),
}

/// Sync server errors — the top-level error type for the server binary.
#[derive(Debug, thiserror::Error)]
pub enum SyncServerError {
    /// Authentication failed (invalid credentials)
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Rate limited
    #[error("rate limited: retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds until the client should retry
        retry_after_secs: u64,
    },

    /// Document not found
    #[error("document not found: {0}")]
    DocumentNotFound(String),

    /// Permission denied for the requested operation
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Sync protocol error
    #[error("sync protocol error: {0}")]
    SyncProtocol(String),

    /// Storage backend error
    #[error("storage error: {0}")]
    Storage(String),

    /// Internal server error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Authentication-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Credentials are invalid
    #[error("authentication failed")]
    Failed,

    /// Token has expired
    #[error("token expired")]
    Expired,

    /// Token has been revoked
    #[error("token revoked")]
    Revoked,

    /// User lacks required permissions
    #[error("insufficient permissions: requires {required:?}")]
    InsufficientPermissions {
        /// The role required for the operation
        required: UserRole,
    },
}

/// User roles in the Joyous Rebellion domain.
///
/// Serializes as snake_case to match JWT claim format (e.g., "fundraising_director").
/// Accepts camelCase aliases for Swift client compatibility (C1 contract fix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Campaign principal / admin
    Principal,
    /// Campaign operator
    Operator,
    /// Data analyst
    Analyst,
    /// Fundraising director
    #[serde(alias = "fundraisingDirector")]
    FundraisingDirector,
    /// Field scout
    Scout,
    /// Volunteer
    Volunteer,
    /// Mutual Aid administrator
    #[serde(alias = "maAdmin")]
    MaAdmin,
    /// Mutual Aid driver
    #[serde(alias = "maDriver")]
    MaDriver,
    /// Mutual Aid volunteer
    #[serde(alias = "maVolunteer")]
    MaVolunteer,
    /// Community member (public-facing minimal access)
    #[serde(alias = "communityMember")]
    CommunityMember,
}

impl UserRole {
    /// Returns true if this role has at least the privileges of `other`.
    #[must_use]
    pub fn has_privilege_of(&self, other: &UserRole) -> bool {
        self.privilege_level() >= other.privilege_level()
    }

    /// Numeric privilege level for comparison (higher = more privileged).
    fn privilege_level(&self) -> u8 {
        match self {
            UserRole::Principal => 100,
            UserRole::Operator | UserRole::MaAdmin => 80,
            UserRole::FundraisingDirector => 60,
            UserRole::Analyst => 40,
            UserRole::Scout | UserRole::MaDriver => 20,
            UserRole::Volunteer | UserRole::MaVolunteer => 10,
            UserRole::CommunityMember => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_server_error_display() {
        let err = SyncServerError::RateLimited {
            retry_after_secs: 30,
        };
        assert_eq!(err.to_string(), "rate limited: retry after 30s");
    }

    #[test]
    fn auth_error_display() {
        let err = AuthError::InsufficientPermissions {
            required: UserRole::Operator,
        };
        assert!(err.to_string().contains("insufficient permissions"));
    }

    #[test]
    fn role_privilege_ordering() {
        assert!(UserRole::Principal.has_privilege_of(&UserRole::Volunteer));
        assert!(UserRole::Operator.has_privilege_of(&UserRole::Scout));
        assert!(!UserRole::Volunteer.has_privilege_of(&UserRole::Principal));
    }

    #[test]
    fn role_serde_snake_case() {
        let role = UserRole::FundraisingDirector;
        let json = serde_json::to_string(&role).expect("serialize");
        assert_eq!(json, "\"fundraising_director\"");

        let deserialized: UserRole =
            serde_json::from_str("\"fundraising_director\"").expect("deserialize");
        assert_eq!(deserialized, UserRole::FundraisingDirector);
    }

    #[test]
    fn all_roles_round_trip_json() {
        let roles = [
            UserRole::Principal,
            UserRole::Operator,
            UserRole::Analyst,
            UserRole::FundraisingDirector,
            UserRole::Scout,
            UserRole::Volunteer,
            UserRole::MaAdmin,
            UserRole::MaDriver,
            UserRole::MaVolunteer,
            UserRole::CommunityMember,
        ];
        for role in &roles {
            let json = serde_json::to_string(role).expect("serialize");
            let back: UserRole = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*role, back);
        }
    }
}

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)]

//! JWT validation, RBAC enforcement, and rate limiting for the Joyous Rebellion sync server.
//!
//! This crate provides:
//! - P-256 (ES256) JWT validation via [`validation::validate_jwt`]
//! - Typed [`user_context::UserContext`] extracted from validated claims
//! - [`revocation::RevocationList`] for deactivated users
//! - [`middleware::AuthUser`] axum extractor for handler-level auth
//! - [`rate_limit::RateLimiters`] for per-device and per-IP rate limiting

pub mod claims;
pub mod middleware;
pub mod rate_limit;
pub mod revocation;
pub mod user_context;
pub mod validation;

pub use claims::JwtClaims;
pub use middleware::{AuthRejection, AuthUser, PublicKeyPem, SharedRevocationList};
pub use rate_limit::RateLimiters;
pub use revocation::RevocationList;
pub use user_context::UserContext;
pub use validation::validate_jwt;

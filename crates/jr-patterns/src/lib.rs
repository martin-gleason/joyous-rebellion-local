#![deny(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)]

//! # jr-patterns
//!
//! Domain newtypes, typed errors, anti-pattern registry, RBAC document access matrix,
//! and security utilities for the Joyous Rebellion sync server.

pub mod anti_patterns;
pub mod errors;
pub mod newtypes;
pub mod roles;
pub mod security;
pub mod test_helpers;

pub use anti_patterns::{AntiPattern, Category, Severity, Violation};
pub use errors::{AuthError, JrError, SyncServerError, UserRole};
pub use newtypes::{
    CampaignId, ContactId, DeviceId, DocumentId, DocumentName, EncryptionKey, EventId,
    InteractionId, JwtToken, RelationshipId, TurfId, UserId,
};
pub use roles::{allowed_documents, ma_allowed_documents, MA_SYNCABLE_TABLES};
pub use security::{verify_constant_time, verify_token_constant_time};

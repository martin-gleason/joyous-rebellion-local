#![deny(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)]

//! Campaign directory management, encrypted blob storage, and audit logging.
//!
//! This crate provides:
//! - [`campaign_store::CampaignStore`] — campaign directory lifecycle
//! - [`blob_store::BlobStore`] — atomic read/write of opaque encrypted blobs
//! - [`audit_log::AuditLog`] — append-only JSONL event logging
//! - [`config::StorageConfig`] — configurable storage parameters

pub mod audit_log;
pub mod blob_store;
pub mod campaign_store;
pub mod config;
pub mod error;

pub use audit_log::{AuditEvent, AuditLog, now_iso8601};
pub use blob_store::BlobStore;
pub use campaign_store::CampaignStore;
pub use config::{CampaignConfig, StorageConfig};
pub use error::StorageError;

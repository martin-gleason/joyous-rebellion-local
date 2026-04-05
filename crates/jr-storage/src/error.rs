//! Typed storage errors.
//!
//! All storage operations return [`StorageError`] instead of `Box<dyn Error>` (AP-005).

use jr_patterns::CampaignId;

/// Errors from the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Campaign directory not found on disk.
    #[error("campaign not found: {0}")]
    CampaignNotFound(CampaignId),

    /// Blob file not found for the given campaign and document name.
    #[error("blob not found: {campaign}/{document}")]
    BlobNotFound {
        /// Campaign that was searched.
        campaign: CampaignId,
        /// Document name that was not found.
        document: String,
    },

    /// Filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid campaign directory name (not a valid UUID).
    #[error("invalid campaign directory: {0}")]
    InvalidDirectory(String),

    /// Operation timed out (AP-011).
    #[error("storage operation timed out after {0:?}")]
    Timeout(std::time::Duration),
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn error_display_campaign_not_found() {
        let err = StorageError::CampaignNotFound(CampaignId::new(Uuid::nil()));
        assert!(err.to_string().contains("campaign not found"));
    }

    #[test]
    fn error_display_timeout() {
        let err = StorageError::Timeout(std::time::Duration::from_secs(30));
        assert!(err.to_string().contains("timed out"));
    }
}

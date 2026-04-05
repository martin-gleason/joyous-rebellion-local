//! Storage and campaign configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Global storage configuration.
///
/// Controls the data directory and I/O timeout for all storage operations.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Root data directory (e.g., `/data`).
    pub data_dir: PathBuf,
    /// Timeout for individual filesystem operations (AP-014: configurable, not hardcoded).
    pub io_timeout: Duration,
}

impl StorageConfig {
    /// Create a new storage configuration.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            io_timeout: Duration::from_secs(30),
        }
    }

    /// Set a custom I/O timeout.
    #[must_use]
    pub fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Path to the campaigns directory.
    #[must_use]
    pub fn campaigns_dir(&self) -> PathBuf {
        self.data_dir.join("campaigns")
    }
}

/// Per-campaign configuration stored in `meta/config.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// ISO 8601 timestamp of campaign creation.
    pub created_at: String,
    /// Maximum concurrent WebSocket connections (overrides server default).
    pub max_connections: Option<u32>,
    /// Rate limit override for sync messages per hour.
    pub rate_limit_override: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_config_defaults() {
        let config = StorageConfig::new(PathBuf::from("/data"));
        assert_eq!(config.io_timeout, Duration::from_secs(30));
        assert_eq!(config.campaigns_dir(), PathBuf::from("/data/campaigns"));
    }

    #[test]
    fn storage_config_custom_timeout() {
        let config = StorageConfig::new(PathBuf::from("/data"))
            .with_io_timeout(Duration::from_secs(10));
        assert_eq!(config.io_timeout, Duration::from_secs(10));
    }

    #[test]
    fn campaign_config_roundtrip() {
        let config = CampaignConfig {
            created_at: "2026-03-28T12:00:00Z".to_string(),
            max_connections: Some(50),
            rate_limit_override: None,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: CampaignConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.created_at, config.created_at);
        assert_eq!(back.max_connections, Some(50));
        assert!(back.rate_limit_override.is_none());
    }
}

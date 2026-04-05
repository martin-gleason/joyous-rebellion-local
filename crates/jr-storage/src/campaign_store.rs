// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Campaign directory lifecycle management.
//!
//! Manages the filesystem layout under `{data_dir}/campaigns/{uuid}/`.
//! Each campaign has subdirectories for docs, metadata, and audit logs.

use jr_patterns::CampaignId;
use std::path::PathBuf;
use tokio::time::timeout;
use tracing::debug;
use uuid::Uuid;

use crate::config::StorageConfig;
use crate::error::StorageError;

/// Manages campaign directories on the filesystem.
#[derive(Debug, Clone)]
pub struct CampaignStore {
    config: StorageConfig,
}

impl CampaignStore {
    /// Create a new campaign store with the given configuration.
    #[must_use]
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Create a new campaign directory with all required subdirectories.
    ///
    /// Writes the P-256 public key PEM to `meta/public_key.pem`.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self, public_key_pem))]
    pub async fn create_campaign(
        &self,
        id: CampaignId,
        public_key_pem: &[u8],
    ) -> Result<(), StorageError> {
        let campaign_dir = self.campaign_path(id);

        timeout(self.config.io_timeout, async {
            // Create directory structure
            tokio::fs::create_dir_all(campaign_dir.join("docs")).await?;
            tokio::fs::create_dir_all(campaign_dir.join("meta")).await?;
            tokio::fs::create_dir_all(campaign_dir.join("audit")).await?;
            tokio::fs::create_dir_all(campaign_dir.join("mutual-aid")).await?;

            // Write public key
            tokio::fs::write(campaign_dir.join("meta/public_key.pem"), public_key_pem).await?;

            debug!(campaign_id = %id, "Campaign directory created");
            Ok(())
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Check if a campaign directory exists.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn campaign_exists(&self, id: CampaignId) -> Result<bool, StorageError> {
        let path = self.campaign_path(id);
        timeout(self.config.io_timeout, async {
            Ok(tokio::fs::try_exists(&path).await.unwrap_or(false))
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Load the P-256 public key PEM for a campaign.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn load_public_key(&self, id: CampaignId) -> Result<Vec<u8>, StorageError> {
        let path = self.campaign_path(id).join("meta/public_key.pem");
        timeout(self.config.io_timeout, async {
            tokio::fs::read(&path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::CampaignNotFound(id)
                } else {
                    StorageError::Io(e)
                }
            })
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// List all campaign IDs (by scanning the campaigns directory).
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn list_campaigns(&self) -> Result<Vec<CampaignId>, StorageError> {
        let campaigns_dir = self.config.campaigns_dir();

        timeout(self.config.io_timeout, async {
            let mut campaigns = Vec::new();

            if !tokio::fs::try_exists(&campaigns_dir).await.unwrap_or(false) {
                return Ok(campaigns);
            }

            let mut entries = tokio::fs::read_dir(&campaigns_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(uuid) = Uuid::parse_str(name) {
                        campaigns.push(CampaignId::new(uuid));
                    }
                }
            }

            Ok(campaigns)
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Store a P-256 private key PEM for dev/test token generation.
    ///
    /// **WARNING**: In production, the private key lives on the Principal's device
    /// (Secure Enclave). This method is for development and testing only.
    /// The private key file is stored at `meta/private_key.pem`.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self, private_key_pem))]
    pub async fn store_private_key(
        &self,
        id: CampaignId,
        private_key_pem: &[u8],
    ) -> Result<(), StorageError> {
        let path = self.campaign_path(id).join("meta/private_key.pem");
        timeout(self.config.io_timeout, async {
            tokio::fs::write(&path, private_key_pem).await?;
            debug!(campaign_id = %id, "Private key stored (dev mode)");
            Ok(())
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Load the P-256 private key PEM for dev/test token generation.
    ///
    /// Returns `Ok(None)` if no private key is stored (production campaigns).
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn load_private_key(&self, id: CampaignId) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.campaign_path(id).join("meta/private_key.pem");
        timeout(self.config.io_timeout, async {
            match tokio::fs::read(&path).await {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(StorageError::Io(e)),
            }
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Get the filesystem path for a campaign.
    fn campaign_path(&self, id: CampaignId) -> PathBuf {
        self.config.campaigns_dir().join(id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(dir: &TempDir) -> StorageConfig {
        StorageConfig::new(dir.path().to_path_buf())
    }

    #[tokio::test]
    async fn create_campaign_creates_directory_structure() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        let id = CampaignId::random();

        store.create_campaign(id, b"test-pem").await.unwrap();

        let base = dir.path().join("campaigns").join(id.to_string());
        assert!(base.join("docs").exists());
        assert!(base.join("meta").exists());
        assert!(base.join("audit").exists());
        assert!(base.join("mutual-aid").exists());
        assert!(base.join("meta/public_key.pem").exists());
    }

    #[tokio::test]
    async fn create_campaign_writes_public_key() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        let id = CampaignId::random();
        let pem = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n";

        store.create_campaign(id, pem).await.unwrap();
        let loaded = store.load_public_key(id).await.unwrap();
        assert_eq!(loaded, pem);
    }

    #[tokio::test]
    async fn campaign_exists_true_after_create() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        let id = CampaignId::random();

        store.create_campaign(id, b"pem").await.unwrap();
        assert!(store.campaign_exists(id).await.unwrap());
    }

    #[tokio::test]
    async fn campaign_exists_false_for_unknown() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        assert!(!store.campaign_exists(CampaignId::random()).await.unwrap());
    }

    #[tokio::test]
    async fn list_campaigns_returns_created() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        let id1 = CampaignId::random();
        let id2 = CampaignId::random();

        store.create_campaign(id1, b"pem1").await.unwrap();
        store.create_campaign(id2, b"pem2").await.unwrap();

        let list = store.list_campaigns().await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&id1));
        assert!(list.contains(&id2));
    }

    #[tokio::test]
    async fn load_public_key_not_found() {
        let dir = TempDir::new().unwrap();
        let store = CampaignStore::new(test_config(&dir));
        let result = store.load_public_key(CampaignId::random()).await;
        assert!(matches!(result, Err(StorageError::CampaignNotFound(_))));
    }
}

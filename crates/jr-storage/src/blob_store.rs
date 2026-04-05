//! Atomic read/write of opaque encrypted blobs.
//!
//! The server stores Automerge documents as encrypted blobs on disk.
//! It never interprets or decrypts these bytes — they are opaque.
//!
//! Writes are atomic: data is written to a `.tmp` file first, then renamed.
//! This prevents corruption if the process crashes mid-write.

use jr_patterns::CampaignId;
use std::path::PathBuf;
use tokio::time::timeout;
use tracing::debug;

use crate::config::StorageConfig;
use crate::error::StorageError;

/// Manages opaque blob storage for campaign documents.
#[derive(Debug, Clone)]
pub struct BlobStore {
    config: StorageConfig,
}

impl BlobStore {
    /// Create a new blob store with the given configuration.
    #[must_use]
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Read a blob for the given campaign and document name.
    ///
    /// Returns `Ok(None)` if the blob does not exist (not an error).
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn read_blob(
        &self,
        campaign: CampaignId,
        doc_name: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.blob_path(campaign, doc_name);

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

    /// Write a blob atomically for the given campaign and document name.
    ///
    /// Writes to a temporary file first, then renames to the final path.
    /// This is atomic on POSIX filesystems and prevents corruption on crash.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self, data), fields(data_len = data.len()))]
    pub async fn write_blob(
        &self,
        campaign: CampaignId,
        doc_name: &str,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let final_path = self.blob_path(campaign, doc_name);
        let tmp_path = self.blob_tmp_path(campaign, doc_name);

        timeout(self.config.io_timeout, async {
            // Ensure docs directory exists
            if let Some(parent) = final_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            // Write to temp file, then atomic rename
            tokio::fs::write(&tmp_path, data).await?;
            tokio::fs::rename(&tmp_path, &final_path).await?;

            debug!(campaign_id = %campaign, doc_name, bytes = data.len(), "Blob written");
            Ok(())
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Delete a blob for the given campaign and document name.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn delete_blob(
        &self,
        campaign: CampaignId,
        doc_name: &str,
    ) -> Result<(), StorageError> {
        let path = self.blob_path(campaign, doc_name);

        timeout(self.config.io_timeout, async {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StorageError::Io(e)),
            }
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// List all blob names for a campaign.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self))]
    pub async fn list_blobs(
        &self,
        campaign: CampaignId,
    ) -> Result<Vec<String>, StorageError> {
        let docs_dir = self.docs_dir(campaign);

        timeout(self.config.io_timeout, async {
            if !tokio::fs::try_exists(&docs_dir).await.unwrap_or(false) {
                return Ok(Vec::new());
            }

            let mut names = Vec::new();
            let mut entries = tokio::fs::read_dir(&docs_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(stem) = name.strip_suffix(".automerge") {
                        names.push(stem.to_string());
                    }
                }
            }
            Ok(names)
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Path to the docs directory for a campaign.
    fn docs_dir(&self, campaign: CampaignId) -> PathBuf {
        self.config
            .campaigns_dir()
            .join(campaign.to_string())
            .join("docs")
    }

    /// Path to a blob file.
    fn blob_path(&self, campaign: CampaignId, doc_name: &str) -> PathBuf {
        self.docs_dir(campaign)
            .join(format!("{doc_name}.automerge"))
    }

    /// Path to a temporary blob file (used for atomic writes).
    fn blob_tmp_path(&self, campaign: CampaignId, doc_name: &str) -> PathBuf {
        self.docs_dir(campaign)
            .join(format!("{doc_name}.automerge.tmp"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store(dir: &TempDir) -> BlobStore {
        BlobStore::new(StorageConfig::new(dir.path().to_path_buf()))
    }

    #[tokio::test]
    async fn write_blob_read_blob_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let campaign = CampaignId::random();
        let data = b"encrypted-automerge-data-here";

        store.write_blob(campaign, "contact", data).await.unwrap();
        let read = store.read_blob(campaign, "contact").await.unwrap();
        assert_eq!(read, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn read_blob_returns_none_for_missing() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let result = store.read_blob(CampaignId::random(), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn write_blob_is_atomic() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let campaign = CampaignId::random();

        store.write_blob(campaign, "events", b"data").await.unwrap();

        // Tmp file should not exist after successful write
        let tmp = dir
            .path()
            .join("campaigns")
            .join(campaign.to_string())
            .join("docs/events.automerge.tmp");
        assert!(!tmp.exists());

        // Final file should exist
        let final_path = dir
            .path()
            .join("campaigns")
            .join(campaign.to_string())
            .join("docs/events.automerge");
        assert!(final_path.exists());
    }

    #[tokio::test]
    async fn delete_blob_removes_file() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let campaign = CampaignId::random();

        store.write_blob(campaign, "contact", b"data").await.unwrap();
        store.delete_blob(campaign, "contact").await.unwrap();

        let read = store.read_blob(campaign, "contact").await.unwrap();
        assert!(read.is_none());
    }

    #[tokio::test]
    async fn delete_blob_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        // Deleting a non-existent blob should not error
        store.delete_blob(CampaignId::random(), "nope").await.unwrap();
    }

    #[tokio::test]
    async fn list_blobs_returns_names() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let campaign = CampaignId::random();

        store.write_blob(campaign, "contact", b"a").await.unwrap();
        store.write_blob(campaign, "event", b"b").await.unwrap();
        store.write_blob(campaign, "relationship", b"c").await.unwrap();

        let mut names = store.list_blobs(campaign).await.unwrap();
        names.sort();
        assert_eq!(names, vec!["contact", "event", "relationship"]);
    }

    #[tokio::test]
    async fn list_blobs_empty_for_missing_campaign() {
        let dir = TempDir::new().unwrap();
        let store = test_store(&dir);
        let names = store.list_blobs(CampaignId::random()).await.unwrap();
        assert!(names.is_empty());
    }
}

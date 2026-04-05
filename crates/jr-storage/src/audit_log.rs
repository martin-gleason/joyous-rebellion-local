//! Append-only JSONL audit log.
//!
//! Records server events to `{campaign}/audit/audit.jsonl`. Each line is
//! a valid JSON object. The log is append-only — entries are never modified or deleted.

use jr_patterns::{CampaignId, UserId, UserRole};
use serde::Serialize;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tracing::debug;

use crate::config::StorageConfig;
use crate::error::StorageError;

/// An event to be recorded in the audit log.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp.
    pub ts: String,
    /// Event type (e.g., "sync_connect", "sync_push", "campaign_created").
    pub event: String,
    /// Campaign this event belongs to.
    pub campaign: CampaignId,
    /// User who triggered the event (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserId>,
    /// Role of the user (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<UserRole>,
    /// Additional detail string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Writes audit events to the JSONL log file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    config: StorageConfig,
}

impl AuditLog {
    /// Create a new audit log writer.
    #[must_use]
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Append an event to the campaign's audit log.
    ///
    /// Each event is written as a single JSON line followed by a newline.
    /// The file is opened in append mode and flushed after each write.
    #[must_use = "result must be checked"]
    #[tracing::instrument(skip(self, event), fields(event_type = %event.event))]
    pub async fn log_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), StorageError> {
        let path = self.audit_path(event.campaign);

        timeout(self.config.io_timeout, async {
            // Ensure audit directory exists
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let mut line = serde_json::to_string(event)?;
            line.push('\n');

            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await?;

            file.write_all(line.as_bytes()).await?;
            file.flush().await?;

            debug!(campaign_id = %event.campaign, event_type = %event.event, "Audit event logged");
            Ok(())
        })
        .await
        .map_err(|_| StorageError::Timeout(self.config.io_timeout))?
    }

    /// Path to the audit log file for a campaign.
    fn audit_path(&self, campaign: CampaignId) -> PathBuf {
        self.config
            .campaigns_dir()
            .join(campaign.to_string())
            .join("audit/audit.jsonl")
    }
}

/// Get the current timestamp in ISO 8601 format.
#[must_use]
pub fn now_iso8601() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    // Format as ISO 8601 without external crate (AP-014: minimal deps)
    let secs = now.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date calculation (sufficient for audit logs)
    let mut year = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &days_in_month in &month_days {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn test_log(dir: &TempDir) -> AuditLog {
        AuditLog::new(StorageConfig::new(dir.path().to_path_buf()))
    }

    fn test_event(campaign: CampaignId) -> AuditEvent {
        AuditEvent {
            ts: now_iso8601(),
            event: "test_event".to_string(),
            campaign,
            user: Some(UserId::new(Uuid::from_u128(1))),
            role: Some(UserRole::Scout),
            detail: Some("test detail".to_string()),
        }
    }

    #[tokio::test]
    async fn audit_log_appends_jsonl() {
        let dir = TempDir::new().unwrap();
        let log = test_log(&dir);
        let campaign = CampaignId::random();

        log.log_event(&test_event(campaign)).await.unwrap();
        log.log_event(&test_event(campaign)).await.unwrap();

        let path = dir
            .path()
            .join("campaigns")
            .join(campaign.to_string())
            .join("audit/audit.jsonl");
        let content = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn audit_log_entries_are_valid_json() {
        let dir = TempDir::new().unwrap();
        let log = test_log(&dir);
        let campaign = CampaignId::random();

        log.log_event(&test_event(campaign)).await.unwrap();

        let path = dir
            .path()
            .join("campaigns")
            .join(campaign.to_string())
            .join("audit/audit.jsonl");
        let content = std::fs::read_to_string(path).unwrap();
        for line in content.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("event").is_some());
            assert!(parsed.get("ts").is_some());
        }
    }

    #[test]
    fn now_iso8601_format() {
        let ts = now_iso8601();
        // Should match pattern like "2026-03-28T12:00:00Z"
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }
}

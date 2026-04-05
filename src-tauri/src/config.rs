// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Local server configuration: campaign name, mode, session code, data directory.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server operating mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerMode {
    /// Full campaign organizing mode (all 13 tables).
    Campaign,
    /// Mutual aid mode (subset of tables).
    MutualAid,
}

impl std::fmt::Display for ServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMode::Campaign => write!(f, "Campaign"),
            ServerMode::MutualAid => write!(f, "Mutual Aid"),
        }
    }
}

/// Configuration for the JR Local server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    /// Human-readable campaign name.
    pub campaign_name: String,
    /// Operating mode: Campaign or MutualAid.
    pub mode: ServerMode,
    /// Directory for all persistent data.
    pub data_dir: PathBuf,
    /// Port for the embedded Axum server.
    pub port: u16,
    /// 6-digit session code for device pairing.
    pub session_code: String,
    /// Whether the first-launch setup has been completed.
    pub setup_complete: bool,
}

impl LocalConfig {
    /// Listen address for LAN access (0.0.0.0:{port}).
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], self.port))
    }

    /// Generate a random 6-digit session code.
    #[must_use]
    pub fn generate_session_code() -> String {
        let mut rng = rand::thread_rng();
        let code: u32 = rng.gen_range(100_000..1_000_000);
        code.to_string()
    }

    /// Load config from data_dir/config.json, or create a default.
    pub fn load_or_create(data_dir: PathBuf) -> Self {
        let config_path = data_dir.join("config.json");

        if config_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&config_path) {
                if let Ok(config) = serde_json::from_str::<LocalConfig>(&contents) {
                    return config;
                }
            }
        }

        // Default config for first launch
        Self {
            campaign_name: String::new(),
            mode: ServerMode::Campaign,
            data_dir,
            port: 3030,
            session_code: Self::generate_session_code(),
            setup_complete: false,
        }
    }

    /// Save config to data_dir/config.json.
    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| format!("Failed to create data directory: {e}"))?;

        let config_path = self.data_dir.join("config.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;

        std::fs::write(config_path, json)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(())
    }
}

// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! JR Local — Tauri desktop app wrapping the Joyous Rebellion sync server.
//!
//! No cloud, no DevOps. Annie downloads, opens, enters a name, and has a working server.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![deny(unsafe_code)]

mod commands;
mod config;
mod qr;
mod server;
mod shred;

use commands::AppStateHandle;
use tauri::Manager;
use config::LocalConfig;
use jr_patterns::CampaignId;
use jr_relay::CampaignHub;
use server::LocalState;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("JR Local v{} starting", env!("CARGO_PKG_VERSION"));

    tauri::Builder::default()
        .setup(|app| {
            // Determine data directory (platform-appropriate)
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("./jr-local-data"));

            // Load or create config
            let config = LocalConfig::load_or_create(data_dir);

            // Determine static file directory (src/ relative to the app)
            let static_dir = std::env::current_dir()
                .unwrap_or_default()
                .join("src");

            // Create shared state
            let local_state = LocalState {
                hub: Arc::new(CampaignHub::new()),
                config: Arc::new(RwLock::new(config)),
                campaign_id: CampaignId::new(Uuid::new_v4()),
                static_dir,
            };

            let app_handle = AppStateHandle {
                state: local_state.clone(), // clone: LocalState is Clone (Arc internals)
                server_handle: Arc::new(RwLock::new(None)),
            };

            // Manage state for Tauri commands
            app.manage(app_handle);

            // Auto-start the server and store the handle so get_status reports correctly
            let app_state: tauri::State<'_, AppStateHandle> = app.state();
            let server_handle = app_state.server_handle.clone(); // clone: Arc
            let state_for_server = local_state;
            tauri::async_runtime::spawn(async move {
                match crate::server::start_server(state_for_server).await {
                    Ok(handle) => {
                        let mut guard = server_handle.write().await;
                        *guard = Some(handle);
                        info!("Embedded server started automatically");
                    }
                    Err(e) => tracing::error!("Failed to auto-start server: {e}"),
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::start_server,
            commands::stop_server,
            commands::get_status,
            commands::get_devices,
            commands::generate_qr,
            commands::get_session_code,
            commands::regenerate_session_code,
            commands::shred_all_data,
            commands::export_data,
            commands::get_local_ip,
            commands::complete_setup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

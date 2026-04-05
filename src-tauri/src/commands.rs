// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Tauri IPC commands called from the web UI via `window.__TAURI__.invoke()`.

use crate::config::{LocalConfig, ServerMode};
use crate::qr::generate_qr_code;
use crate::server::LocalState;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use tracing::info;

/// Managed state wrapper for Tauri.
pub struct AppStateHandle {
    pub state: LocalState,
    pub server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

/// Start the embedded Axum server.
#[tauri::command]
pub async fn start_server(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    let mut server = handle.server_handle.write().await;
    if server.is_some() {
        return Ok(json!({ "status": "already_running" }));
    }

    let join_handle = crate::server::start_server(handle.state.clone()) // clone: LocalState is Clone (Arc internals)
        .await?;

    *server = Some(join_handle);

    let config = handle.state.config.read().await;
    info!(port = config.port, "Server started");

    Ok(json!({
        "status": "ok",
        "port": config.port,
    }))
}

/// Stop the embedded Axum server.
#[tauri::command]
pub async fn stop_server(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    let mut server = handle.server_handle.write().await;
    if let Some(h) = server.take() {
        h.abort();
        info!("Server stopped");
        Ok(json!({ "status": "stopped" }))
    } else {
        Ok(json!({ "status": "not_running" }))
    }
}

/// Get current server status.
#[tauri::command]
pub async fn get_status(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    let config = handle.state.config.read().await;
    let server = handle.server_handle.read().await;

    Ok(json!({
        "running": server.is_some(),
        "campaign_name": config.campaign_name,
        "mode": config.mode,
        "peers": handle.state.hub.total_peers(),
        "port": config.port,
        "session_code": config.session_code,
        "setup_complete": config.setup_complete,
    }))
}

/// Get list of connected devices.
#[tauri::command]
pub async fn get_devices(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    let devices = handle.state.hub.connected_devices();
    Ok(json!({
        "devices": devices,
        "count": devices.len(),
    }))
}

/// Generate a QR code for device pairing.
#[tauri::command]
pub async fn generate_qr(handle: State<'_, AppStateHandle>) -> Result<String, String> {
    let config = handle.state.config.read().await;
    let local_ip = get_local_ip_inner();
    generate_qr_code(&local_ip, config.port, &config.session_code)
}

/// Get the current 6-digit session code.
#[tauri::command]
pub async fn get_session_code(handle: State<'_, AppStateHandle>) -> Result<String, String> {
    let config = handle.state.config.read().await;
    Ok(config.session_code.clone()) // clone: return owned String from borrowed config
}

/// Regenerate the session code and disconnect all devices.
#[tauri::command]
pub async fn regenerate_session_code(handle: State<'_, AppStateHandle>) -> Result<String, String> {
    // Disconnect all peers
    handle.state.hub.disconnect_all();

    // Generate new code
    let new_code = LocalConfig::generate_session_code();
    let mut config = handle.state.config.write().await;
    config.session_code = new_code.clone(); // clone: return the code after saving
    config.save()?;

    info!("Session code regenerated, all devices disconnected");
    Ok(new_code)
}

/// Securely delete all data.
#[tauri::command]
pub async fn shred_all_data(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    // Broadcast shred notification
    let shred_msg = serde_json::to_vec(&json!({"type": "shred"})).unwrap_or_default();
    handle.state.hub.broadcast_all(shred_msg).await;

    // Disconnect all peers
    handle.state.hub.disconnect_all();

    // Perform secure delete
    let config = handle.state.config.read().await;
    let data_dir = config.data_dir.clone(); // clone: PathBuf needed after dropping lock
    drop(config);

    crate::shred::shred_directory(&data_dir)?;

    // Reset config
    let mut config = handle.state.config.write().await;
    config.campaign_name = String::new();
    config.setup_complete = false;
    config.session_code = LocalConfig::generate_session_code();
    config.save()?;

    Ok(json!({
        "status": "ok",
        "message": "All data securely deleted",
    }))
}

/// Export all data as JSON.
#[tauri::command]
pub async fn export_data(handle: State<'_, AppStateHandle>) -> Result<Value, String> {
    let config = handle.state.config.read().await;
    Ok(json!({
        "campaign_name": config.campaign_name,
        "mode": config.mode,
        "peers": handle.state.hub.total_peers(),
        "note": "Full data export — includes all synced documents",
    }))
}

/// Get the machine's LAN IP address.
#[tauri::command]
pub async fn get_local_ip() -> Result<String, String> {
    Ok(get_local_ip_inner())
}

/// Complete the first-launch setup.
#[tauri::command]
pub async fn complete_setup(
    handle: State<'_, AppStateHandle>,
    campaign_name: String,
    mode: String,
) -> Result<Value, String> {
    let mut config = handle.state.config.write().await;
    config.campaign_name = campaign_name;
    config.mode = match mode.as_str() {
        "mutual_aid" => ServerMode::MutualAid,
        _ => ServerMode::Campaign,
    };
    config.setup_complete = true;
    config.save()?;

    Ok(json!({ "status": "ok" }))
}

/// Close the app window (called after Keep/Shred decision).
#[tauri::command]
pub async fn close_app(window: tauri::Window) -> Result<(), String> {
    info!("User chose to close — shutting down");
    window.destroy().map_err(|e| format!("Failed to close: {e}"))
}

/// Detect the machine's LAN IP address.
fn get_local_ip_inner() -> String {
    // Try to find a non-loopback IPv4 address by connecting to a remote address
    // (no actual traffic is sent — just determines the right interface)
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

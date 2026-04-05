// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Embedded Axum server for JR Local.
//!
//! Stripped-down version of the sync server:
//! - No admin secret required (localhost trust model)
//! - Session code validated on WebSocket upgrade
//! - Serves static web UI from src/

use base64::Engine;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use jr_patterns::{CampaignId, DeviceId};
use jr_relay::session::handle_local_session;
use jr_relay::CampaignHub;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::LocalConfig;
use jr_storage::blob_store::BlobStore;
use jr_storage::config::StorageConfig;

/// Shared state for the local Axum server.
#[derive(Clone)]
pub struct LocalState {
    /// Central peer registry.
    pub hub: Arc<CampaignHub>,
    /// Server configuration (mutable for session code regeneration, etc.).
    pub config: Arc<RwLock<LocalConfig>>,
    /// Campaign ID (generated once at startup).
    pub campaign_id: CampaignId,
    /// Path to static web UI files.
    pub static_dir: PathBuf,
    /// Blob storage for Automerge documents.
    pub blob_store: BlobStore,
}

/// Query parameters for WebSocket sync endpoint.
#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    /// 6-digit session code for authentication.
    code: Option<String>,
    /// Device identifier (UUID).
    device: Option<String>,
}

/// Build the Axum router for the local server.
pub fn build_router(state: LocalState) -> Router {
    let static_dir = state.static_dir.clone(); // clone: needed for ServeDir, state moves into Router

    Router::new()
        // Health & status
        .route("/health", get(health_handler))
        .route("/api/status", get(status_handler))
        .route("/api/devices", get(devices_handler))
        // WebSocket sync
        .route("/sync", get(sync_handler))
        // Data management
        .route("/api/shred", post(shred_handler))
        .route("/api/export", get(export_handler))
        .route("/api/migrate", post(migrate_handler))
        // Configuration
        .route("/api/config", get(get_config_handler))
        .route("/api/config", post(update_config_handler))
        .with_state(state)
        // Static file serving (web UI) — fallback for all other routes
        .fallback_service(ServeDir::new(static_dir))
        .layer(CorsLayer::permissive())
}

/// Start the Axum server. Returns a shutdown handle.
pub async fn start_server(
    state: LocalState,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let addr = {
        let config = state.config.read().await;
        config.listen_addr()
    };

    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {addr}: {e}"))?;

    info!(%addr, "JR Local server starting");

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Server error: {e}");
        }
    });

    Ok(handle)
}

// ── Handlers ──────────────────────────────────────────────────────────

/// GET /health — basic health check.
#[tracing::instrument(skip(state))]
async fn health_handler(State(state): State<LocalState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "connected_peers": state.hub.total_peers(),
    }))
}

/// GET /api/status — detailed server status.
#[tracing::instrument(skip(state))]
async fn status_handler(State(state): State<LocalState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "campaign_name": config.campaign_name,
        "mode": config.mode,
        "peers": state.hub.total_peers(),
        "port": config.port,
        "session_code": config.session_code,
        "setup_complete": config.setup_complete,
    }))
}

/// GET /api/devices — list of connected devices.
#[tracing::instrument(skip(state))]
async fn devices_handler(State(state): State<LocalState>) -> Json<Value> {
    let devices = state.hub.connected_devices();
    Json(json!({
        "devices": devices,
        "count": devices.len(),
    }))
}

/// GET /sync — WebSocket upgrade with session code validation.
#[tracing::instrument(skip(state, ws, query))]
async fn sync_handler(
    State(state): State<LocalState>,
    ws: WebSocketUpgrade,
    Query(query): Query<SyncQuery>,
) -> Response {
    // Validate session code
    let config = state.config.read().await;
    let expected_code = config.session_code.clone(); // clone: need owned string after dropping lock
    drop(config);

    let provided_code = query.code.unwrap_or_default();
    if provided_code != expected_code {
        warn!("Invalid session code attempt");
        return (StatusCode::UNAUTHORIZED, "invalid session code").into_response();
    }

    // Parse or generate device ID
    let device_id = query
        .device
        .as_deref()
        .and_then(|d| Uuid::parse_str(d).ok())
        .map(DeviceId::new)
        .unwrap_or_else(|| DeviceId::new(Uuid::new_v4()));

    let campaign_id = state.campaign_id;
    let hub = state.hub.clone(); // clone: Arc clone for move into async block

    let max_msg_size = 5 * 1024 * 1024; // 5MB
    ws.max_message_size(max_msg_size)
        .on_upgrade(move |socket| handle_local_session(socket, device_id, campaign_id, hub))
}

/// POST /api/shred — secure delete all data.
#[tracing::instrument(skip(state))]
async fn shred_handler(State(state): State<LocalState>) -> Json<Value> {
    // Broadcast shred notification to connected devices
    let shred_msg = serde_json::to_vec(&json!({"type": "shred"})).unwrap_or_default();
    state.hub.broadcast_all(shred_msg).await;

    // Disconnect all peers
    state.hub.disconnect_all();

    // Perform secure delete
    let config = state.config.read().await;
    let data_dir = config.data_dir.clone(); // clone: PathBuf needed after dropping lock
    drop(config);

    if let Err(e) = crate::shred::shred_directory(&data_dir) {
        return Json(json!({
            "status": "error",
            "message": format!("Shred failed: {e}"),
        }));
    }

    // Reset config
    let mut config = state.config.write().await;
    config.campaign_name = String::new();
    config.setup_complete = false;
    config.session_code = LocalConfig::generate_session_code();
    if let Err(e) = config.save() {
        warn!("Failed to save reset config: {e}");
    }

    Json(json!({
        "status": "ok",
        "message": "All data securely deleted",
    }))
}

/// GET /api/export — JSON export of all data including Automerge document blobs.
#[tracing::instrument(skip(state))]
async fn export_handler(State(state): State<LocalState>) -> Json<Value> {
    let config = state.config.read().await;
    let campaign_name = config.campaign_name.clone();
    let mode = serde_json::to_value(&config.mode).unwrap_or(json!("campaign"));
    drop(config);

    // Read all stored document blobs
    let mut documents = json!({});
    match state.blob_store.list_blobs(state.campaign_id).await {
        Ok(names) => {
            for name in &names {
                match state.blob_store.read_blob(state.campaign_id, name).await {
                    Ok(Some(data)) => {
                        documents[name] = json!({
                            "size_bytes": data.len(),
                            "data_base64": base64::engine::general_purpose::STANDARD.encode(&data),
                        });
                    }
                    Ok(None) => {
                        documents[name] = json!({ "size_bytes": 0, "data_base64": "" });
                    }
                    Err(e) => {
                        documents[name] = json!({ "error": format!("{e}") });
                    }
                }
            }
            info!(count = names.len(), "Exported {} documents", names.len());
        }
        Err(e) => {
            warn!("Failed to list blobs for export: {e}");
        }
    }

    // Read audit log if it exists
    let audit_log = {
        let config = state.config.read().await;
        let audit_path = config.data_dir.join("campaigns")
            .join(state.campaign_id.to_string())
            .join("audit/audit.jsonl");
        drop(config);
        match tokio::fs::read_to_string(&audit_path).await {
            Ok(content) => json!(content),
            Err(_) => json!(null),
        }
    };

    Json(json!({
        "campaign_name": campaign_name,
        "mode": mode,
        "campaign_id": state.campaign_id.to_string(),
        "exported_at": chrono_now_iso(),
        "connected_peers": state.hub.total_peers(),
        "documents": documents,
        "audit_log": audit_log,
    }))
}

/// POST /api/migrate — push data to remote server (stub for M-LS-3).
#[tracing::instrument(skip(_state))]
async fn migrate_handler(State(_state): State<LocalState>) -> Json<Value> {
    Json(json!({
        "status": "not_implemented",
        "message": "Migration to remote server will be available in M-LS-3",
    }))
}

/// GET /api/config — get current configuration.
#[tracing::instrument(skip(state))]
async fn get_config_handler(State(state): State<LocalState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "campaign_name": config.campaign_name,
        "mode": config.mode,
        "port": config.port,
        "session_code": config.session_code,
        "setup_complete": config.setup_complete,
    }))
}

/// POST /api/config — update configuration.
#[tracing::instrument(skip(state, body))]
async fn update_config_handler(
    State(state): State<LocalState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut config = state.config.write().await;

    if let Some(name) = body.get("campaign_name").and_then(|v| v.as_str()) {
        config.campaign_name = name.to_string();
    }

    if let Some(mode) = body.get("mode").and_then(|v| v.as_str()) {
        match mode {
            "campaign" => config.mode = crate::config::ServerMode::Campaign,
            "mutual_aid" => config.mode = crate::config::ServerMode::MutualAid,
            _ => {}
        }
    }

    if let Some(true) = body.get("setup_complete").and_then(|v| v.as_bool()) {
        config.setup_complete = true;
    }

    match config.save() {
        Ok(()) => Json(json!({ "status": "ok" })),
        Err(e) => Json(json!({ "status": "error", "message": e })),
    }
}

/// Simple ISO 8601 timestamp without pulling in chrono.
fn chrono_now_iso() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s-since-epoch", now.as_secs())
}

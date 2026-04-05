// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Per-WebSocket-connection session lifecycle.
//!
//! Each session:
//! 1. Authenticates via session code (local trust model)
//! 2. Registers in the `CampaignHub`
//! 3. Splits the WebSocket into send/receive halves
//! 4. Runs two tasks: receive loop (client -> hub) and send loop (hub -> client)
//! 5. On disconnect: deregisters from hub

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use jr_patterns::{CampaignId, DeviceId, UserRole};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::campaign_hub::CampaignHub;
use super::envelope::RelayEnvelope;

/// Idle timeout for WebSocket connections.
/// Connections with no messages for this duration are disconnected.
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

/// Handle a single WebSocket session for JR Local.
///
/// Simplified from sync server: no JWT auth (session code already validated),
/// no rate limiters, no audit log (local trust model).
#[tracing::instrument(skip(socket, hub), fields(%device_id, %campaign_id))]
pub async fn handle_local_session(
    socket: WebSocket,
    device_id: DeviceId,
    campaign_id: CampaignId,
    hub: Arc<CampaignHub>,
) {
    // Register in hub — get a receiver for outbound messages
    let Some(outbound_rx) = hub.register(campaign_id, device_id, UserRole::Operator) else {
        warn!("Device already connected — closing duplicate");
        return;
    };

    debug!("Local WebSocket session started");

    // Split the WebSocket
    let (ws_sender, ws_receiver) = socket.split();

    // Spawn send loop: hub -> client
    let send_task = tokio::spawn(send_loop(ws_sender, outbound_rx));

    // Run receive loop: client -> hub (blocks until client disconnects)
    receive_loop(ws_receiver, campaign_id, device_id, &hub).await;

    // Client disconnected — clean up
    send_task.abort();
    hub.deregister(campaign_id, device_id);

    debug!("Local WebSocket session ended");
}

/// Send loop: forwards messages from the hub channel to the WebSocket.
async fn send_loop(
    mut ws_sender: futures_util::stream::SplitSink<WebSocket, Message>,
    mut outbound_rx: mpsc::Receiver<Message>,
) {
    while let Some(msg) = outbound_rx.recv().await {
        if let Err(e) = ws_sender.send(msg).await {
            debug!("WebSocket send error: {e}");
            break;
        }
    }
}

/// Receive loop: reads messages from the WebSocket and routes them through the hub.
///
/// Disconnects idle clients after [`WS_IDLE_TIMEOUT`].
async fn receive_loop(
    mut ws_receiver: futures_util::stream::SplitStream<WebSocket>,
    campaign_id: CampaignId,
    device_id: DeviceId,
    hub: &CampaignHub,
) {
    loop {
        // Wrap in timeout to disconnect idle clients
        let next = tokio::time::timeout(WS_IDLE_TIMEOUT, ws_receiver.next()).await;

        let result = match next {
            Ok(Some(result)) => result,
            Ok(None) => break, // Stream ended (client disconnected)
            Err(_) => {
                warn!(%device_id, "WebSocket idle timeout — disconnecting");
                break;
            }
        };

        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                debug!("WebSocket receive error: {e}");
                break;
            }
        };

        let data = match msg {
            Message::Binary(data) => Some(data.to_vec()),
            Message::Text(text) => Some(text.as_bytes().to_vec()),
            Message::Close(_) => {
                debug!("WebSocket close frame received");
                break;
            }
            Message::Ping(_) | Message::Pong(_) => None,
        };

        if let Some(data) = data {
            handle_relay_message(data, campaign_id, device_id, hub).await;
        }
    }
}

/// Parse a `RelayEnvelope` from raw bytes and route it through the hub.
///
/// In local mode, no RBAC enforcement — all document types are permitted.
async fn handle_relay_message(
    data: Vec<u8>,
    campaign_id: CampaignId,
    sender_device_id: DeviceId,
    hub: &CampaignHub,
) {
    let envelope: RelayEnvelope = match serde_json::from_slice(&data) {
        Ok(e) => e,
        Err(e) => {
            error!("Invalid RelayEnvelope JSON: {e}");
            return;
        }
    };

    // Route based on targetPeerId
    if let Some(ref target) = envelope.target_peer_id {
        hub.send_to_peer(campaign_id, target, data).await;
    } else {
        hub.broadcast(campaign_id, sender_device_id, data).await;
    }
}

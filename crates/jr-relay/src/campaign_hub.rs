// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Campaign peer registry and message routing.
//!
//! The `CampaignHub` tracks all connected WebSocket sessions grouped by campaign.
//! It routes `RelayEnvelope` messages to the correct peers.

use axum::extract::ws::Message;
use dashmap::DashMap;
use jr_patterns::{CampaignId, DeviceId, UserRole};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Capacity for per-session send channels (AP-010: bounded channels only).
const SESSION_CHANNEL_CAPACITY: usize = 256;

/// A connected peer session.
#[derive(Debug)]
#[allow(dead_code)] // role used in Phase 4 for RBAC logging
pub struct PeerSession {
    /// Device identifier (from JWT).
    pub device_id: DeviceId,
    /// User role (from JWT).
    pub role: UserRole,
    /// Bounded channel for sending messages to this peer's WebSocket.
    pub sender: mpsc::Sender<Message>,
}

/// Central registry of connected peers, grouped by campaign.
///
/// Uses `DashMap` for lock-free concurrent access from multiple WebSocket tasks.
#[derive(Debug, Default)]
pub struct CampaignHub {
    /// Campaign ID -> list of connected peer sessions.
    campaigns: DashMap<CampaignId, Vec<PeerSession>>,
}

impl CampaignHub {
    /// Create a new empty hub.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new peer session for a campaign.
    ///
    /// Returns a receiver for messages to send to this peer's WebSocket,
    /// or `None` if the device already has a connection (1-per-device limit).
    #[tracing::instrument(skip(self), fields(%campaign_id, %device_id, ?role))]
    pub fn register(
        &self,
        campaign_id: CampaignId,
        device_id: DeviceId,
        role: UserRole,
    ) -> Option<mpsc::Receiver<Message>> {
        let mut entry = self.campaigns.entry(campaign_id).or_default();

        // Enforce 1 concurrent connection per device
        if entry.iter().any(|s| s.device_id == device_id) {
            warn!(%device_id, "Device already connected — rejecting duplicate");
            return None;
        }

        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_CAPACITY);

        entry.push(PeerSession {
            device_id,
            role,
            sender: tx,
        });

        debug!(%device_id, peers = entry.len(), "Peer registered");
        Some(rx)
    }

    /// Remove a peer session from a campaign.
    #[tracing::instrument(skip(self))]
    pub fn deregister(&self, campaign_id: CampaignId, device_id: DeviceId) {
        if let Some(mut entry) = self.campaigns.get_mut(&campaign_id) {
            let before = entry.len();
            entry.retain(|s| s.device_id != device_id);
            let after = entry.len();

            if before != after {
                debug!(%device_id, remaining = after, "Peer deregistered");
            }

            // Clean up empty campaigns
            if entry.is_empty() {
                drop(entry);
                self.campaigns.remove(&campaign_id);
            }
        }
    }

    /// Broadcast a message to all peers in a campaign except the sender.
    ///
    /// If a peer's channel is full, the message is dropped for that peer
    /// (AP-010: bounded channels, no unbounded buffering).
    #[tracing::instrument(skip(self, message), fields(msg_len = message.len()))]
    pub async fn broadcast(
        &self,
        campaign_id: CampaignId,
        sender_device_id: DeviceId,
        message: Vec<u8>,
    ) {
        let Some(entry) = self.campaigns.get(&campaign_id) else {
            return;
        };

        let ws_message = Message::Binary(message.into());

        for peer in entry.iter() {
            if peer.device_id == sender_device_id {
                continue; // Don't echo back to sender
            }

            if let Err(_e) = peer.sender.try_send(ws_message.clone()) {
                // clone: each peer gets its own copy of the WS message
                warn!(
                    target_device = %peer.device_id,
                    "Peer channel full — dropping message"
                );
            }
        }
    }

    /// Broadcast a raw WebSocket message to ALL peers in ALL campaigns.
    ///
    /// Used for system-level notifications (e.g., shred broadcast).
    pub async fn broadcast_all(&self, message: Vec<u8>) {
        let ws_message = Message::Binary(message.into());

        for entry in self.campaigns.iter() {
            for peer in entry.value().iter() {
                if let Err(_e) = peer.sender.try_send(ws_message.clone()) {
                    // clone: each peer gets its own copy
                    warn!(
                        target_device = %peer.device_id,
                        "Peer channel full — dropping broadcast_all message"
                    );
                }
            }
        }
    }

    /// Send a message to a specific peer in a campaign.
    ///
    /// Returns `true` if the peer was found and the message was queued.
    #[tracing::instrument(skip(self, message), fields(msg_len = message.len()))]
    pub async fn send_to_peer(
        &self,
        campaign_id: CampaignId,
        target_device_id: &str,
        message: Vec<u8>,
    ) -> bool {
        let Some(entry) = self.campaigns.get(&campaign_id) else {
            return false;
        };

        let ws_message = Message::Binary(message.into());

        for peer in entry.iter() {
            if peer.device_id.to_string() == target_device_id {
                if let Err(_e) = peer.sender.try_send(ws_message) {
                    warn!(
                        target_device = target_device_id,
                        "Peer channel full — dropping targeted message"
                    );
                }
                return true;
            }
        }

        false
    }

    /// Number of connected peers across all campaigns.
    #[must_use]
    pub fn total_peers(&self) -> usize {
        self.campaigns.iter().map(|e| e.value().len()).sum()
    }

    /// Number of connected peers in a specific campaign.
    #[must_use]
    #[allow(dead_code)] // used in tests and Phase 4 admin endpoints
    pub fn campaign_peers(&self, campaign_id: &CampaignId) -> usize {
        self.campaigns
            .get(campaign_id)
            .map(|e| e.len())
            .unwrap_or(0)
    }

    /// List all connected device IDs across all campaigns.
    #[must_use]
    pub fn connected_devices(&self) -> Vec<String> {
        let mut devices = Vec::new();
        for entry in self.campaigns.iter() {
            for peer in entry.value().iter() {
                devices.push(peer.device_id.to_string());
            }
        }
        devices
    }

    /// Disconnect all peers by clearing the registry.
    pub fn disconnect_all(&self) {
        self.campaigns.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn device(n: u128) -> DeviceId {
        DeviceId::new(Uuid::from_u128(n))
    }

    fn campaign(n: u128) -> CampaignId {
        CampaignId::new(Uuid::from_u128(n))
    }

    #[test]
    fn register_returns_receiver() {
        let hub = CampaignHub::new();
        let rx = hub.register(campaign(1), device(1), UserRole::Scout);
        assert!(rx.is_some());
        assert_eq!(hub.total_peers(), 1);
    }

    #[test]
    fn register_rejects_duplicate_device() {
        let hub = CampaignHub::new();
        let _rx1 = hub.register(campaign(1), device(1), UserRole::Scout);
        let rx2 = hub.register(campaign(1), device(1), UserRole::Scout);
        assert!(rx2.is_none(), "Duplicate device should be rejected");
        assert_eq!(hub.total_peers(), 1);
    }

    #[test]
    fn deregister_removes_peer() {
        let hub = CampaignHub::new();
        let _rx = hub.register(campaign(1), device(1), UserRole::Scout);
        assert_eq!(hub.total_peers(), 1);

        hub.deregister(campaign(1), device(1));
        assert_eq!(hub.total_peers(), 0);
    }

    #[tokio::test]
    async fn broadcast_sends_to_others_not_sender() {
        let hub = CampaignHub::new();
        let c = campaign(1);
        let _rx1 = hub.register(c, device(1), UserRole::Scout);
        let mut rx2 = hub.register(c, device(2), UserRole::Operator).unwrap();

        hub.broadcast(c, device(1), b"hello".to_vec()).await;

        let msg = rx2.try_recv().expect("should receive message");
        match msg {
            Message::Binary(data) => assert_eq!(&*data, b"hello"),
            other => panic!("expected Binary, got {other:?}"),
        }
    }
}

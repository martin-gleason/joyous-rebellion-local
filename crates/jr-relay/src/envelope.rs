// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Wire protocol types matching the Swift app's JSON format.
//!
//! **CONTRACT CRITICAL**: These types must serialize to JSON that exactly matches
//! the Swift app's `Codable` output. See the CLAUDE.md wire protocol contract.
//!
//! Source of truth: `joyous_rebellion/JoyousRebellion/Core/Data/Sync/WebSocketTransport.swift`

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A relay envelope sent between the Swift app and the sync server.
///
/// Field names are **camelCase** to match Swift's `Codable` default.
/// The `payload` is base64-encoded to match Swift's `Data` serialization.
///
/// **Critical serde rules:**
/// - `targetPeerId` must serialize as JSON `null` when absent (NOT omitted)
/// - `payload` uses standard base64 (RFC 4648, `+/=`, NOT URL-safe)
/// - Field names are camelCase via `rename_all`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RelayEnvelope {
    /// Target peer ID. `null` for broadcast, a device UUID string for targeted send.
    pub target_peer_id: Option<String>,

    /// Source peer ID (the sender's device UUID).
    pub source_peer_id: String,

    /// Automerge document name (e.g., "contact", "relationship").
    /// Used for RBAC enforcement — the server checks this against the role's allowed documents.
    pub document_name: String,

    /// Opaque encrypted payload. Base64-encoded in JSON (standard alphabet, with padding).
    #[serde(serialize_with = "serialize_base64", deserialize_with = "deserialize_base64")]
    pub payload: Vec<u8>,
}

/// Serialize `Vec<u8>` as a standard base64 string (matching Swift `Data` Codable).
fn serialize_base64<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = BASE64_STANDARD.encode(data);
    serializer.serialize_str(&encoded)
}

/// Deserialize a standard base64 string to `Vec<u8>`.
fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CONTRACT TEST: RelayEnvelope with null targetPeerId.
    #[test]
    fn contract_broadcast_envelope_json() {
        let envelope = RelayEnvelope {
            target_peer_id: None,
            source_peer_id: "ABC-123".to_string(),
            document_name: "contact".to_string(),
            payload: vec![0x01, 0x02, 0x03],
        };

        let json = serde_json::to_string(&envelope).expect("serialize");

        assert_eq!(
            json,
            r#"{"targetPeerId":null,"sourcePeerId":"ABC-123","documentName":"contact","payload":"AQID"}"#
        );
    }

    /// CONTRACT TEST: round-trip serialization preserves all data.
    #[test]
    fn contract_roundtrip() {
        let original = RelayEnvelope {
            target_peer_id: Some("peer-1".to_string()),
            source_peer_id: "peer-2".to_string(),
            document_name: "event".to_string(),
            payload: vec![1, 2, 3, 4, 5, 100, 200, 255],
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RelayEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    /// CONTRACT TEST: null targetPeerId must serialize as JSON null, NOT be omitted.
    #[test]
    fn contract_null_target_not_omitted() {
        let envelope = RelayEnvelope {
            target_peer_id: None,
            source_peer_id: "x".to_string(),
            document_name: "contact".to_string(),
            payload: vec![],
        };

        let json = serde_json::to_string(&envelope).expect("serialize");
        assert!(
            json.contains(r#""targetPeerId":null"#),
            "targetPeerId must be null, not omitted. Got: {json}"
        );
    }
}

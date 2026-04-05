// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)]

//! WebSocket relay subsystem.
//!
//! Routes encrypted `RelayEnvelope` messages between peers in the same campaign.
//! The server never decrypts or interprets the payload — it is opaque bytes.

pub mod campaign_hub;
pub mod envelope;
pub mod session;

pub use campaign_hub::CampaignHub;
pub use envelope::RelayEnvelope;

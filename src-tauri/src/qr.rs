// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! QR code generation for device pairing.
//!
//! Generates a QR code containing the WebSocket connection URL
//! with the session code, encoded as a base64 PNG.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use image::Luma;
use qrcode::QrCode;

/// QR code image dimensions (pixels).
const QR_SIZE: u32 = 256;

/// Generate a base64-encoded PNG QR code for device pairing.
///
/// The QR code encodes: `ws://{local_ip}:{port}/sync?code={session_code}`
///
/// Returns a base64 string suitable for use in an `<img src="data:image/png;base64,...">` tag.
pub fn generate_qr_code(
    local_ip: &str,
    port: u16,
    session_code: &str,
) -> Result<String, String> {
    let url = format!("ws://{local_ip}:{port}/sync?code={session_code}");

    let code = QrCode::new(url.as_bytes())
        .map_err(|e| format!("Failed to create QR code: {e}"))?;

    let image = code.render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(QR_SIZE, QR_SIZE)
        .build();

    // Encode as PNG to bytes
    let mut png_bytes: Vec<u8> = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    image::ImageEncoder::write_image(
        encoder,
        image.as_raw(),
        image.width(),
        image.height(),
        image::ExtendedColorType::L8,
    )
    .map_err(|e| format!("Failed to encode PNG: {e}"))?;

    // Base64 encode
    let b64 = BASE64_STANDARD.encode(&png_bytes);

    Ok(b64)
}

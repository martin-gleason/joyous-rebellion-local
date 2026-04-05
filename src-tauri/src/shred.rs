// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

//! Secure delete implementation.
//!
//! Overwrites each file with random bytes (same size) before deleting.
//! Removes the campaign data directory recursively.

use rand::Rng;
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::debug;

/// Securely shred all files in a directory.
///
/// For each file:
/// 1. Overwrite with random bytes (same size as original)
/// 2. Flush to disk
/// 3. Delete the file
///
/// Then remove the directory tree.
pub fn shred_directory(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }

    // Walk all files and overwrite before deleting
    shred_recursive(dir)?;

    // Remove the directory tree
    fs::remove_dir_all(dir)
        .map_err(|e| format!("Failed to remove directory {}: {e}", dir.display()))?;

    // Recreate the empty data dir so config.save() still works
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to recreate data directory: {e}"))?;

    debug!("Shred complete: {}", dir.display());
    Ok(())
}

/// Recursively overwrite and delete all files in a directory.
fn shred_recursive(dir: &Path) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Failed to read directory {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
        let path = entry.path();

        if path.is_dir() {
            shred_recursive(&path)?;
        } else {
            shred_file(&path)?;
        }
    }

    Ok(())
}

/// Securely overwrite a single file with random bytes, then delete it.
fn shred_file(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to read metadata for {}: {e}", path.display()))?;

    let size = metadata.len() as usize;

    if size > 0 {
        // Overwrite with random bytes
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..size).map(|_| rng.gen()).collect();

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open {} for overwrite: {e}", path.display()))?;

        file.write_all(&random_bytes)
            .map_err(|e| format!("Failed to overwrite {}: {e}", path.display()))?;

        file.flush()
            .map_err(|e| format!("Failed to flush {}: {e}", path.display()))?;
    }

    // Delete the file
    fs::remove_file(path)
        .map_err(|e| format!("Failed to delete {}: {e}", path.display()))?;

    debug!("Shredded: {}", path.display());
    Ok(())
}

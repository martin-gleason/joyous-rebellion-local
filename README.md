# JR Local — Desktop Sync Server

A desktop app that gives campaign organizers a working sync server in 2 minutes. No cloud, no DevOps, no terminal. Download, open, enter a campaign name, start.

**4MB download. 12MB installed. Runs on a 2015 Intel Mac.**

Built with [Tauri 2](https://tauri.app/) (Rust backend + native WebView). The sync server runs inside the app — no child processes, no Docker, no configuration files.

## What It Does

- Runs a local Automerge sync relay on your WiFi network
- iOS and Android devices connect by scanning a QR code
- Encrypted at rest (same standard as the full sync server)
- Campaign mode or Mutual Aid mode
- Keep data between sessions, or Shred (secure delete with random-byte overwrite)
- Export to JSON for backup or migration to the full cloud server

## Screenshots

The web admin UI runs inside a native desktop window:

- **Dashboard:** Server status, connected devices, QR code for pairing
- **Devices:** Live list of connected phones with sync status
- **Settings:** Campaign name, mode, session code
- **Data:** Export and Shred buttons

## Prerequisites

### macOS

```bash
# Xcode Command Line Tools (you probably already have these)
xcode-select --install

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Tauri CLI
cargo install tauri-cli
```

### Windows

```bash
# Install Rust from https://rustup.rs
# Requires MSVC Build Tools (Visual Studio Installer → "Desktop development with C++")

cargo install tauri-cli
```

### Linux

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# System dependencies (Ubuntu/Debian)
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libssl-dev libayatana-appindicator3-dev librsvg2-dev

cargo install tauri-cli
```

## Build

```bash
git clone https://github.com/martin-gleason/joyous-rebellion-local.git
cd joyous-rebellion-local

# Run tests (104 tests)
cargo test --workspace

# Development mode (opens window with hot-reload)
cargo tauri dev

# Production build (creates distributable)
cargo tauri build
```

### Build Output

| Platform | Artifact | Location |
|----------|----------|----------|
| macOS | `JR Local.app` + `.dmg` | `target/release/bundle/dmg/` |
| Windows | `.msi` installer | `target/release/bundle/msi/` |
| Linux | `.AppImage` + `.deb` | `target/release/bundle/appimage/` |

## Usage

### First Launch

1. Open JR Local
2. Enter your campaign or organization name
3. Select mode: **Campaign** or **Mutual Aid**
4. Click **Start**
5. A QR code appears — phones scan this to connect

### Connecting Phones

1. Open Joyous Rebellion on your iPhone or Android
2. Go to Settings → Sync → scan the QR code (or enter the 6-digit session code)
3. Devices sync automatically over your local WiFi

### After the Session

When you close the app, it asks: **Keep** or **Shred**?

- **Keep:** Data stays encrypted on your laptop. Reopen anytime to resume.
- **Shred:** All data is overwritten with random bytes and deleted. Connected devices are notified to clear their cache.

### Migrating to Cloud

When your campaign outgrows local sync:

1. Open Settings → Data → **Connect to Remote Server**
2. Enter the cloud server URL and API key
3. JR Local pushes all data upstream
4. Mobile devices switch to the cloud server automatically

## Architecture

```
┌─────────────────────────────────────────┐
│         JR Local (Tauri Desktop App)     │
│                                          │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │ Rust Backend  │  │ Native WebView  │  │
│  │ (Axum server) │  │ (Admin UI)      │  │
│  │ port 3030     │  │                 │  │
│  └──────┬────────┘  └─────────────────┘  │
│         │                                │
│  ┌──────┴──────────────────────────────┐ │
│  │       Encrypted Local Storage        │ │
│  └──────────────────────────────────────┘ │
└──────────────────┬──────────────────────┘
                   │ Local WiFi
        ┌──────────┼──────────┐
     iPhone     iPhone     Android
```

### Workspace

| Crate | Purpose |
|-------|---------|
| `jr-patterns` | Domain types, RBAC matrix, newtypes |
| `jr-auth` | JWT validation, revocation |
| `jr-storage` | Campaign directory management, blob I/O, audit log |
| `jr-relay` | WebSocket relay: peer registry, session lifecycle, wire protocol |
| `jr-local` (src-tauri) | Tauri app: config, commands, server, shred, QR |

### Reuse

The `jr-patterns`, `jr-auth`, `jr-storage`, and `jr-relay` crates are extracted from the [full sync server](https://github.com/martin-gleason/jr_server_sync). The relay engine — the hardest part — is production-tested code, not a reimplementation.

## API Endpoints

JR Local exposes these on `localhost:3030`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Server status + peer count |
| `/sync` | GET (WebSocket) | Automerge document relay |
| `/api/status` | GET | Campaign name, mode, data size |
| `/api/devices` | GET | Connected device list |
| `/api/config` | GET/POST | Server configuration |
| `/api/export` | GET | JSON export of all data |
| `/api/shred` | POST | Secure delete all data |
| `/api/migrate` | POST | Push data to remote server |

## Security

- **Encrypted at rest:** Same AES-256 standard as the full server
- **Session code auth:** 6-digit code required for WebSocket connections
- **No internet required:** Runs entirely on local network
- **Secure shred:** Random-byte overwrite before file deletion (not just unlink)
- **Localhost binding:** Admin UI only accessible from the local machine

## Hardware Requirements

| | Minimum | Recommended |
|---|---------|-------------|
| **CPU** | Intel Core i3 / Apple Silicon | Any modern processor |
| **RAM** | 4 GB | 8 GB |
| **Disk** | 100 MB free | 1 GB free |
| **OS** | macOS 10.15+ / Windows 10+ / Ubuntu 20.04+ | Latest stable |
| **Network** | WiFi (for device connections) | — |

Tested on a 2015 Intel MacBook Air. The Rust binary uses ~30MB of RAM with 10 connected devices.

## License

AGPL-3.0-or-later. Copyright © 2026 Martin Gleason & Arthur Dennis.

See [LICENSE](../LICENSE) for the full text.

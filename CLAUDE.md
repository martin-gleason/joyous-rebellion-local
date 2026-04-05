# CLAUDE.md — JR Local (Desktop Sync Server)

> Tauri desktop app wrapping the Joyous Rebellion sync server for local-only operation.
> No cloud, no DevOps. Annie downloads, opens, enters a name, and has a working server.

## Build & Run
```bash
cargo tauri dev       # Development with hot-reload
cargo tauri build     # Production build
cargo build --workspace  # Build all crates without Tauri
cargo test --workspace   # Run all tests
```

## Architecture
Tauri 2.x shell with embedded Axum server. Web UI served from src/.
Reuses jr-patterns, jr-auth, jr-storage, jr-relay crates from sync server.
Server binds to 0.0.0.0:3030 for LAN access. Session code auth.

## Workspace Layout
```
crates/
  jr-patterns/       Domain newtypes, typed errors, RBAC matrix (copied from sync server)
  jr-auth/           JWT validation, rate limiting (copied from sync server)
  jr-storage/        Campaign directory management, audit log (copied from sync server)
  jr-relay/          WebSocket relay: peer registry, session lifecycle, wire protocol (extracted from sync server)
src-tauri/           Tauri app: config, commands, server, shred, QR generation
src/                 Web admin UI: HTML, CSS, vanilla JS
```

## Key Differences from Sync Server
- No admin secret required (localhost trust model)
- Session code auth instead of JWT for WebSocket
- No rate limiting or RBAC enforcement (local trust)
- QR code generation for device pairing
- Secure shred (random-byte overwrite before delete)
- Static file serving for web UI

## Coding Conventions
- `#![deny(unsafe_code)]` in all crates
- Never `.unwrap()` outside `#[cfg(test)]`
- Never `.clone()` without a comment explaining why
- All handlers: `#[tracing::instrument]`
- Copyright header on all files

## Wire Protocol Contract
Same as sync server — RelayEnvelope JSON with camelCase fields.
See jr-relay/src/envelope.rs for the contract tests.

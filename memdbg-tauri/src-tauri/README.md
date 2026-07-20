# MemDBG Tauri host

This directory contains the native Rust host that owns the raw TCP socket
to the MemDBG payload running on the console. The React UI lives at the
project root and is served through Tauri's webview.

## Prerequisites

- Rust stable (>= 1.77) — https://rustup.rs/
- System deps per https://tauri.app/start/prerequisites/
- Bun (or npm) for the frontend
- Tauri CLI: `cargo install tauri-cli --version '^2.0' --locked`

## Develop

```bash
bun install            # once
cargo tauri dev        # opens the Tauri window, hot-reloads the webview
```

Under `cargo tauri dev` the frontend detects `window.__TAURI_INTERNALS__`
and routes MDBG traffic through the native TCP pipe. The WebSocket bridge
(`bridge/`) is only used when the same UI is opened from a regular browser.

## Build

```bash
cargo tauri build
```

Output lands in `src-tauri/target/release/bundle/` (per-platform:
`.dmg`/`.app`, `.msi`/`.exe`, `.AppImage`/`.deb`).

## Wire contract

The host exposes three Tauri commands and two events. Framing, HELLO
handshake and protocol semantics stay in TypeScript (`src/lib/protocol/`);
the Rust side is a dumb byte-pipe over TCP.

- `invoke("mdbg_tcp_open",  { host, port })`
- `invoke("mdbg_tcp_send",  { bytes: number[] })`
- `invoke("mdbg_tcp_close", { reason?: string })`
- `listen<number[]>("mdbg://data",  ...)` — inbound chunks
- `listen<string>("mdbg://close",  ...)` — remote/local close

Later iterations will layer typed commands on top (debugger poll, tracer
streaming, kernel-log UDP forwarder).

## Icons

Provide platform icons under `src-tauri/icons/`. Generate from the MemDBG
logo with:

```bash
cargo tauri icon ../src/assets/memdbg-logo.png
```

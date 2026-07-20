//! MemDBG Tauri host.
//!
//! Owns the raw TCP socket to the console MDBG payload and exposes a small
//! set of commands to the React front-end. Framing, HELLO handshake and
//! protocol semantics stay in JS for now (see `src/lib/protocol/`); this
//! module is a dumb byte-pipe with reconnection-safe state.
//!
//! Commands:
//!   - `mdbg_tcp_open  { host, port }`  → open TCP, start pump task
//!   - `mdbg_tcp_send  { bytes }`       → write bytes to the socket
//!   - `mdbg_tcp_close { reason }`      → close and reset state
//!
//! Events:
//!   - `mdbg://data`  payload: `Vec<u8>` (chunks as read from the socket)
//!   - `mdbg://close` payload: `String` (reason)
//!
//! Later iterations will layer typed commands (debugger poll, tracer,
//! kernel log via the udp_log_port) on top of this transport.

mod mdbg;

use tauri::Manager;

pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,memdbg=debug")),
        )
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            app.manage(mdbg::TcpPipe::new());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            mdbg::mdbg_tcp_open,
            mdbg::mdbg_tcp_send,
            mdbg::mdbg_tcp_close,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

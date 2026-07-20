//! MDBG TCP byte-pipe. See lib.rs for the wire contract.

use parking_lot::Mutex;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// One outbound message. The pump task writes it to the socket in order.
enum Outbound {
    Bytes(Vec<u8>),
    Close(String),
}

pub struct TcpPipe {
    inner: Arc<Mutex<Option<Handle>>>,
}

struct Handle {
    tx: mpsc::UnboundedSender<Outbound>,
    host: String,
    port: u16,
}

impl Default for TcpPipe {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpPipe {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PipeError {
    #[error("already connected to {0}:{1}")]
    AlreadyConnected(String, u16),
    #[error("not connected")]
    NotConnected,
    #[error("tcp: {0}")]
    Io(#[from] std::io::Error),
}

impl serde::Serialize for PipeError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[tauri::command]
pub async fn mdbg_tcp_open(
    app: AppHandle,
    state: State<'_, TcpPipe>,
    host: String,
    port: u16,
) -> Result<(), PipeError> {
    // Reject if already active — the JS side calls `close` before reopen.
    {
        let guard = state.inner.lock();
        if let Some(h) = guard.as_ref() {
            return Err(PipeError::AlreadyConnected(h.host.clone(), h.port));
        }
    }

    tracing::info!(host = %host, port, "mdbg_tcp_open");
    let stream = TcpStream::connect((host.as_str(), port)).await?;
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();

    let (tx, mut rx) = mpsc::unbounded_channel::<Outbound>();
    {
        let mut guard = state.inner.lock();
        *guard = Some(Handle {
            tx: tx.clone(),
            host: host.clone(),
            port,
        });
    }

    // Reader task: pump bytes → JS event.
    let app_read = app.clone();
    let inner_read = state.inner.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = app_read.emit("mdbg://close", "eof".to_string());
                    inner_read.lock().take();
                    break;
                }
                Ok(n) => {
                    let chunk = buf[..n].to_vec();
                    if let Err(e) = app_read.emit("mdbg://data", chunk) {
                        tracing::warn!("emit failed: {e}");
                    }
                }
                Err(e) => {
                    let _ = app_read.emit("mdbg://close", format!("read error: {e}"));
                    inner_read.lock().take();
                    break;
                }
            }
        }
    });

    // Writer task: consume outbound queue.
    let app_write = app.clone();
    let inner_write = state.inner.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                Outbound::Bytes(bytes) => {
                    if let Err(e) = wr.write_all(&bytes).await {
                        let _ = app_write.emit("mdbg://close", format!("write error: {e}"));
                        break;
                    }
                }
                Outbound::Close(reason) => {
                    let _ = wr.shutdown().await;
                    let _ = app_write.emit("mdbg://close", reason);
                    break;
                }
            }
        }
        inner_write.lock().take();
    });

    Ok(())
}

#[tauri::command]
pub fn mdbg_tcp_send(state: State<'_, TcpPipe>, bytes: Vec<u8>) -> Result<(), PipeError> {
    let guard = state.inner.lock();
    let h = guard.as_ref().ok_or(PipeError::NotConnected)?;
    h.tx.send(Outbound::Bytes(bytes))
        .map_err(|_| PipeError::NotConnected)?;
    Ok(())
}

#[tauri::command]
pub fn mdbg_tcp_close(state: State<'_, TcpPipe>, reason: Option<String>) -> Result<(), PipeError> {
    let mut guard = state.inner.lock();
    if let Some(h) = guard.take() {
        let _ = h
            .tx
            .send(Outbound::Close(reason.unwrap_or_else(|| "user".into())));
    }
    Ok(())
}

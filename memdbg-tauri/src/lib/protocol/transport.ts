/**
 * Transport — abstract byte-pipe to the MemDBG payload on the console.
 *
 * Two implementations:
 *   - WsTransport    → browser dev mode via the local WebSocket-to-TCP bridge.
 *   - TauriTransport → desktop build (Tauri host owns the raw TCP socket).
 *
 * The transport is a raw pipe. Framing, HELLO handshake, correlation and
 * LZ4 unwrap all live in {@link MdbgClient}; the transport only moves bytes.
 */

export type DataHandler = (chunk: Uint8Array) => void;
export type CloseHandler = (reason: string) => void;

export interface OpenOptions {
  /** Console IP / hostname running the MDBG payload. */
  host: string;
  /** MDBG listen port (default 9020). */
  port: number;
  /** Bridge URL — only used by {@link WsTransport}. */
  bridgeUrl?: string;
}

export interface Transport {
  /** Open the pipe. Rejects if the underlying socket cannot connect. */
  open(opts: OpenOptions): Promise<void>;
  /** Send bytes to the console. Idempotent no-op when already closed. */
  send(bytes: Uint8Array): void;
  /** Close the pipe. */
  close(reason?: string): void;
  /** Subscribe to inbound bytes. */
  onData(fn: DataHandler): () => void;
  /** Subscribe to remote/local close events. */
  onClose(fn: CloseHandler): () => void;
  /** True when the socket is open. */
  isOpen(): boolean;
  /** Human-readable transport name (for logs / UI). */
  readonly kind: "ws" | "tauri";
}

// ─── Detection ───────────────────────────────────────────────────────────
export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") return false;
  const w = window as unknown as Record<string, unknown>;
  return "__TAURI_INTERNALS__" in w || "__TAURI__" in w;
}

export function isBrowserRuntime(): boolean {
  return typeof window !== "undefined" && !isTauriRuntime();
}

/**
 * Transport selection preference.
 *   - "auto"   → environment-aware chain: Tauri TCP first when available,
 *                fall back to WebSocket bridge if the direct socket fails
 *                or the runtime cannot open one (plain browser preview).
 *   - "tauri"  → force direct TCP via the Rust host (Tauri build only).
 *   - "ws"     → force WebSocket bridge (dev / browser preview).
 */
export type TransportPreference = "auto" | "tauri" | "ws";

export function pickTransport(pref: TransportPreference = "auto"): Transport {
  if (pref === "tauri") return new TauriTransport();
  if (pref === "ws") return new WsTransport();
  // auto
  if (isTauriRuntime()) return new AutoTransport(["tauri", "ws"]);
  return new AutoTransport(["ws"]);
}


// ─── WebSocket bridge transport (dev / browser build) ────────────────────
export class WsTransport implements Transport {
  readonly kind = "ws" as const;
  private ws: WebSocket | null = null;
  private dataHandlers = new Set<DataHandler>();
  private closeHandlers = new Set<CloseHandler>();

  open(opts: OpenOptions): Promise<void> {
    const bridgeUrl = opts.bridgeUrl?.trim() || "ws://localhost:9021";
    const url = buildBridgeUrl(bridgeUrl, opts.host, opts.port);
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      this.ws = ws;
      const to = setTimeout(() => reject(new Error("bridge connect timeout")), 5000);
      ws.onopen = () => {
        clearTimeout(to);
        ws.onmessage = (evt) => {
          if (evt.data instanceof ArrayBuffer) {
            const bytes = new Uint8Array(evt.data);
            for (const h of this.dataHandlers) h(bytes);
          }
        };
        ws.onclose = (evt) => this.fireClose(evt.reason || `ws close ${evt.code}`);
        ws.onerror = () => {
          /* surfaced via close */
        };
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(to);
        reject(new Error("bridge websocket error"));
      };
    });
  }

  send(bytes: Uint8Array) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    // Copy into a fresh ArrayBuffer to satisfy structured-clone semantics.
    const ab = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
    this.ws.send(ab);
  }

  close(reason = "user") {
    if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
      try {
        this.ws.close();
      } catch {
        /* ignore */
      }
    }
    this.ws = null;
    this.fireClose(reason);
  }

  onData(fn: DataHandler) {
    this.dataHandlers.add(fn);
    return () => this.dataHandlers.delete(fn);
  }
  onClose(fn: CloseHandler) {
    this.closeHandlers.add(fn);
    return () => this.closeHandlers.delete(fn);
  }
  isOpen() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private fireClose(reason: string) {
    for (const h of this.closeHandlers) h(reason);
  }
}

function buildBridgeUrl(bridge: string, host: string, port: number): string {
  const base = bridge.replace(/\/+$/, "");
  const sep = base.includes("?") ? "&" : "?";
  return `${base}/mdbg${sep}host=${encodeURIComponent(host)}&port=${port}`;
}

// ─── Tauri transport (desktop build) ─────────────────────────────────────
/**
 * The Rust host owns the TCP socket. This class marshals bytes through
 * three commands and one event:
 *
 *   invoke("mdbg_tcp_open", { host, port })
 *   invoke("mdbg_tcp_send", { bytes })   // bytes = Vec<u8> (Tauri v2 handles Uint8Array)
 *   invoke("mdbg_tcp_close", { reason })
 *   listen<number[]>("mdbg://data", (evt) => …)
 *   listen<string>("mdbg://close", (evt) => …)
 *
 * Framing is done entirely on the JS side (see MdbgClient / MdbgFramer),
 * which keeps the Rust surface as a dumb byte pipe for now. Streaming
 * commands (debugger poll, tracer, klog) will layer on top via dedicated
 * Tauri events in later iterations.
 */
export class TauriTransport implements Transport {
  readonly kind = "tauri" as const;
  private opened = false;
  private dataHandlers = new Set<DataHandler>();
  private closeHandlers = new Set<CloseHandler>();
  private unlistenData: (() => void) | null = null;
  private unlistenClose: (() => void) | null = null;

  async open(opts: OpenOptions): Promise<void> {
    const { invoke } = await import("@tauri-apps/api/core");
    const { listen } = await import("@tauri-apps/api/event");

    this.unlistenData = await listen<number[]>("mdbg://data", (evt) => {
      const bytes = Uint8Array.from(evt.payload);
      for (const h of this.dataHandlers) h(bytes);
    });
    this.unlistenClose = await listen<string>("mdbg://close", (evt) => {
      this.fireClose(evt.payload || "remote closed");
    });

    try {
      await invoke("mdbg_tcp_open", { host: opts.host, port: opts.port });
      this.opened = true;
    } catch (e) {
      this.detachListeners();
      throw new Error(
        `tauri connect failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  send(bytes: Uint8Array) {
    if (!this.opened) return;
    // Fire-and-forget — errors surface via the close event.
    void import("@tauri-apps/api/core").then(({ invoke }) =>
      invoke("mdbg_tcp_send", { bytes: Array.from(bytes) }).catch((e) => {
        this.fireClose(`send failed: ${e instanceof Error ? e.message : String(e)}`);
      }),
    );
  }

  close(reason = "user") {
    if (!this.opened) {
      this.detachListeners();
      return;
    }
    this.opened = false;
    void import("@tauri-apps/api/core").then(({ invoke }) =>
      invoke("mdbg_tcp_close", { reason }).catch(() => {
        /* ignore */
      }),
    );
    this.detachListeners();
    this.fireClose(reason);
  }

  onData(fn: DataHandler) {
    this.dataHandlers.add(fn);
    return () => this.dataHandlers.delete(fn);
  }
  onClose(fn: CloseHandler) {
    this.closeHandlers.add(fn);
    return () => this.closeHandlers.delete(fn);
  }
  isOpen() {
    return this.opened;
  }

  private fireClose(reason: string) {
    for (const h of this.closeHandlers) h(reason);
  }
  private detachListeners() {
    try {
      this.unlistenData?.();
    } catch {
      /* ignore */
    }
    try {
      this.unlistenClose?.();
    } catch {
      /* ignore */
    }
    this.unlistenData = null;
    this.unlistenClose = null;
  }
}

// ─── Auto transport (chained fallback) ───────────────────────────────────
/**
 * Tries a chain of transports in order. The first one whose `open()` resolves
 * wins and becomes the active pipe. Any transport that fails to open is
 * discarded and the next candidate is attempted. The subscribers registered
 * on the AutoTransport are forwarded to the winning inner transport.
 *
 * This is what lets the app run unchanged in three environments:
 *   - Tauri desktop  → tries direct TCP, falls back to bridge if the Rust
 *                      host cannot reach the target (network policy, VPN, …).
 *   - Browser preview → only ws is viable, so the chain has a single link.
 *   - CI / headless  → same as browser.
 */
export class AutoTransport implements Transport {
  readonly kind = "ws" as const; // reported kind is patched after open()
  private inner: Transport | null = null;
  private dataHandlers = new Set<DataHandler>();
  private closeHandlers = new Set<CloseHandler>();

  constructor(private readonly chain: Array<"tauri" | "ws">) {}

  async open(opts: OpenOptions): Promise<void> {
    const errors: string[] = [];
    for (const kind of this.chain) {
      const candidate: Transport = kind === "tauri" ? new TauriTransport() : new WsTransport();
      try {
        await candidate.open(opts);
        // Wire subscribers through to the winner.
        for (const h of this.dataHandlers) candidate.onData(h);
        for (const h of this.closeHandlers) candidate.onClose(h);
        this.inner = candidate;
        // Reflect the winning kind for logs / UI. `kind` is declared readonly
        // for consumers but we own the instance so a controlled patch is fine.
        (this as { kind: "ws" | "tauri" }).kind = candidate.kind;
        return;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        errors.push(`${kind}: ${msg}`);
        try {
          candidate.close("auto-fallback");
        } catch {
          /* ignore */
        }
      }
    }
    throw new Error(`no transport reachable — ${errors.join(" | ")}`);
  }

  send(bytes: Uint8Array) {
    this.inner?.send(bytes);
  }
  close(reason = "user") {
    this.inner?.close(reason);
    this.inner = null;
  }
  onData(fn: DataHandler) {
    this.dataHandlers.add(fn);
    const off = this.inner?.onData(fn);
    return () => {
      this.dataHandlers.delete(fn);
      off?.();
    };
  }
  onClose(fn: CloseHandler) {
    this.closeHandlers.add(fn);
    const off = this.inner?.onClose(fn);
    return () => {
      this.closeHandlers.delete(fn);
      off?.();
    };
  }
  isOpen() {
    return this.inner?.isOpen() ?? false;
  }
}

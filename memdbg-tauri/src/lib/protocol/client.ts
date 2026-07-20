/**
 * MdbgClient — MemDBG protocol client over an abstract byte-pipe transport.
 *
 * Two transports are supported:
 *   - Tauri desktop build (default when `window.__TAURI_INTERNALS__` exists):
 *     the Rust host opens the TCP socket to the console directly.
 *   - Local WebSocket-to-TCP bridge (browser dev mode): see `bridge/README.md`.
 *
 * The transport moves raw bytes. This client owns: HELLO handshake,
 * request/response correlation, timeouts, reconnection state signalling.
 */
import {
  BodyReader,
  BodyWriter,
  MdbgFramer,
  encodeRequest,
  unwrapCompressed,
} from "./codec";
import {
  Cmd,
  type CmdId,
  FRAMED_RESPONSE_COMMANDS,
  HELLO_REQUEST_SIZE,
  MDBG_HELLO_IDENTITY_VERSION,
  MDBG_HELLO_MAGIC,
  MDBG_PROTOCOL_VERSION,
  Role,
  type RoleId,
  Status,
  statusName,
  hasCap as capHas,
} from "./constants";
import { pickTransport, type Transport } from "./transport";


export type ConnState =
  | { kind: "idle" }
  | { kind: "connecting"; host: string; port: number }
  | { kind: "handshaking"; host: string; port: number }
  | { kind: "online"; host: string; port: number; hello: HelloInfo }
  | { kind: "error"; message: string }
  | { kind: "closed"; reason: string };

export interface HelloInfo {
  protocolVersion: number;
  platformId: number;
  capabilities: number;
  debugPort: number;
  udpLogPort: number;
  version: string;
  name: string;
  /** Feature level negotiated by daemon (wire v2 appends this + instance fields). */
  featureLevel: number;
  /** Random ID generated at payload startup; survives rest-mode cycles. */
  daemonInstanceId: bigint;
  /** Monotonic clock at payload startup. */
  daemonStartMonotonicNs: bigint;
  /** Extended capability words (fetched post-HELLO via GET_EXTENDED_CAPS). */
  extendedCaps: number[];
}


export interface ConnectOptions {
  /** Only consumed by the WebSocket bridge transport. */
  bridgeUrl?: string;
  host: string;
  port: number;
  role?: RoleId;
  sessionId?: bigint;
}

type Pending = {
  command: CmdId;
  resolve: (value: { status: number; body: Uint8Array }) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

export type StateListener = (s: ConnState) => void;
export type EventListener = (evt: { kind: string; detail?: unknown }) => void;

const DEFAULT_TIMEOUT_MS = 8000;

export class MdbgClient {
  private transport: Transport | null = null;
  private framer = new MdbgFramer();
  private pending = new Map<number, Pending>();
  private nextReqId = 1;
  private state: ConnState = { kind: "idle" };
  private stateListeners = new Set<StateListener>();
  private eventListeners = new Set<EventListener>();
  private unsubData: (() => void) | null = null;
  private unsubClose: (() => void) | null = null;

  onState(fn: StateListener): () => void {
    this.stateListeners.add(fn);
    fn(this.state);
    return () => this.stateListeners.delete(fn);
  }
  onEvent(fn: EventListener): () => void {
    this.eventListeners.add(fn);
    return () => this.eventListeners.delete(fn);
  }

  getState(): ConnState {
    return this.state;
  }
  getTransportKind(): "ws" | "tauri" | null {
    return this.transport?.kind ?? null;
  }

  private setState(s: ConnState) {
    this.state = s;
    for (const l of this.stateListeners) l(s);
  }
  private emit(kind: string, detail?: unknown) {
    for (const l of this.eventListeners) l({ kind, detail });
  }

  async connect(opts: ConnectOptions): Promise<HelloInfo> {
    this.disconnect("reconnecting");

    const transport = pickTransport();
    this.transport = transport;
    this.setState({ kind: "connecting", host: opts.host, port: opts.port });

    try {
      await transport.open({
        host: opts.host,
        port: opts.port,
        bridgeUrl: opts.bridgeUrl,
      });
    } catch (e) {
      this.transport = null;
      const message = e instanceof Error ? e.message : String(e);
      this.setState({ kind: "error", message });
      throw e;
    }

    this.unsubData = transport.onData((chunk) => this.onData(chunk));
    this.unsubClose = transport.onClose((reason) => this.onTransportClose(reason));

    this.setState({ kind: "handshaking", host: opts.host, port: opts.port });
    try {
      const hello = await this.doHello(opts.role ?? Role.CONTROL, opts.sessionId ?? 0n);
      this.setState({ kind: "online", host: opts.host, port: opts.port, hello });
      return hello;
    } catch (e) {
      this.disconnect(`handshake: ${e instanceof Error ? e.message : String(e)}`);
      throw e;
    }
  }

  disconnect(reason = "user") {
    // Best-effort orderly shutdown (spec §4.4): send GOODBYE before the
    // socket is torn down. Non-blocking — ignore any failure.
    if (this.transport?.isOpen() && this.state.kind === "online") {
      try {
        const reqId = this.nextReqId++;
        const packet = encodeRequest(Cmd.GOODBYE, reqId, new Uint8Array(0));
        this.transport.send(packet);
      } catch { /* ignore */ }
    }
    try { this.unsubData?.(); } catch { /* ignore */ }
    try { this.unsubClose?.(); } catch { /* ignore */ }
    this.unsubData = null;
    this.unsubClose = null;

    if (this.transport) {
      try { this.transport.close(reason); } catch { /* ignore */ }
      this.transport = null;
    }
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error(`disconnected: ${reason}`));
    }
    this.pending.clear();
    this.framer = new MdbgFramer();
    if (this.state.kind !== "idle") {
      this.setState({ kind: "closed", reason });
    }
  }


  isOnline(): boolean {
    return this.state.kind === "online" && !!this.transport?.isOpen();
  }

  /** Send a raw MDBG request and await its response. */
  send(
    command: CmdId,
    body: Uint8Array,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<{ status: number; body: Uint8Array }> {
    if (!this.transport || !this.transport.isOpen()) {
      return Promise.reject(new Error("not connected"));
    }
    const reqId = this.nextReqId++;
    if (this.nextReqId > 0x7fffffff) this.nextReqId = 1;
    const packet = encodeRequest(command, reqId, body);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(reqId);
        reject(new Error(`request 0x${command.toString(16)} timed out`));
      }, timeoutMs);
      this.pending.set(reqId, { command, resolve, reject, timer });
      try {
        this.transport!.send(packet);
      } catch (e) {
        this.pending.delete(reqId);
        clearTimeout(timer);
        reject(e as Error);
      }
    });
  }

  /** Send + reject on non-zero status. */
  async call(command: CmdId, body: Uint8Array, timeoutMs?: number): Promise<Uint8Array> {
    const res = await this.send(command, body, timeoutMs);
    if (res.status !== Status.OK) {
      throw new MdbgStatusError(command, res.status);
    }
    return res.body;
  }

  private async doHello(role: RoleId, sessionId: bigint): Promise<HelloInfo> {
    const w = new BodyWriter()
      .u32(MDBG_HELLO_MAGIC)
      .u16(MDBG_HELLO_IDENTITY_VERSION)
      .u16(role)
      .u64(sessionId);
    const body = w.finish();
    if (body.length !== HELLO_REQUEST_SIZE) {
      throw new Error(`hello body size mismatch (${body.length})`);
    }
    const res = await this.send(Cmd.HELLO, body, 6000);
    if (res.status !== Status.OK) {
      throw new MdbgStatusError(Cmd.HELLO, res.status);
    }
    const r = new BodyReader(res.body);
    const hello: HelloInfo = {
      protocolVersion: r.u16(),
      platformId: r.u16(),
      capabilities: r.u32(),
      debugPort: r.u16(),
      udpLogPort: r.u16(),
      version: r.cstring(16),
      name: r.cstring(16),
      featureLevel: r.u16(),
      daemonInstanceId: 0n,
      daemonStartMonotonicNs: 0n,
      extendedCaps: [],
    };
    r.skip(2); // reserved
    hello.daemonInstanceId = r.u64();
    hello.daemonStartMonotonicNs = r.u64();
    if (hello.protocolVersion !== MDBG_PROTOCOL_VERSION) {
      this.emit("protocol_mismatch", hello);
    }
    // Best-effort fetch of extended caps (feature level 2). Ignore errors —
    // older daemons don't implement 0x0D03 and will answer ERR_UNSUPPORTED.
    try {
      const ecRes = await this.send(Cmd.GET_EXTENDED_CAPS, new Uint8Array(0), 3000);
      if (ecRes.status === Status.OK && ecRes.body.length >= 4) {
        const er = new BodyReader(ecRes.body);
        const count = er.u32();
        for (let i = 0; i < count && er.remaining >= 4; i++) {
          hello.extendedCaps.push(er.u32());
        }
      }
    } catch { /* older daemons */ }
    return hello;
  }

  /** Query the HELLO capability bitmap. */
  hasCap(bit: number): boolean {
    if (this.state.kind !== "online") return false;
    return capHas(this.state.hello.capabilities, bit);
  }
  /** Query an extended-capability bit (word 0 of GET_EXTENDED_CAPS). */
  hasExtCap(bit: number): boolean {
    if (this.state.kind !== "online") return false;
    const words = this.state.hello.extendedCaps;
    return words.length > 0 && ((words[0] & bit) === bit);
  }


  private onData(chunk: Uint8Array) {
    this.framer.push(chunk);
    for (const frame of this.framer.drain()) {
      const p = this.pending.get(frame.header.requestId);
      if (!p) {
        this.emit("packet", frame);
        continue;
      }
      this.pending.delete(frame.header.requestId);
      clearTimeout(p.timer);
      // Only framed-payload commands carry the LZ4/raw prefix. For all
      // other commands the body is raw and must not be reinterpreted.
      let body = frame.body;
      if (frame.header.status === Status.OK && FRAMED_RESPONSE_COMMANDS.has(frame.header.command)) {
        try {
          body = unwrapCompressed(frame.body).raw;
        } catch (e) {
          p.reject(e instanceof Error ? e : new Error(String(e)));
          continue;
        }
      }
      p.resolve({ status: frame.header.status, body });
    }

  }

  private onTransportClose(reason: string) {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error(`transport closed: ${reason}`));
    }
    this.pending.clear();
    if (this.state.kind !== "idle") {
      this.setState({ kind: "closed", reason });
    }
  }
}

export class MdbgStatusError extends Error {
  constructor(
    public command: CmdId,
    public status: number,
  ) {
    super(`mdbg 0x${command.toString(16)} → ${statusName(status)} (${status})`);
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────
let singleton: MdbgClient | null = null;
export function getClient(): MdbgClient {
  if (!singleton) singleton = new MdbgClient();
  return singleton;
}

/**
 * Mock Transport — implements the Transport interface for E2E protocol testing.
 *
 * Captures all sent packets and allows tests to inject responses that are
 * delivered back through the onData handler, simulating a real MDBG daemon.
 */
import type { DataHandler, CloseHandler, OpenOptions, Transport } from "../transport";
import { MDBG_MAGIC, MDBG_PROTOCOL_VERSION, REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE, Status } from "../constants";
import type { CmdId } from "../constants";

/** A captured request sent by the client. */
export interface CapturedRequest {
  /** The raw packet bytes (header + body). */
  raw: Uint8Array;
  /** The decoded command ID. */
  command: CmdId;
  /** The request ID assigned by the client. */
  requestId: number;
  /** The request body (after the 16-byte header). */
  body: Uint8Array;
  /** Timestamp of when the packet was sent. */
  timestamp: number;
}

/** A response to inject back to the client. */
export interface MockResponse {
  /** The request ID to respond to (must match a pending request). */
  requestId: number;
  /** The MDBG status code (0 = OK). */
  status: number;
  /** The response body bytes. */
  body: Uint8Array;
  /** Optional delay in ms before delivering (default 0). */
  delay?: number;
}

/**
 * Creates a properly framed MDBG response packet.
 */
export function makeResponse(
  requestId: number,
  command: CmdId,
  status: number,
  body: Uint8Array,
): Uint8Array {
  const packet = new Uint8Array(RESPONSE_HEADER_SIZE + body.length);
  const dv = new DataView(packet.buffer);
  dv.setUint32(0, MDBG_MAGIC, true);            // magic (0)
  dv.setUint16(4, MDBG_PROTOCOL_VERSION, true); // version (4)
  dv.setUint16(6, command, true);               // command (6)
  dv.setUint32(8, requestId, true);             // request_id (8)
  dv.setInt32(12, status, true);                // status (12)
  dv.setUint32(16, body.length, true);          // length (16)
  packet.set(body, RESPONSE_HEADER_SIZE);       // body at offset 20
  return packet;
}

/**
 * Mock transport that captures outgoing packets and allows
 * injecting responses for fine-grained protocol testing.
 */
export class MockTransport implements Transport {
  readonly kind = "ws" as const;

  private opened = false;
  private dataHandlers = new Set<DataHandler>();
  private closeHandlers = new Set<CloseHandler>();
  private captured: CapturedRequest[] = [];
  private pendingResponses: MockResponse[] = [];

  /** When true, unmatched requests get an automatic ERR_UNSUPPORTED response.
   *  Default false — enable explicitly when needed. */
  autoRespond = false;

  // ─── Transport interface ──────────────────────────────────────────────

  async open(_opts: OpenOptions): Promise<void> {
    this.opened = true;
  }

  send(bytes: Uint8Array): void {
    if (!this.opened) return;
    // Decode the request header for test assertions
    const cmd = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(6, true) as CmdId;
    const reqId = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, true);
    const bodyLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(12, true);
    const body = bytes.subarray(REQUEST_HEADER_SIZE, REQUEST_HEADER_SIZE + bodyLen).slice();

    this.captured.push({
      raw: bytes,
      command: cmd,
      requestId: reqId,
      body,
      timestamp: Date.now(),
    });

    // Deliver any queued responses that match this request, or auto-respond
    // with ERR_UNSUPPORTED if no match (simulates real daemon behavior).
    const matching = this.pendingResponses.filter((r) => r.requestId === reqId);
    if (matching.length > 0) {
      for (const resp of matching) {
        const idx = this.pendingResponses.indexOf(resp);
        if (idx >= 0) this.pendingResponses.splice(idx, 1);
        const packet = makeResponse(reqId, cmd, resp.status, resp.body);
        if (resp.delay && resp.delay > 0) {
          setTimeout(() => this.deliver(packet), resp.delay);
        } else {
          this.deliver(packet);
        }
      }
    } else if (this.autoRespond) {
      // Auto-respond with ERR_UNSUPPORTED for unmatched requests
      const packet = makeResponse(reqId, cmd, Status.ERR_UNSUPPORTED, new Uint8Array(0));
      this.deliver(packet);
    }
  }

  close(reason = "user"): void {
    this.opened = false;
    this.fireClose(reason);
  }

  onData(fn: DataHandler): () => void {
    this.dataHandlers.add(fn);
    return () => this.dataHandlers.delete(fn);
  }

  onClose(fn: CloseHandler): () => void {
    this.closeHandlers.add(fn);
    return () => this.closeHandlers.delete(fn);
  }

  isOpen(): boolean {
    return this.opened;
  }

  // ─── Test helpers ─────────────────────────────────────────────────────

  /** Queue a response to be delivered when the matching request is sent. */
  queueResponse(response: MockResponse): void {
    this.pendingResponses.push(response);
  }

  /** Inject a raw packet directly (bypasses request matching). */
  injectPacket(packet: Uint8Array): void {
    this.deliver(packet);
  }

  /** Get all captured requests in order. */
  getRequests(): ReadonlyArray<CapturedRequest> {
    return this.captured;
  }

  /** Get the most recent captured request, or null. */
  lastRequest(): CapturedRequest | null {
    return this.captured[this.captured.length - 1] ?? null;
  }

  /** Clear all captured requests and queued responses. */
  reset(): void {
    this.captured = [];
    this.pendingResponses = [];
  }

  /** Simulate an unexpected close (e.g. server crash). */
  simulateClose(reason = "connection lost"): void {
    this.opened = false;
    this.fireClose(reason);
  }

  // ─── Internal ─────────────────────────────────────────────────────────

  private deliver(packet: Uint8Array): void {
    for (const h of this.dataHandlers) h(packet);
  }

  private fireClose(reason: string): void {
    for (const h of this.closeHandlers) h(reason);
  }
}

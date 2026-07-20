/**
 * MDBG Kernel Log stream (0x0D02).
 *
 * KLOG_CONNECT opens a TCP port on the daemon for streaming kernel log
 * lines. The response carries the ephemeral port number. The client
 * connects to that port on a separate socket to receive klog entries.
 *
 * Per memdbg_protocol.h:
 *   memdbg_klog_connect_request_t = 4 bytes: reserved(4)
 *   Response: u32 port number
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/**
 * Connect to the kernel log stream. Returns the ephemeral TCP port
 * on which the daemon will stream klog lines.
 */
export async function klogConnect(): Promise<number> {
  const body = new BodyWriter().u32(0).finish(); // reserved
  const res = await getClient().call(Cmd.KLOG_CONNECT, body, 5000);
  return new BodyReader(res).u32();
}

// ─── Compatibility exports for callers ──────────────────────────────────

/** Severity level names for klog entries. */
export function severityName(sev: number): string {
  switch (sev) {
    case 0: return "trace";
    case 1: return "debug";
    case 2: return "info";
    case 3: return "warn";
    case 4: return "error";
    case 5: return "fatal";
    default: return `sev_${sev}`;
  }
}

/** Stub poll — klog streaming uses a separate TCP socket. */
export async function klogPoll(): Promise<KLogLine[]> {
  return [];
}

/** Kernel log line parsed from the klog stream. */
export interface KLogLine {
  timestamp: bigint;
  severity: number;
  tag: string;
  message: string;
  cpu: number;  // CPU core index, default 0
}

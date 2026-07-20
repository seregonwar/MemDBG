/**
 * Admin / auth / arena / telemetry (spec §7.4, §7.8, §12).
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 *   TELEMETRY       0x0400 — server-side counters snapshot
 *   AUTH_KEY        0x0D00 — authenticate with a shared key
 *   ARENA_CONFIG    0x0D01 — configure scratch-arena
 *   SHUTDOWN        0x7F00 — request daemon shutdown
 *   GET_EXTENDED_CAPS 0x0D03 — query extended capability words
 */
import { BodyReader, BodyWriter, TEXT_ENC } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/** memdbg_telemetry_response_t = 60 bytes:
 *  total_bytes_read(8) + total_bytes_written(8) +
 *  total_read_calls(8) + total_write_calls(8) +
 *  uptime_seconds(8) + active_connections(4) +
 *  thread_pool_size(4) + scan_cache_hits(4) +
 *  scan_cache_misses(4) + reserved(4) */
export interface TelemetrySnapshot {
  totalBytesRead: bigint;
  totalBytesWritten: bigint;
  totalReadCalls: bigint;
  totalWriteCalls: bigint;
  uptimeSeconds: bigint;
  activeConnections: number;
  threadPoolSize: number;
  scanCacheHits: number;
  scanCacheMisses: number;
}

export async function telemetry(): Promise<TelemetrySnapshot> {
  const res = await getClient().call(Cmd.TELEMETRY, new Uint8Array(0), 4000);
  const r = new BodyReader(res);
  return {
    totalBytesRead: r.u64(),
    totalBytesWritten: r.u64(),
    totalReadCalls: r.u64(),
    totalWriteCalls: r.u64(),
    uptimeSeconds: r.u64(),
    activeConnections: r.u32(),
    threadPoolSize: r.u32(),
    scanCacheHits: r.u32(),
    scanCacheMisses: r.u32(),
    ...readSkip(4), // reserved
  };
}

/**
 * Authenticate with a pre-shared key.
 * memdbg_auth_key_request_t = 8 bytes: magic(4) + flags(4).
 */
export async function authKey(key: string): Promise<void> {
  const AUTH_KEY_MAGIC = 0x4DE640BB;
  const bytes = TEXT_ENC.encode(key);
  const body = new BodyWriter().u32(AUTH_KEY_MAGIC).u32(0).bytes(bytes).finish();
  await getClient().call(Cmd.AUTH_KEY, body);
}

export interface ArenaConfig {
  /** 0 = disable, 1 = enable */
  enabled: boolean;
}

/** memdbg_arena_config_request_t = 8 bytes: enabled(4) + reserved(4) */
export async function arenaConfig(cfg: ArenaConfig): Promise<void> {
  const body = new BodyWriter().u32(cfg.enabled ? 1 : 0).u32(0).finish();
  await getClient().call(Cmd.ARENA_CONFIG, body);
}

/** Ask the daemon to shut down. Only works after AUTH_KEY on secured builds. */
export async function shutdown(): Promise<void> {
  await getClient().call(Cmd.SHUTDOWN, new Uint8Array(0));
}

/** Fetch extended capability words. Used by MdbgClient.doHello internally;
 *  exposed here for explicit re-queries. */
export async function getExtendedCaps(): Promise<number[]> {
  const res = await getClient().call(Cmd.GET_EXTENDED_CAPS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  const words: number[] = [];
  for (let i = 0; i < count && r.remaining >= 4; i++) words.push(r.u32());
  return words;
}

function readSkip(n: number): Record<string, never> { return {}; }

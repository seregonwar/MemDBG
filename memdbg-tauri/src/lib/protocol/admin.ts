/**
 * Admin / auth / arena / telemetry (spec §7.4, §7.8, §12).
 *   TELEMETRY     0x0400 — server-side counters snapshot
 *   AUTH_KEY      0x0D00 — authenticate with a shared key (challenge/response)
 *   ARENA_CONFIG  0x0D01 — configure scratch-arena size/policy
 *   SHUTDOWN      0x7F00 — request daemon shutdown
 */
import { BodyReader, BodyWriter, TEXT_ENC } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface TelemetrySnapshot {
  rxBytes: bigint;
  txBytes: bigint;
  requests: bigint;
  errors: bigint;
  compressedRatioPct: number;
  scanJobsActive: number;
  uptimeMs: bigint;
}

export async function telemetry(): Promise<TelemetrySnapshot> {
  const res = await getClient().call(Cmd.TELEMETRY, new Uint8Array(0), 4000);
  const r = new BodyReader(res);
  return {
    rxBytes: r.u64(),
    txBytes: r.u64(),
    requests: r.u64(),
    errors: r.u64(),
    compressedRatioPct: r.u32(),
    scanJobsActive: r.u32(),
    uptimeMs: r.u64(),
  };
}

/**
 * Authenticate with a pre-shared key. The daemon replies OK on success or
 * ERR_PERMISSION on failure. `key` is treated as a UTF-8 secret.
 */
export async function authKey(key: string): Promise<void> {
  const bytes = TEXT_ENC.encode(key);
  const body = new BodyWriter().u32(bytes.length).bytes(bytes).finish();
  await getClient().call(Cmd.AUTH_KEY, body);
}

export interface ArenaConfig {
  /** Scratch-arena size in bytes. 0 = keep current. */
  size: bigint;
  /** Policy: 0 = default, 1 = pinned, 2 = huge-pages. */
  policy?: number;
}
export async function arenaConfig(cfg: ArenaConfig): Promise<void> {
  const body = new BodyWriter().u64(cfg.size).u32(cfg.policy ?? 0).u32(0).finish();
  await getClient().call(Cmd.ARENA_CONFIG, body);
}

/** Ask the daemon to shut down. Only works after AUTH_KEY on secured builds. */
export async function shutdown(): Promise<void> {
  await getClient().call(Cmd.SHUTDOWN, new Uint8Array(0));
}

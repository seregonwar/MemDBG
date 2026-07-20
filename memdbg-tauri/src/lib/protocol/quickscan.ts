/**
 * QuickScan / FlashScan family (spec §8) — gated by MEMDBG_EXT_CAP_QUICKSCAN.
 *
 * Wire formats match the canonical C header:
 *   memdbg_quickscan_caps_response_t    = 16 bytes
 *   memdbg_quickscan_start_request_t    = 40 bytes + value + optional data
 *   memdbg_quickscan_count_request_t    = 28 bytes prefix + optional data
 *   memdbg_quickscan_fetch_request_t    = 12 bytes
 *   memdbg_quickscan_config_request_t   = 8 bytes + spill path
 *   memdbg_quickscan_regions_request_t  = 16 bytes
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";
import type { ScanHit } from "./ops";

/** QUICKSCAN_CAPS response: memdbg_quickscan_caps_response_t (16 bytes). */
export interface QuickScanCaps {
  protocolVers: number;
  engineFlags: number;
  maxWorkers: number;
}
export async function quickscanCaps(): Promise<QuickScanCaps> {
  const res = await getClient().call(Cmd.QUICKSCAN_CAPS, new Uint8Array(0));
  const r = new BodyReader(res);
  return {
    protocolVers: r.u32(),
    engineFlags: r.u32(),
    maxWorkers: r.u32(),
    // reserved(u32) — skipped
  };
}

/** QUICKSCAN_CONFIG request: memdbg_quickscan_config_request_t (8 bytes + spill path). */
export async function quickscanConfig(
  ramLimitMb: number,
  spillPath: string = "",
): Promise<void> {
  const spillBytes = new TextEncoder().encode(spillPath);
  const w = new BodyWriter()
    .u32(ramLimitMb)
    .u32(spillBytes.length);
  if (spillBytes.length > 0) w.bytes(spillBytes);
  await getClient().call(Cmd.QUICKSCAN_CONFIG, w.finish());
}

/** QUICKSCAN_REGIONS request: memdbg_quickscan_regions_request_t (16 bytes).
 *  Asks the server to probe up to `regionMax` regions; the server replies
 *  with a stream of memdbg_quickscan_region_info_t entries (32 bytes each). */
export interface QuickScanRegionInfo {
  start: bigint;
  end: bigint;
  protection: number;
  flags: number;
  readMbps: number;
}
export async function quickscanRegions(
  pid: number,
  regionMax: number,
  probeBytes: number,
): Promise<QuickScanRegionInfo[]> {
  const body = new BodyWriter()
    .i32(pid)
    .u32(regionMax)
    .u32(probeBytes)
    .u32(0) // reserved
    .finish();
  const res = await getClient().call(Cmd.QUICKSCAN_REGIONS, body);
  const r = new BodyReader(res);
  const out: QuickScanRegionInfo[] = [];
  while (r.remaining >= 32) {
    out.push({
      start: r.u64(),
      end: r.u64(),
      protection: r.u32(),
      flags: r.u32(),
      readMbps: r.u32(),
      // reserved(u32) — consumed below
    });
    r.skip(4); // reserved
  }
  return out;
}

/**
 * QUICKSCAN_START request: memdbg_quickscan_start_request_t (40 bytes).
 *
 * Response: memdbg_quickscan_resident_header_t (12 bytes: stored + hit_count)
 * followed by scan results.
 */
export interface QuickScanStartResult {
  stored: boolean;
  hitCount: bigint;
  hits: ScanHit[];
}
export async function quickscanStart(
  pid: number,
  valueType: number,
  compareType: number,
  alignment: number,
  value: Uint8Array,
  requestFlags: number = 0,
  address: bigint = 0n,
  length: bigint = 0n,
): Promise<QuickScanStartResult> {
  const w = new BodyWriter()
    .i32(pid)
    .u32(valueType)
    .u32(compareType)
    .u32(alignment)
    .u32(value.length)
    .u32(requestFlags)
    .u64(address)
    .u64(length);
  // Value data — exactly value.length bytes (not padded)
  w.bytes(value);
  // Compare data (between-type): send second copy if compare type differs
  if (compareType !== 0 && compareType !== valueType) {
    w.bytes(value);
  }
  const res = await getClient().call(Cmd.QUICKSCAN_START, w.finish());
  const r = new BodyReader(res);
  const stored = r.u32() !== 0;
  const hitCount = r.u64();
  const hits: ScanHit[] = [];
  while (r.remaining >= 8) {
    const addr = r.u64();
    hits.push({ address: addr, addressHex: addrToHex(addr), value: new Uint8Array(0) });
  }
  return { stored, hitCount, hits };
}

/**
 * QUICKSCAN_COUNT request: memdbg_quickscan_count_request_t (28-byte prefix).
 * Re-count survivors with a possibly different value.
 */
export async function quickscanCount(
  pid: number,
  valueType: number,
  compareType: number,
  valueLength: number,
  requestFlags: number,
  baseAddress: bigint,
): Promise<{ matches: number; done: boolean }> {
  const w = new BodyWriter()
    .i32(pid)
    .u32(valueType)
    .u32(compareType)
    .u32(valueLength)
    .u32(requestFlags)
    .u64(baseAddress);
  const res = await getClient().call(Cmd.QUICKSCAN_COUNT, w.finish());
  const r = new BodyReader(res);
  return { matches: r.u32(), done: r.u32() !== 0 };
}

/**
 * QUICKSCAN_FETCH request: memdbg_quickscan_fetch_request_t (12 bytes).
 */
export async function quickscanFetch(
  startIndex: number,
  count: number,
  flags: number = 0,
  valueSize?: number,
): Promise<ScanHit[]> {
  const body = new BodyWriter()
    .u32(startIndex)
    .u32(count)
    .u32(flags)
    .finish();
  const res = await getClient().call(Cmd.QUICKSCAN_FETCH, body);
  const r = new BodyReader(res);
  const out: ScanHit[] = [];
  while (r.remaining >= 8) {
    const address = r.u64();
    const value = valueSize && r.remaining >= valueSize
      ? r.bytes(valueSize)
      : new Uint8Array(0);
    out.push({ address, addressHex: addrToHex(address), value });
  }
  return out;
}

/** QUICKSCAN_END — release session. */
export async function quickscanEnd(sessionId: number): Promise<void> {
  await getClient().call(Cmd.QUICKSCAN_END, new BodyWriter().u32(sessionId).finish());
}

/** QUICKSCAN_CANCEL — abort in-flight. */
export async function quickscanCancel(sessionId: number): Promise<void> {
  await getClient().call(Cmd.QUICKSCAN_CANCEL, new BodyWriter().u32(sessionId).finish());
}

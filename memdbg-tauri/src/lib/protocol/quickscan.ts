/**
 * QuickScan / FlashScan family (spec §8) — gated by MEMDBG_EXT_CAP_QUICKSCAN.
 *
 * QuickScan is a stateful, region-parallel scanner:
 *   1. QUICKSCAN_CAPS     — feature bitmap
 *   2. QUICKSCAN_CONFIG   — set thread count, chunk size, alignment
 *   3. QUICKSCAN_REGIONS  — declare which regions to include
 *   4. QUICKSCAN_START    — begin (returns session id)
 *   5. QUICKSCAN_COUNT    — poll match count
 *   6. QUICKSCAN_FETCH    — pull match batches
 *   7. QUICKSCAN_END      — release the session
 *   8. QUICKSCAN_CANCEL   — abort in-flight
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, type ValueTypeId } from "./constants";
import { getClient } from "./client";
import type { ScanHit } from "./ops";

export interface QuickScanCaps {
  maxThreads: number;
  maxRegions: number;
  chunkGranularity: number;
  flags: number;
}
export async function quickscanCaps(): Promise<QuickScanCaps> {
  const res = await getClient().call(Cmd.QUICKSCAN_CAPS, new Uint8Array(0));
  const r = new BodyReader(res);
  return {
    maxThreads: r.u32(),
    maxRegions: r.u32(),
    chunkGranularity: r.u32(),
    flags: r.u32(),
  };
}

export interface QuickScanConfig {
  threads: number;
  chunkSize: number;
  alignment: number;
}
export async function quickscanConfig(cfg: QuickScanConfig): Promise<void> {
  const body = new BodyWriter().u32(cfg.threads).u32(cfg.chunkSize).u32(cfg.alignment).u32(0).finish();
  await getClient().call(Cmd.QUICKSCAN_CONFIG, body);
}

export interface QuickScanRegion {
  base: bigint;
  size: bigint;
}
export async function quickscanRegions(pid: number, regions: QuickScanRegion[]): Promise<void> {
  const w = new BodyWriter().u32(pid).u32(regions.length);
  for (const r of regions) w.u64(r.base).u64(r.size);
  await getClient().call(Cmd.QUICKSCAN_REGIONS, w.finish());
}

export async function quickscanStart(
  pid: number,
  type: ValueTypeId,
  value: Uint8Array,
): Promise<{ sessionId: number }> {
  const w = new BodyWriter().u32(pid).u16(type).u16(value.length).bytes(value);
  const res = await getClient().call(Cmd.QUICKSCAN_START, w.finish());
  return { sessionId: new BodyReader(res).u32() };
}

export async function quickscanCount(sessionId: number): Promise<{ matches: number; done: boolean }> {
  const res = await getClient().call(Cmd.QUICKSCAN_COUNT, new BodyWriter().u32(sessionId).finish());
  const r = new BodyReader(res);
  return { matches: r.u32(), done: r.u32() !== 0 };
}

export async function quickscanFetch(
  sessionId: number,
  offset: number,
  max: number,
  valueSize: number,
): Promise<ScanHit[]> {
  const w = new BodyWriter().u32(sessionId).u32(offset).u32(max).u32(0);
  const res = await getClient().call(Cmd.QUICKSCAN_FETCH, w.finish());
  const r = new BodyReader(res);
  const count = r.u32();
  const out: ScanHit[] = [];
  for (let i = 0; i < count; i++) {
    const address = r.u64();
    const value = valueSize > 0 && r.remaining >= valueSize ? r.bytes(valueSize) : new Uint8Array(0);
    out.push({ address, addressHex: addrToHex(address), value });
  }
  return out;
}

export async function quickscanEnd(sessionId: number): Promise<void> {
  await getClient().call(Cmd.QUICKSCAN_END, new BodyWriter().u32(sessionId).finish());
}

export async function quickscanCancel(sessionId: number): Promise<void> {
  await getClient().call(Cmd.QUICKSCAN_CANCEL, new BodyWriter().u32(sessionId).finish());
}

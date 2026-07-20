/**
 * Advanced scanner commands (spec §7.3):
 *   SCAN_EXACT                 0x0300 — range-only exact scan (no pid)
 *   SCAN_POINTER               0x0303 — pointer-chain scan
 *   SCAN_UNKNOWN / _V2         0x0304 / 0x0306 — unknown-initial-value scan
 *   SCAN_PROCESS_EXACT_TRACKED 0x0307 — async tracked-scan job
 *   SCAN_JOB_STATUS            0x0308 — poll a job
 *   SCAN_JOB_CANCEL            0x0309 — cancel a job
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, ValueType, type ValueTypeId } from "./constants";
import { getClient } from "./client";
import type { ScanFilter, ScanHit } from "./ops";

function parseHits(body: Uint8Array, valueSize: number): ScanHit[] {
  const r = new BodyReader(body);
  const count = r.u32();
  const out: ScanHit[] = [];
  for (let i = 0; i < count; i++) {
    const address = r.u64();
    const value = valueSize > 0 && r.remaining >= valueSize ? r.bytes(valueSize) : new Uint8Array(0);
    out.push({ address, addressHex: addrToHex(address), value });
  }
  return out;
}

/** Range-only exact scan (no process attach). */
export async function scanExactRange(
  type: ValueTypeId,
  value: Uint8Array,
  filter: ScanFilter = {},
): Promise<ScanHit[]> {
  const w = new BodyWriter()
    .u16(type).u16(value.length).bytes(value)
    .u64(filter.rangeStart ?? 0n).u64(filter.rangeEnd ?? 0n)
    .u32(filter.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_EXACT, w.finish(), 60000);
  return parseHits(res, value.length);
}

/** Pointer-chain scan. */
export interface PointerScanOptions {
  maxDepth: number;
  maxOffset: number;
  filter?: ScanFilter;
}
export async function scanPointer(
  pid: number,
  target: bigint,
  opts: PointerScanOptions,
): Promise<ScanHit[]> {
  const f = opts.filter ?? {};
  const w = new BodyWriter()
    .u32(pid).u64(target)
    .u32(opts.maxDepth).u32(opts.maxOffset)
    .u64(f.rangeStart ?? 0n).u64(f.rangeEnd ?? 0n)
    .u32(f.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_POINTER, w.finish(), 60000);
  return parseHits(res, 8);
}

/** Unknown-initial-value scan v2 (returns an opaque snapshot handle). */
export async function scanUnknownV2(
  pid: number,
  type: ValueTypeId,
  filter: ScanFilter = {},
): Promise<{ snapshotId: number; matches: number }> {
  const w = new BodyWriter()
    .u32(pid).u16(type).u16(0)
    .u64(filter.rangeStart ?? 0n).u64(filter.rangeEnd ?? 0n)
    .u32(filter.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_UNKNOWN_V2, w.finish(), 60000);
  const r = new BodyReader(res);
  return { snapshotId: r.u32(), matches: r.u32() };
}

// ─── Tracked-scan jobs (spec §7.3.9) ─────────────────────────────────────
export interface ScanJobHandle {
  jobId: number;
}
export interface ScanJobStatus {
  jobId: number;
  state: number;    // 0 pending / 1 running / 2 done / 3 error / 4 cancelled
  progress: number; // 0..100
  matches: number;
  errorCode: number;
}

/** Start a tracked (async) exact scan; returns a job handle. */
export async function scanExactTracked(
  pid: number,
  type: ValueTypeId,
  value: Uint8Array,
  filter: ScanFilter = {},
): Promise<ScanJobHandle> {
  const w = new BodyWriter()
    .u32(pid).u16(type).u16(value.length).bytes(value)
    .u64(filter.rangeStart ?? 0n).u64(filter.rangeEnd ?? 0n)
    .u32(filter.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_PROCESS_EXACT_TRACKED, w.finish());
  return { jobId: new BodyReader(res).u32() };
}

export async function scanJobStatus(jobId: number): Promise<ScanJobStatus> {
  const res = await getClient().call(Cmd.SCAN_JOB_STATUS, new BodyWriter().u32(jobId).finish());
  const r = new BodyReader(res);
  return {
    jobId,
    state: r.u32(),
    progress: r.u32(),
    matches: r.u32(),
    errorCode: r.i32(),
  };
}

export async function scanJobCancel(jobId: number): Promise<void> {
  await getClient().call(Cmd.SCAN_JOB_CANCEL, new BodyWriter().u32(jobId).finish());
}

export { ValueType };

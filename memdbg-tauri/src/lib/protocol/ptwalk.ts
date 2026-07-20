/**
 * Page-table walk family (spec §9) — gated by MEMDBG_EXT_CAP_PTWALK.
 *
 * Wire formats match the canonical C header:
 *   memdbg_ptwalk_discover_response_t = 20 bytes
 *   memdbg_ptwalk_probe_request_t     = 16 bytes
 *   memdbg_ptwalk_probe_response_t    = 32 bytes
 *   memdbg_ptwalk_io_request_t        = 24 bytes
 *   memdbg_ptwalk_augment_request_t   = 8 bytes
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/**
 * PTWALK_DISCOVER (0x0C00) — find page-table root(s) for pid.
 *
 * Response: memdbg_ptwalk_discover_response_t (20 bytes).
 */
export interface PtWalkDiscover {
  status: number;
  dmapBase: bigint;
  pmapOffset: bigint;
}
export async function ptwalkDiscover(pid: number): Promise<PtWalkDiscover> {
  const res = await getClient().call(Cmd.PTWALK_DISCOVER, new BodyWriter().i32(pid).finish());
  const r = new BodyReader(res);
  return {
    status: r.u32(),
    dmapBase: r.u64(),
    pmapOffset: r.u64(),
  };
}

/**
 * PTWALK_PROBE (0x0C04) — resolve VA → PA + prot.
 *
 * Request:  pid(i32) + reserved(u32) + address(u64) = 16 bytes.
 * Response: memdbg_ptwalk_probe_response_t (32 bytes).
 */
export interface PtProbe {
  physAddress: bigint;
  pageSize: bigint;
  pteValue: bigint;
  pageLevel: number;
  cached: boolean;
}
export async function ptwalkProbe(pid: number, virt: bigint): Promise<PtProbe> {
  const body = new BodyWriter().i32(pid).u32(0).u64(virt).finish();
  const res = await getClient().call(Cmd.PTWALK_PROBE, body);
  const r = new BodyReader(res);
  return {
    physAddress: r.u64(),
    pageSize: r.u64(),
    pteValue: r.u64(),
    pageLevel: r.i32(),
    cached: r.u32() !== 0,
  };
}

/**
 * PTWALK_READ (0x0C02) — physical read via pt walk.
 *
 * Request: pid(i32) + reserved(u32) + address(u64) + length(u64) = 24 bytes.
 */
export async function ptwalkRead(pid: number, virt: bigint, length: bigint): Promise<Uint8Array> {
  const body = new BodyWriter().i32(pid).u32(0).u64(virt).u64(length).finish();
  return getClient().call(Cmd.PTWALK_READ, body, 15000);
}

/**
 * PTWALK_WRITE (0x0C03) — physical write via pt walk.
 *
 * Request: pid(i32) + reserved(u32) + address(u64) + length(u64) + data = 24 bytes + data.
 */
export async function ptwalkWrite(pid: number, virt: bigint, data: Uint8Array): Promise<void> {
  const body = new BodyWriter()
    .i32(pid)
    .u32(0)
    .u64(virt)
    .u64(BigInt(data.length))
    .bytes(data)
    .finish();
  await getClient().call(Cmd.PTWALK_WRITE, body);
}

/**
 * PTWALK_AUGMENT (0x0C01) — annotate maps with pte flags.
 *
 * Request: pid(i32) + reserved(u32) = 8 bytes.
 * Response: count-prefixed array of { base, size, pteFlags } entries.
 */
export interface PtAugmentEntry {
  base: bigint;
  size: bigint;
  pteFlags: number;
}
export async function ptwalkAugment(pid: number): Promise<PtAugmentEntry[]> {
  const body = new BodyWriter().i32(pid).u32(0).finish();
  const res = await getClient().call(Cmd.PTWALK_AUGMENT, body);
  const r = new BodyReader(res);
  const out: PtAugmentEntry[] = [];
  while (r.remaining >= 20) {
    out.push({ base: r.u64(), size: r.u64(), pteFlags: r.u32() });
  }
  return out;
}

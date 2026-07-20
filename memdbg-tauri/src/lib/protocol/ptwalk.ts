/**
 * Page-table walk family (spec §9) — gated by MEMDBG_EXT_CAP_PTWALK.
 *
 *   PTWALK_DISCOVER 0x0C00 — find page-table root(s) for pid
 *   PTWALK_AUGMENT  0x0C01 — annotate maps with pte flags
 *   PTWALK_READ     0x0C02 — physical read via pt walk
 *   PTWALK_WRITE    0x0C03 — physical write via pt walk
 *   PTWALK_PROBE    0x0C04 — resolve VA → PA + prot
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface PtWalkRoot {
  pid: number;
  cr3: bigint;
  flags: number;
}
export async function ptwalkDiscover(pid: number): Promise<PtWalkRoot[]> {
  const res = await getClient().call(Cmd.PTWALK_DISCOVER, new BodyWriter().u32(pid).finish());
  const r = new BodyReader(res);
  const count = r.u32();
  const out: PtWalkRoot[] = [];
  for (let i = 0; i < count && r.remaining >= 16; i++) {
    out.push({ pid: r.u32(), cr3: r.u64(), flags: r.u32() });
  }
  return out;
}

export interface PtProbe {
  physical: bigint;
  present: boolean;
  writable: boolean;
  user: boolean;
  nx: boolean;
  pageSize: number;
}
export async function ptwalkProbe(pid: number, virt: bigint): Promise<PtProbe> {
  const body = new BodyWriter().u32(pid).u64(virt).finish();
  const res = await getClient().call(Cmd.PTWALK_PROBE, body);
  const r = new BodyReader(res);
  const physical = r.u64();
  const flags = r.u32();
  const pageSize = r.u32();
  return {
    physical,
    pageSize,
    present:  (flags & 1) !== 0,
    writable: (flags & 2) !== 0,
    user:     (flags & 4) !== 0,
    nx:       (flags & 8) !== 0,
  };
}

export async function ptwalkRead(pid: number, virt: bigint, length: number): Promise<Uint8Array> {
  const body = new BodyWriter().u32(pid).u64(virt).u32(length).u32(0).finish();
  return getClient().call(Cmd.PTWALK_READ, body, 15000);
}

export async function ptwalkWrite(pid: number, virt: bigint, data: Uint8Array): Promise<void> {
  const body = new BodyWriter().u32(pid).u64(virt).u32(data.length).u32(0).bytes(data).finish();
  await getClient().call(Cmd.PTWALK_WRITE, body);
}

export interface PtAugmentEntry {
  base: bigint;
  size: bigint;
  pteFlags: number;
}
export async function ptwalkAugment(pid: number): Promise<PtAugmentEntry[]> {
  const res = await getClient().call(Cmd.PTWALK_AUGMENT, new BodyWriter().u32(pid).finish());
  const r = new BodyReader(res);
  const count = r.u32();
  const out: PtAugmentEntry[] = [];
  for (let i = 0; i < count && r.remaining >= 20; i++) {
    out.push({ base: r.u64(), size: r.u64(), pteFlags: r.u32() });
  }
  return out;
}

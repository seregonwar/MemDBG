/**
 * Memory batch operations (spec §7.2):
 *   BATCH_READ       0x0202  — scatter/gather read with LZ4-framed body
 *   BATCH_WRITE      0x0203  — many (addr,size,data) writes in one round-trip
 *   BATCH_WRITE_ADV  0x0204  — batch write with pre-write protection change
 *
 * Response bodies for BATCH_READ pass through the framed LZ4 unwrap
 * inside {@link MdbgClient.onData} so this module only decodes raw bytes.
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface BatchReadRequest {
  address: bigint;
  size: number;
}
export interface BatchReadResult {
  address: bigint;
  status: number;   // per-slot MDBG status
  data: Uint8Array; // empty on failure
}

export async function batchRead(
  pid: number,
  slots: BatchReadRequest[],
): Promise<BatchReadResult[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length);
  for (const s of slots) w.u64(s.address).u32(s.size).u32(0);
  const res = await getClient().call(Cmd.BATCH_READ, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  const heads: { address: bigint; status: number; size: number }[] = [];
  for (let i = 0; i < count; i++) {
    heads.push({ address: r.u64(), status: r.i32(), size: r.u32() });
  }
  const out: BatchReadResult[] = [];
  for (const h of heads) {
    const data = h.size > 0 && r.remaining >= h.size ? r.bytes(h.size) : new Uint8Array(0);
    out.push({ address: h.address, status: h.status, data });
  }
  return out;
}

export interface BatchWriteSlot {
  address: bigint;
  data: Uint8Array;
}

export async function batchWrite(
  pid: number,
  slots: BatchWriteSlot[],
): Promise<number[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length);
  for (const s of slots) w.u64(s.address).u32(s.data.length).u32(0);
  for (const s of slots) w.bytes(s.data);
  const res = await getClient().call(Cmd.BATCH_WRITE, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: number[] = [];
  for (let i = 0; i < count && r.remaining >= 4; i++) out.push(r.i32());
  return out;
}

export interface BatchWriteAdvSlot extends BatchWriteSlot {
  /** Prot mask to apply before the write (R/W/X). 0 = keep current. */
  prot?: number;
  /** If true, restore the original prot after writing. */
  restoreProt?: boolean;
}

export async function batchWriteAdv(
  pid: number,
  slots: BatchWriteAdvSlot[],
): Promise<number[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length);
  for (const s of slots) {
    w.u64(s.address)
      .u32(s.data.length)
      .u32(s.prot ?? 0)
      .u32(s.restoreProt ? 1 : 0);
  }
  for (const s of slots) w.bytes(s.data);
  const res = await getClient().call(Cmd.BATCH_WRITE_ADV, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: number[] = [];
  for (let i = 0; i < count && r.remaining >= 4; i++) out.push(r.i32());
  return out;
}

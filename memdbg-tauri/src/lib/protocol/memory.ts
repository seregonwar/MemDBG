/**
 * Memory batch operations (spec §7.2):
 *   BATCH_READ       0x0202 — scatter/gather read with LZ4-framed body
 *   BATCH_WRITE      0x0203 — many (addr,size,data) writes in one round-trip
 *   BATCH_WRITE_ADV  0x0204 — batch write with pre-write protection change
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 * Response bodies for BATCH_READ pass through the framed LZ4 unwrap
 * inside MdbgClient.onData so this module only decodes raw bytes.
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/** memdbg_batch_read_item_t = 16 bytes: address(8) + length(4) + reserved(4) */
export interface BatchReadRequest {
  address: bigint;
  size: number;
}

/** memdbg_batch_read_result_entry_t = 16 bytes: address(8) + length(4) + status(4) */
export interface BatchReadResult {
  address: bigint;
  status: number;
  data: Uint8Array;
}

/** memdbg_batch_read_request_t = 12 bytes: pid(4) + count(4) + reserved(4)
 *  followed by count × memdbg_batch_read_item_t entries. */
export async function batchRead(
  pid: number,
  slots: BatchReadRequest[],
): Promise<BatchReadResult[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length).u32(0); // pid + count + reserved
  for (const s of slots) w.u64(s.address).u32(s.size).u32(0); // item: addr + len + reserved
  const res = await getClient().call(Cmd.BATCH_READ, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const heads: { address: bigint; length: number; status: number }[] = [];
  for (let i = 0; i < count; i++) {
    heads.push({ address: r.u64(), length: r.u32(), status: r.i32() });
  }
  const out: BatchReadResult[] = [];
  for (const h of heads) {
    const data = h.length > 0 && r.remaining >= h.length ? r.bytes(h.length) : new Uint8Array(0);
    out.push({ address: h.address, status: h.status, data });
  }
  return out;
}

/** memdbg_batch_write_item_t = 16 bytes header: address(8) + length(4) + reserved(4)
 *  followed by length bytes of inline data. */
export interface BatchWriteSlot {
  address: bigint;
  data: Uint8Array;
}

/** memdbg_batch_write_request_t = 12 bytes: pid(4) + count(4) + reserved(4)
 *  followed by count × memdbg_batch_write_item_t + inline data.
 *  Response: count × memdbg_batch_write_result_entry_t (16B each: address+written+status). */
export async function batchWrite(
  pid: number,
  slots: BatchWriteSlot[],
): Promise<{ address: bigint; written: number; status: number }[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length).u32(0); // pid + count + reserved
  for (const s of slots) w.u64(s.address).u32(s.data.length).u32(0); // item headers
  for (const s of slots) w.bytes(s.data); // inline data
  const res = await getClient().call(Cmd.BATCH_WRITE, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: { address: bigint; written: number; status: number }[] = [];
  for (let i = 0; i < count && r.remaining >= 16; i++) {
    out.push({ address: r.u64(), written: r.u32(), status: r.i32() });
  }
  return out;
}

/** memdbg_batch_write_adv_request_t = 16 bytes: pid(4) + count(4) + flags(4) + reserved(4)
 *  followed by streamed entries: { uint64 address; uint32 length; <length> bytes }.
 *  Response: count × memdbg_batch_write_result_entry_t (16B each). */
export interface BatchWriteAdvSlot extends BatchWriteSlot {
  /** Prot mask to apply before the write (R/W/X). 0 = keep current. */
  prot?: number;
  /** If true, restore the original prot after writing. */
  restoreProt?: boolean;
}

export async function batchWriteAdv(
  pid: number,
  slots: BatchWriteAdvSlot[],
): Promise<{ address: bigint; written: number; status: number }[]> {
  const w = new BodyWriter().u32(pid).u32(slots.length).u32(0).u32(0); // pid + count + flags + reserved
  for (const s of slots) {
    w.u64(s.address).u32(s.data.length);
  }
  for (const s of slots) w.bytes(s.data);
  const res = await getClient().call(Cmd.BATCH_WRITE_ADV, w.finish(), 20000);
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: { address: bigint; written: number; status: number }[] = [];
  for (let i = 0; i < count && r.remaining >= 16; i++) {
    out.push({ address: r.u64(), written: r.u32(), status: r.i32() });
  }
  return out;
}

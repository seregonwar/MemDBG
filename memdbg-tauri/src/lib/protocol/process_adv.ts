/**
 * Advanced process operations (spec §7.1):
 *   PROCESS_STACK     0x010B — capture a thread call-stack
 *   PROCESS_CALL      0x010C — remote function call
 *   PROCESS_ELF_LOAD  0x010D — inject / load an ELF module
 *   PROCESS_HIJACK    0x010E — hijack an existing thread
 *   PROCESS_DUMP      0x010F — dump address range (LZ4-framed body)
 *   PROCESS_MAPS_V2   0x0110 — v2 maps with LZ4-framed body
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, protString } from "./constants";
import { getClient } from "./client";
import type { MemoryRegion } from "./ops";

export interface StackFrame {
  rip: bigint;
  rsp: bigint;
  ripHex: string;
  rspHex: string;
  symbol: string;
  offset: bigint;
}

export async function processStack(pid: number, lwp: number, maxFrames = 64): Promise<StackFrame[]> {
  const body = new BodyWriter().u32(pid).u32(lwp).u32(maxFrames).u32(0).finish();
  const res = await getClient().call(Cmd.PROCESS_STACK, body, 8000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: StackFrame[] = [];
  for (let i = 0; i < count && r.remaining >= 24; i++) {
    const rip = r.u64();
    const rsp = r.u64();
    const offset = r.u64();
    const symbol = r.remaining >= 48 ? r.cstring(48) : "";
    out.push({ rip, rsp, ripHex: addrToHex(rip), rspHex: addrToHex(rsp), symbol, offset });
  }
  return out;
}

export interface RemoteCallResult {
  rax: bigint;
  status: number;
}

export async function processCall(
  pid: number,
  address: bigint,
  args: bigint[] = [],
  timeoutMs = 15000,
): Promise<RemoteCallResult> {
  const w = new BodyWriter().u32(pid).u64(address).u32(args.length).u32(0);
  for (let i = 0; i < 6; i++) w.u64(args[i] ?? 0n);
  const res = await getClient().call(Cmd.PROCESS_CALL, w.finish(), timeoutMs);
  const r = new BodyReader(res);
  return { rax: r.u64(), status: r.remaining >= 4 ? r.i32() : 0 };
}

export async function processElfLoad(pid: number, elf: Uint8Array, entryArg: bigint = 0n): Promise<bigint> {
  const w = new BodyWriter().u32(pid).u64(entryArg).u32(elf.length).u32(0).bytes(elf);
  const res = await getClient().call(Cmd.PROCESS_ELF_LOAD, w.finish(), 30000);
  return new BodyReader(res).u64(); // load base
}

export async function processHijack(pid: number, lwp: number, address: bigint, args: bigint[] = []): Promise<void> {
  const w = new BodyWriter().u32(pid).u32(lwp).u64(address).u32(args.length).u32(0);
  for (let i = 0; i < 6; i++) w.u64(args[i] ?? 0n);
  await getClient().call(Cmd.PROCESS_HIJACK, w.finish(), 15000);
}

/**
 * Dump `size` bytes from `pid` at `address`. Response body is LZ4-framed
 * (unwrapped by the client). Returns the raw bytes.
 */
export async function processDump(pid: number, address: bigint, size: bigint): Promise<Uint8Array> {
  const body = new BodyWriter().u32(pid).u64(address).u64(size).finish();
  return getClient().call(Cmd.PROCESS_DUMP, body, 60000);
}

/**
 * Maps v2 — same shape as legacy MAPS with a couple of extra u32 fields
 * (mapping id + flags), body is LZ4-framed.
 */
export async function listMapsV2(pid: number): Promise<MemoryRegion[]> {
  const body = new BodyWriter().u32(pid).finish();
  const res = await getClient().call(Cmd.PROCESS_MAPS_V2, body, 12000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: MemoryRegion[] = [];
  for (let i = 0; i < count; i++) {
    const base = r.u64();
    const size = r.u64();
    const prot = r.u32();
    r.u32(); // mapping id
    r.u32(); // flags
    r.u32(); // reserved
    const name = r.cstring(64);
    out.push({ base, size, prot, protStr: protString(prot), name, end: base + size });
  }
  return out;
}

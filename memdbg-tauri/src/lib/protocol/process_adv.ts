/**
 * Advanced process operations (spec §7.1):
 *   PROCESS_STACK     0x010B — capture a thread call-stack
 *   PROCESS_CALL      0x010C — remote function call
 *   PROCESS_ELF_LOAD  0x010D — inject / load an ELF module
 *   PROCESS_HIJACK    0x010E — hijack an existing thread
 *   PROCESS_DUMP      0x010F — dump address range (LZ4-framed body)
 *   PROCESS_MAPS_V2   0x0110 — v2 maps with LZ4-framed body
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, protString } from "./constants";
import { getClient } from "./client";
import type { MemoryRegion } from "./ops";

// ─── Stack walk ──────────────────────────────────────────────────────────

/** memdbg_process_stack_frame_t = 56 bytes:
 *  frame_pointer(8) + saved_frame_pointer(8) + return_address(8) +
 *  stack_address(8) + code_address(8) +
 *  stack_size(4) + code_size(4) + stack_data_offset(4) + code_data_offset(4) */
export interface StackFrame {
  framePointer: bigint;
  savedFramePointer: bigint;
  returnAddress: bigint;
  stackAddress: bigint;
  codeAddress: bigint;
  stackSize: number;
  codeSize: number;
  stackDataOffset: number;
  codeDataOffset: number;
  // Derived helpers
  rip: bigint;
  ripHex: string;
  rsp: bigint;
  rspHex: string;
  symbol: string; // not in wire format; set by caller
  offset: bigint; // not in wire format
}

/** memdbg_process_stack_request_t = 40 bytes:
 *  pid(4) + lwp(4) + frame_pointer(8) + stack_pointer(8) +
 *  max_frames(4) + max_bytes_per_frame(4) + code_window(4) + flags(4)
 *
 * Response: memdbg_process_stack_response_prefix_t = 16 bytes:
 *  count(4) + truncated(4) + entry_size(4) + data_size(4)
 *  followed by count × memdbg_process_stack_frame_t + stack/code data blobs */
export async function processStack(
  pid: number, lwp: number,
  maxFrames = 64, maxBytesPerFrame = 512, codeWindow = 200,
): Promise<StackFrame[]> {
  const w = new BodyWriter()
    .u32(pid).u32(lwp)
    .u64(0n).u64(0n) // frame_pointer=0, stack_pointer=0
    .u32(maxFrames).u32(maxBytesPerFrame).u32(codeWindow).u32(0);
  const res = await getClient().call(Cmd.PROCESS_STACK, w.finish(), 8000);
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(12); // truncated + entry_size + data_size
  const out: StackFrame[] = [];
  for (let i = 0; i < count && r.remaining >= 40; i++) {
    const framePointer = r.u64();
    const savedFramePointer = r.u64();
    const returnAddress = r.u64();
    const stackAddress = r.u64();
    const codeAddress = r.u64();
    const stackSize = r.u32();
    const codeSize = r.u32();
    const stackDataOffset = r.u32();
    const codeDataOffset = r.u32();
    out.push({
      framePointer, savedFramePointer, returnAddress,
      stackAddress, codeAddress,
      stackSize, codeSize, stackDataOffset, codeDataOffset,
      rip: returnAddress, ripHex: addrToHex(returnAddress),
      rsp: stackAddress, rspHex: addrToHex(stackAddress),
      symbol: "", offset: 0n,
    });
  }
  return out;
}

// ─── Remote call ─────────────────────────────────────────────────────────

/** memdbg_process_call_request_t = 64 bytes:
 *  pid(4) + reserved(4) + function_address(8) + args[6](48)
 *  Response: memdbg_process_call_response_t = 8 bytes: rax(8) */
export async function processCall(
  pid: number, address: bigint, args: bigint[] = [],
): Promise<bigint> {
  const w = new BodyWriter().u32(pid).u32(0).u64(address);
  for (let i = 0; i < 6; i++) w.u64(args[i] ?? 0n);
  const res = await getClient().call(Cmd.PROCESS_CALL, w.finish(), 15000);
  return new BodyReader(res).u64();
}

// ─── ELF load ────────────────────────────────────────────────────────────

/** memdbg_process_elf_load_request_t = 64 bytes:
 *  pid(4) + flags(4) + image_size(8) + match_flags(4) + target_region[44]
 *  followed by image_size bytes of ELF data.
 *
 *  Response: memdbg_process_elf_load_response_t = 16 bytes:
 *  entry_address(8) + load_base(8) */
export async function processElfLoad(
  pid: number, elf: Uint8Array,
  flags = 0, matchFlags = 0, targetRegion = "",
): Promise<{ entryAddress: bigint; loadBase: bigint }> {
  const regionBytes = new TextEncoder().encode(targetRegion);
  const regionPad = new Uint8Array(44);
  regionPad.set(regionBytes.subarray(0, 44));
  const w = new BodyWriter()
    .u32(pid).u32(flags).u64(BigInt(elf.length)).u32(matchFlags)
    .bytes(regionPad)
    .bytes(elf);
  const res = await getClient().call(Cmd.PROCESS_ELF_LOAD, w.finish(), 30000);
  const r = new BodyReader(res);
  return { entryAddress: r.u64(), loadBase: r.u64() };
}

// ─── Hijack ──────────────────────────────────────────────────────────────

/** memdbg_process_hijack_request_t = 64 bytes:
 *  pid(4) + flags(4) + payload_size(8) + match_flags(4) + target_region[44]
 *  followed by payload_size bytes of ELF data.
 *
 *  Response: memdbg_process_hijack_response_t = 8 bytes: accepted(4) + reserved(4) */
export async function processHijack(
  pid: number, elf: Uint8Array,
  flags = 0, matchFlags = 0, targetRegion = "",
): Promise<boolean> {
  const regionBytes = new TextEncoder().encode(targetRegion);
  const regionPad = new Uint8Array(44);
  regionPad.set(regionBytes.subarray(0, 44));
  const w = new BodyWriter()
    .u32(pid).u32(flags).u64(BigInt(elf.length)).u32(matchFlags)
    .bytes(regionPad)
    .bytes(elf);
  const res = await getClient().call(Cmd.PROCESS_HIJACK, w.finish(), 15000);
  return new BodyReader(res).u32() !== 0;
}

// ─── Process dump ────────────────────────────────────────────────────────

/** memdbg_process_dump_request_t = 8 bytes: pid(4) + flags(4).
 *  flags: bit 0 = include registers, bit 1 = include stack traces,
 *         bit 2 = include region preview.
 *  Response is a JSON string (LZ4-framed). */
export async function processDump(pid: number, flags = 0): Promise<string> {
  const body = new BodyWriter().u32(pid).u32(flags).finish();
  const res = await getClient().call(Cmd.PROCESS_DUMP, body, 60000);
  return new TextDecoder().decode(res);
}

// ─── Maps v2 ─────────────────────────────────────────────────────────────

/** Maps v2: same memdbg_map_entry_t entries (88 bytes each) as PROCESS_MAPS,
 *  but the body is LZ4-framed (unwrap handled by MdbgClient).
 *  memdbg_map_entry_t = 88 bytes: start(8) + end(8) + protection(4) + flags(4) + name[64] */
export async function listMapsV2(pid: number): Promise<MemoryRegion[]> {
  const body = new BodyWriter().u32(pid).finish();
  const res = await getClient().call(Cmd.PROCESS_MAPS_V2, body, 12000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: MemoryRegion[] = [];
  for (let i = 0; i < count; i++) {
    const base = r.u64();
    const end = r.u64();
    const prot = r.u32();
    const flags = r.u32();
    const name = r.cstring(64);
    out.push({
      base, end, size: end - base, prot, flags,
      protStr: protString(prot), name,
    });
  }
  return out;
}

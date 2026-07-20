/**
 * MDBG debugger operations (0x0600..0x0619).
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 * Sizes confirmed by static_assert in the C header.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

// ─── Types (match C structs exactly) ─────────────────────────────────────

/** memdbg_thread_stop_info_t = 48 bytes:
 *  pl_event(4) + stop_signal(4) + pl_flags(4) + _pad(4) +
 *  pl_sigmask_lo(8) + pl_sigmask_hi(8) + pl_siglist_lo(8) + pl_siglist_hi(8) */
export interface ThreadStopInfo {
  plEvent: number;
  stopSignal: number;
  plFlags: number;
  plSigmaskLo: bigint;
  plSigmaskHi: bigint;
  plSiglistLo: bigint;
  plSiglistHi: bigint;
}

/** memdbg_debug_thread_entry_t = 100 bytes:
 *  lwp(4) + state(4) + stop_info(48) + priority(4) +
 *  runtime_us(8) + pctcpu(4) + cpu_id(4) + name[24] */
export interface DebugThread {
  lwp: number;
  tid: number;        // alias for lwp
  state: number;
  stopInfo: ThreadStopInfo;
  priority: number;
  runtimeUs: bigint;
  pctcpu: number;
  cpuId: number;
  cpu: number;        // alias for cpuId
  name: string;
}

export const ThreadState = {
  RUNNING: 0,
  STOPPED: 1,
  SUSPENDED: 2,
  WAITING: 3,
  UNKNOWN: 4,
} as const;

export function threadStateName(s: number): string {
  switch (s) {
    case 0: return "running";
    case 1: return "stopped";
    case 2: return "suspended";
    case 3: return "waiting";
    case 4: return "unknown";
    default: return `state_${s}`;
  }
}

/** memdbg_debug_regs_t = 176 bytes:
 *  r15(8) r14(8) r13(8) r12(8) r11(8) r10(8) r9(8) r8(8)
 *  rdi(8) rsi(8) rbp(8) rbx(8) rdx(8) rcx(8) rax(8)
 *  trapno(4) fs(2) gs(2) err(4) es(2) ds(2)
 *  rip(8) cs(8) rflags(8) rsp(8) ss(8) */
export interface DebugRegs {
  r15: bigint; r14: bigint; r13: bigint; r12: bigint;
  r11: bigint; r10: bigint; r9: bigint;  r8: bigint;
  rdi: bigint; rsi: bigint; rbp: bigint; rbx: bigint;
  rdx: bigint; rcx: bigint; rax: bigint;
  trapno: number; fs: number; gs: number;
  err: number; es: number; ds: number;
  rip: bigint; cs: bigint; rflags: bigint; rsp: bigint; ss: bigint;
}

/** C register read order (matching memdbg_debug_regs_t field order). */
export function decodeRegs(r: BodyReader): DebugRegs {
  return {
    r15: r.u64(), r14: r.u64(), r13: r.u64(), r12: r.u64(),
    r11: r.u64(), r10: r.u64(), r9: r.u64(),  r8: r.u64(),
    rdi: r.u64(), rsi: r.u64(), rbp: r.u64(), rbx: r.u64(),
    rdx: r.u64(), rcx: r.u64(), rax: r.u64(),
    trapno: r.u32(), fs: r.u16(), gs: r.u16(),
    err: r.u32(), es: r.u16(), ds: r.u16(),
    rip: r.u64(), cs: r.u64(), rflags: r.u64(), rsp: r.u64(), ss: r.u64(),
  };
}

export function encodeRegs(w: BodyWriter, regs: DebugRegs): BodyWriter {
  return w
    .u64(regs.r15).u64(regs.r14).u64(regs.r13).u64(regs.r12)
    .u64(regs.r11).u64(regs.r10).u64(regs.r9).u64(regs.r8)
    .u64(regs.rdi).u64(regs.rsi).u64(regs.rbp).u64(regs.rbx)
    .u64(regs.rdx).u64(regs.rcx).u64(regs.rax)
    .u32(regs.trapno).u16(regs.fs).u16(regs.gs)
    .u32(regs.err).u16(regs.es).u16(regs.ds)
    .u64(regs.rip).u64(regs.cs).u64(regs.rflags).u64(regs.rsp).u64(regs.ss);
}

/** memdbg_debug_dbregs_t = 128 bytes: dr[16] */
export interface DebugDbRegs {
  dr: bigint[];
}

/** memdbg_debug_fpregs_t = 4 + 4 + 1024 = up to 1032 bytes */
export interface DebugFpRegs {
  length: number;
  flags: number;
  data: Uint8Array;
}

/** memdbg_debug_fsgsbase_t = 16 bytes: fs_base(8) + gs_base(8) */
export interface DebugFsGs {
  fsBase: bigint;
  gsBase: bigint;
}

/** memdbg_debug_breakpoint_list_entry_t = 32 bytes:
 *  address(8) + kind(4) + flags(4) + cond_reg(4) + cond_op(4) + cond_value(8) */
export interface BreakpointEntry {
  address: bigint;
  addressHex: string;
  kind: number;       // 0 = software, 1 = hardware
  type: number;       // alias for kind
  flags: number;      // bit 0 = installed, bit 1 = active
  enabled: boolean;   // derived from flags
  condReg: number;
  condOp: number;
  condValue: bigint;
}

/** memdbg_debug_watchpoint_list_entry_t = 24 bytes:
 *  address(8) + length(4) + type(4) + slot(4) + flags(4) */
export interface WatchpointEntry {
  address: bigint;
  addressHex: string;
  length: number;  // 1, 2, 4, 8
  size: number;     // alias for length
  type: number;    // 0 = exec, 1 = write, 2 = read, 3 = read-write
  slot: number;    // 0..3
  hwIndex: number; // alias for slot
  flags: number;   // bit 0 = installed
}

/** memdbg_debug_poll_response_t = 8 bytes: stopped(4) + stop_lwp(4) */
export interface DebugPoll {
  stopped: boolean;
  stopLwp: number;
}

export interface DisasmInsn {
  address: bigint;
  addressHex: string;
  size: number;
  bytes: Uint8Array;
  mnemonic: string;
  operands: string;
}

// ─── Attach / lifecycle ──────────────────────────────────────────────────

/** memdbg_debug_attach_request_t = 8 bytes: pid(4) + reserved(4) */
export async function debugAttach(pid: number): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(0).finish();
  await getClient().call(Cmd.DEBUG_ATTACH, body, 10000);
}

export async function debugDetach(): Promise<void> {
  await getClient().call(Cmd.DEBUG_DETACH, new Uint8Array(0));
}

export async function debugStop(): Promise<void> {
  await getClient().call(Cmd.DEBUG_STOP, new Uint8Array(0));
}

export async function debugContinue(): Promise<void> {
  await getClient().call(Cmd.DEBUG_CONTINUE, new Uint8Array(0));
}

/** memdbg_debug_thread_request_t = 8 bytes: pid(4) + lwp(4) */
export async function debugStep(lwp: number): Promise<void> {
  await getClient().call(Cmd.DEBUG_STEP, threadReq(lwp));
}

export async function debugSuspend(lwp: number): Promise<void> {
  await getClient().call(Cmd.DEBUG_SUSPEND_THREAD, threadReq(lwp));
}

export async function debugResume(lwp: number): Promise<void> {
  await getClient().call(Cmd.DEBUG_RESUME_THREAD, threadReq(lwp));
}

// ─── Threads ─────────────────────────────────────────────────────────────

/** memdbg_debug_threads_response_prefix_t = 8 bytes: count(4) + reserved(4)
 *  followed by count × memdbg_debug_thread_entry_t entries. */
export async function debugGetThreads(): Promise<DebugThread[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_THREADS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: DebugThread[] = [];
  for (let i = 0; i < count; i++) {
    out.push(decodeThread(r));
  }
  return out;
}

function decodeThread(r: BodyReader): DebugThread {
  const lwp = r.i32();
  const state = r.u32();
  const stopInfo: ThreadStopInfo = {
    plEvent: r.i32(),
    stopSignal: r.i32(),
    plFlags: r.i32(),
    plSigmaskLo: (r.skip(4), r.u64()), // skip _pad(4), then read sigmask
    plSigmaskHi: r.u64(),
    plSiglistLo: r.u64(),
    plSiglistHi: r.u64(),
  };
  const priority = r.i32();
  const runtimeUs = r.u64();
  const pctcpu = r.i32();
  const cpuId = r.i32();
  const name = r.cstring(24);
  return { lwp, tid: lwp, state, stopInfo, priority, runtimeUs, pctcpu, cpuId, cpu: cpuId, name };
}

// ─── Registers ───────────────────────────────────────────────────────────

export async function debugGetRegs(lwp: number): Promise<DebugRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_REGS, threadReq(lwp));
  return decodeRegs(new BodyReader(res));
}

export async function debugSetRegs(lwp: number, regs: DebugRegs): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0);
  encodeRegs(w, regs);
  await getClient().call(Cmd.DEBUG_SET_REGS, w.finish());
}

export async function debugGetDbRegs(lwp: number): Promise<DebugDbRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_DBREGS, threadReq(lwp));
  const r = new BodyReader(res);
  const dr: bigint[] = [];
  for (let i = 0; i < 16 && r.remaining >= 8; i++) dr.push(r.u64());
  return { dr };
}

export async function debugSetDbRegs(lwp: number, dr: bigint[]): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0);
  for (let i = 0; i < 16; i++) w.u64(dr[i] ?? 0n);
  await getClient().call(Cmd.DEBUG_SET_DBREGS, w.finish());
}

export async function debugGetFpRegs(lwp: number): Promise<DebugFpRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_FPREGS, threadReq(lwp));
  const r = new BodyReader(res);
  const length = r.u32();
  const flags = r.u32();
  const data = r.remaining >= length ? r.bytes(length) : r.bytes(r.remaining);
  return { length, flags, data };
}

export async function debugSetFpRegs(lwp: number, flags: number, data: Uint8Array): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0).u32(data.length).u32(flags).bytes(data);
  await getClient().call(Cmd.DEBUG_SET_FPREGS, w.finish());
}

export async function debugGetFsGs(lwp: number): Promise<DebugFsGs> {
  const res = await getClient().call(Cmd.DEBUG_GET_FSGSBASE, threadReq(lwp));
  const r = new BodyReader(res);
  return { fsBase: r.u64(), gsBase: r.u64() };
}

export async function debugSetFsGs(lwp: number, fsBase: bigint, gsBase: bigint): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0).u64(fsBase).u64(gsBase);
  await getClient().call(Cmd.DEBUG_SET_FSGSBASE, w.finish());
}

// ─── Breakpoints ─────────────────────────────────────────────────────────

/** memdbg_debug_breakpoint_request_t = 16 bytes: address(8) + kind(4) + reserved(4) */
export async function debugSetBreakpoint(address: bigint, kind = 0): Promise<void> {
  const w = new BodyWriter().u64(address).u32(kind).u32(0);
  await getClient().call(Cmd.DEBUG_SET_BREAKPOINT, w.finish());
}

/** memdbg_debug_breakpoint_cond_request_t = 32 bytes:
 *  address(8) + kind(4) + cond_reg(4) + cond_op(4) + reserved(4) + cond_value(8) */
export async function debugSetBreakpointCond(
  address: bigint, kind: number,
  condReg: number, condOp: number, condValue: bigint,
): Promise<void> {
  const w = new BodyWriter()
    .u64(address).u32(kind).u32(condReg).u32(condOp).u32(0).u64(condValue);
  await getClient().call(Cmd.DEBUG_SET_BREAKPOINT_COND, w.finish());
}

export async function debugClearBreakpoint(address: bigint, kind = 0): Promise<void> {
  const w = new BodyWriter().u64(address).u32(kind).u32(0);
  await getClient().call(Cmd.DEBUG_CLEAR_BREAKPOINT, w.finish());
}

/** memdbg_debug_clear_all_response_t = 8 bytes: cleared(4) + reserved(4) */
export async function debugClearAllBreakpoints(): Promise<number> {
  const res = await getClient().call(Cmd.DEBUG_CLEAR_ALL_BREAKPOINTS, new Uint8Array(0));
  return res.length >= 4 ? new BodyReader(res).u32() : 0;
}

/** memdbg_debug_breakpoint_list_prefix_t = 8 bytes: count(4) + reserved(4)
 *  followed by count × memdbg_debug_breakpoint_list_entry_t entries (32B each). */
export async function debugGetBreakpoints(): Promise<BreakpointEntry[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_BREAKPOINTS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: BreakpointEntry[] = [];
  for (let i = 0; i < count; i++) {
    const address = r.u64();
    const kind = r.u32();
    const flags = r.u32();
    const condReg = r.u32();
    const condOp = r.u32();
    const condValue = r.u64();
    out.push({ address, addressHex: addrToHex(address), kind, type: kind, flags, enabled: !!(flags & 1), condReg, condOp, condValue });
  }
  return out;
}

// ─── Watchpoints ─────────────────────────────────────────────────────────

/** memdbg_debug_watchpoint_request_t = 16 bytes: address(8) + length(4) + type(4) */
export async function debugSetWatchpoint(
  address: bigint, length: number, type: number,
): Promise<void> {
  const w = new BodyWriter().u64(address).u32(length).u32(type);
  await getClient().call(Cmd.DEBUG_SET_WATCHPOINT, w.finish());
}

export async function debugClearWatchpoint(address: bigint): Promise<void> {
  const w = new BodyWriter().u64(address).u32(0).u32(0);
  await getClient().call(Cmd.DEBUG_CLEAR_WATCHPOINT, w.finish());
}

export async function debugClearAllWatchpoints(): Promise<number> {
  const res = await getClient().call(Cmd.DEBUG_CLEAR_ALL_WATCHPOINTS, new Uint8Array(0));
  return res.length >= 4 ? new BodyReader(res).u32() : 0;
}

/** memdbg_debug_watchpoint_list_prefix_t = 8 bytes: count(4) + reserved(4)
 *  followed by count × memdbg_debug_watchpoint_list_entry_t entries (24B each). */
export async function debugGetWatchpoints(): Promise<WatchpointEntry[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_WATCHPOINTS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: WatchpointEntry[] = [];
  for (let i = 0; i < count; i++) {
    const address = r.u64();
    const length = r.u32();
    const type = r.u32();
    const slot = r.u32();
    const flags = r.u32();
    out.push({ address, addressHex: addrToHex(address), length, size: length, type, slot, hwIndex: slot, flags });
  }
  return out;
}

// ─── Poll ────────────────────────────────────────────────────────────────

/** memdbg_debug_poll_response_t = 8 bytes: stopped(4) + stop_lwp(4) */
export async function debugPollEvents(): Promise<DebugPoll> {
  const res = await getClient().call(Cmd.DEBUG_POLL_EVENTS, new Uint8Array(0), 3000);
  const r = new BodyReader(res);
  return {
    stopped: r.i32() !== 0,
    stopLwp: r.i32(),
  };
}

// ─── Disasm / Asm ────────────────────────────────────────────────────────

/** memdbg_disasm_request_t = 24 bytes:
 *  pid(4) + count_max(4) + address(8) + length(4) + reserved(4) */
export async function disasm(
  pid: number, address: bigint, length = 128, countMax = 64,
): Promise<DisasmInsn[]> {
  const w = new BodyWriter().u32(pid).u32(countMax).u64(address).u32(length).u32(0);
  const res = await getClient().call(Cmd.DISASM, w.finish(), 8000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: DisasmInsn[] = [];
  for (let i = 0; i < count; i++) {
    const addr = r.u64();
    r.u64(); // rip_rel_target
    r.u64(); // rip_rel_target (skip)
    r.i64(); // mem_displacement (signed)
    const byteLen = r.u8();
    const opcodeKind = r.u8();
    const memBaseReg = r.u8();
    const memIndexReg = r.u8();
    const memScale = r.u8();
    const mnemonicId = r.u8();
    r.skip(2); // padding (memdbg_disasm_entry_t = 32 bytes total)
    // The struct does not carry inline strings — mnemonic_id is a compact ID.
    // We report what the wire gives us.
    out.push({
      address: addr, addressHex: addrToHex(addr),
      size: byteLen, bytes: new Uint8Array(0),
      mnemonic: `id_${mnemonicId}`,
      operands: "",
    });
  }
  return out;
}

export async function asmEncode(
  address: bigint, source: string,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; error: string }> {
  const text = new TextEncoder().encode(source);
  // memdbg_asm_encode_request_t = 16 bytes: origin(8) + syntax(4) + reserved(4)
  // followed by source text bytes
  const w = new BodyWriter().u64(address).u32(0).u32(0).bytes(text);
  const res = await getClient().send(Cmd.ASM_ENCODE, w.finish(), 6000);
  const r = new BodyReader(res.body);
  if (res.status !== 0) {
    // memdbg_asm_encode_err_t: err_code(4) + msg_len(4) + msg
    const errCode = r.remaining >= 4 ? r.u32() : 0;
    const msgLen = r.remaining >= 4 ? r.u32() : 0;
    const msg = msgLen > 0 ? new TextDecoder().decode(r.bytes(Math.min(msgLen, r.remaining))) : `asm error ${errCode}`;
    return { ok: false, error: msg };
  }
  // memdbg_asm_encode_ok_t: byte_count(4) + insn_count(4) + bytes
  const byteCount = r.u32();
  r.u32(); // insn_count
  const bytes = r.bytes(Math.min(byteCount, r.remaining));
  return { ok: true, bytes };
}

/** memdbg_xrefs_to_request_t = 32 bytes:
 *  pid(4) + reserved(4) + scan_address(8) + scan_length(8) + target_address(8) */
export async function xrefsTo(
  pid: number, scanAddress: bigint, scanLength: bigint, targetAddress: bigint,
): Promise<bigint[]> {
  const w = new BodyWriter().u32(pid).u32(0).u64(scanAddress).u64(scanLength).u64(targetAddress);
  const res = await getClient().call(Cmd.XREFS_TO, w.finish());
  const r = new BodyReader(res);
  const count = r.u32();
  const out: bigint[] = [];
  for (let i = 0; i < count && r.remaining >= 8; i++) out.push(r.u64());
  return out;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function threadReq(lwp: number): Uint8Array {
  return new BodyWriter().u32(lwp).u32(0).finish();
}

function readSkip(n: number): Record<string, never> { return {}; }

/** GP register names in memdbg_debug_regs_t field order (wire-compatible display order).
 *  Only includes 64-bit GP registers; excludes segment/trap/error regs. */
export const GP_REG_ORDER = [
  "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8",
  "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax",
  "rip", "rsp", "rflags", "cs", "ss",
] as const;

export const BpType = { SW: 0, HW: 1 } as const;
export const WpType = { EXEC: 0, WRITE: 1, READ: 2, RW: 3 } as const;
export const CondOp = { EQ: 0, NE: 1, LT: 2, LE: 3, GT: 4, GE: 5 } as const;

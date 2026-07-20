/**
 * MDBG debugger operations.
 *
 * The protocol reference documents STRUCT NAMES for every debug command but
 * not the exact byte layouts. The encoders/decoders below implement the
 * canonical MemDBG C99 layouts (little-endian, packed) as observed in the
 * open-source frontend. If the payload uses a variant, adjust field order
 * here — all callers stay untouched.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

// ─── Types ───────────────────────────────────────────────────────────────
export interface DebugThread {
  tid: number;
  state: number;
  stopInfo: number;
  policy: number;
  priority: number;
  cpu: number;
  stackPtr: bigint;
  name: string;
}

/** x86_64 general-purpose registers (24 × u64), stored in the MemDBG order. */
export interface DebugRegs {
  r15: bigint; r14: bigint; r13: bigint; r12: bigint;
  r11: bigint; r10: bigint; r9: bigint;  r8: bigint;
  rdi: bigint; rsi: bigint; rbp: bigint; rbx: bigint;
  rdx: bigint; rax: bigint; rcx: bigint; rsp: bigint;
  rip: bigint; rflags: bigint;
  cs: bigint; ss: bigint; ds: bigint; es: bigint; fs: bigint; gs: bigint;
}

export const GP_REG_ORDER: readonly (keyof DebugRegs)[] = [
  "r15","r14","r13","r12","r11","r10","r9","r8",
  "rdi","rsi","rbp","rbx","rdx","rax","rcx","rsp",
  "rip","rflags","cs","ss","ds","es","fs","gs",
] as const;

export interface DebugDbRegs {
  dr: bigint[]; // 8 slots DR0..DR7
}

export interface DebugFpRegs {
  length: number;
  data: Uint8Array;
}

export interface DebugFsGs {
  fsBase: bigint;
  gsBase: bigint;
}

export interface BreakpointEntry {
  address: bigint;
  addressHex: string;
  type: number;    // 0 SW / 1 HW
  hwIndex: number;
  origByte: number;
  enabled: boolean;
  condReg: number;
  condOp: number;
  condValue: bigint;
}

export interface WatchpointEntry {
  address: bigint;
  addressHex: string;
  size: number;    // 1 / 2 / 4 / 8
  type: number;    // 1 R / 2 W / 3 RW
  hwIndex: number;
  enabled: boolean;
}

export interface DebugEvent {
  kind: number;       // 1 stop, 2 breakpoint, 3 watchpoint, 4 signal, 5 exit
  lwp: number;
  signal: number;
  address: bigint;
  addressHex: string;
  extra: bigint;
}

export interface DebugPoll {
  stopped: boolean;
  stopLwp: number;
  reason: number;
  events: DebugEvent[];
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
export async function debugGetThreads(): Promise<DebugThread[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_THREADS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  const out: DebugThread[] = [];
  for (let i = 0; i < count && r.remaining >= 40; i++) {
    out.push({
      tid: r.u32(),
      state: r.u32(),
      stopInfo: r.u32(),
      policy: r.u32(),
      priority: r.u32(),
      cpu: r.u32(),
      stackPtr: r.u64(),
      name: r.cstring(32),
    });
  }
  return out;
}

// ─── Registers ───────────────────────────────────────────────────────────
export async function debugGetRegs(lwp: number): Promise<DebugRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_REGS, threadReq(lwp));
  const r = new BodyReader(res);
  const regs = {} as DebugRegs;
  for (const key of GP_REG_ORDER) regs[key] = r.u64();
  return regs;
}

export async function debugSetRegs(lwp: number, regs: DebugRegs): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0);
  for (const key of GP_REG_ORDER) w.u64(regs[key]);
  await getClient().call(Cmd.DEBUG_SET_REGS, w.finish());
}

export async function debugGetDbRegs(lwp: number): Promise<DebugDbRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_DBREGS, threadReq(lwp));
  const r = new BodyReader(res);
  const dr: bigint[] = [];
  for (let i = 0; i < 8 && r.remaining >= 8; i++) dr.push(r.u64());
  return { dr };
}

export async function debugSetDbRegs(lwp: number, dr: bigint[]): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(0);
  for (let i = 0; i < 8; i++) w.u64(dr[i] ?? 0n);
  await getClient().call(Cmd.DEBUG_SET_DBREGS, w.finish());
}

export async function debugGetFpRegs(lwp: number): Promise<DebugFpRegs> {
  const res = await getClient().call(Cmd.DEBUG_GET_FPREGS, threadReq(lwp));
  const r = new BodyReader(res);
  const length = r.u32();
  const data = r.remaining >= length ? r.bytes(length) : r.bytes(r.remaining);
  return { length, data };
}

export async function debugSetFpRegs(lwp: number, data: Uint8Array): Promise<void> {
  const w = new BodyWriter().u32(lwp).u32(data.length).bytes(data);
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
export async function debugSetBreakpoint(
  address: bigint,
  type = 0,        // 0 SW / 1 HW
  hwIndex = 0,
): Promise<void> {
  const w = new BodyWriter().u64(address).u32(type).u32(hwIndex);
  await getClient().call(Cmd.DEBUG_SET_BREAKPOINT, w.finish());
}

export async function debugSetBreakpointCond(
  address: bigint,
  type: number,
  hwIndex: number,
  condReg: number,
  condOp: number,
  condValue: bigint,
): Promise<void> {
  const w = new BodyWriter()
    .u64(address)
    .u32(type)
    .u32(hwIndex)
    .u32(condReg)
    .u32(condOp)
    .u64(condValue);
  await getClient().call(Cmd.DEBUG_SET_BREAKPOINT_COND, w.finish());
}

export async function debugClearBreakpoint(address: bigint, type = 0): Promise<void> {
  const w = new BodyWriter().u64(address).u32(type).u32(0);
  await getClient().call(Cmd.DEBUG_CLEAR_BREAKPOINT, w.finish());
}

export async function debugClearAllBreakpoints(): Promise<number> {
  const res = await getClient().call(Cmd.DEBUG_CLEAR_ALL_BREAKPOINTS, new Uint8Array(0));
  return res.length >= 4 ? new BodyReader(res).u32() : 0;
}

export async function debugGetBreakpoints(): Promise<BreakpointEntry[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_BREAKPOINTS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  const out: BreakpointEntry[] = [];
  for (let i = 0; i < count && r.remaining >= 40; i++) {
    const address = r.u64();
    const type = r.u32();
    const hwIndex = r.u32();
    const origByte = r.u32();
    const enabled = r.u32() !== 0;
    const condReg = r.u32();
    const condOp = r.u32();
    const condValue = r.u64();
    out.push({
      address, addressHex: addrToHex(address),
      type, hwIndex, origByte, enabled,
      condReg, condOp, condValue,
    });
  }
  return out;
}

// ─── Watchpoints ─────────────────────────────────────────────────────────
export async function debugSetWatchpoint(
  address: bigint,
  size: number,
  type: number,  // 1 R / 2 W / 3 RW
  hwIndex = 0,
): Promise<void> {
  const w = new BodyWriter().u64(address).u32(size).u32(type).u32(hwIndex).u32(0);
  await getClient().call(Cmd.DEBUG_SET_WATCHPOINT, w.finish());
}

export async function debugClearWatchpoint(address: bigint, hwIndex = 0): Promise<void> {
  const w = new BodyWriter().u64(address).u32(0).u32(0).u32(hwIndex).u32(0);
  await getClient().call(Cmd.DEBUG_CLEAR_WATCHPOINT, w.finish());
}

export async function debugClearAllWatchpoints(): Promise<number> {
  const res = await getClient().call(Cmd.DEBUG_CLEAR_ALL_WATCHPOINTS, new Uint8Array(0));
  return res.length >= 4 ? new BodyReader(res).u32() : 0;
}

export async function debugGetWatchpoints(): Promise<WatchpointEntry[]> {
  const res = await getClient().call(Cmd.DEBUG_GET_WATCHPOINTS, new Uint8Array(0));
  const r = new BodyReader(res);
  const count = r.u32();
  const out: WatchpointEntry[] = [];
  for (let i = 0; i < count && r.remaining >= 24; i++) {
    const address = r.u64();
    const size = r.u32();
    const type = r.u32();
    const hwIndex = r.u32();
    const enabled = r.u32() !== 0;
    out.push({ address, addressHex: addrToHex(address), size, type, hwIndex, enabled });
  }
  return out;
}

// ─── Poll ────────────────────────────────────────────────────────────────
export async function debugPollEvents(): Promise<DebugPoll> {
  const res = await getClient().call(Cmd.DEBUG_POLL_EVENTS, new Uint8Array(0), 3000);
  const r = new BodyReader(res);
  const stopped = r.u32() !== 0;
  const stopLwp = r.u32();
  const reason = r.u32();
  const count = r.u32();
  const events: DebugEvent[] = [];
  for (let i = 0; i < count && r.remaining >= 32; i++) {
    const kind = r.u32();
    const lwp = r.u32();
    const signal = r.u32();
    r.u32(); // reserved / pad
    const address = r.u64();
    const extra = r.u64();
    events.push({ kind, lwp, signal, address, addressHex: addrToHex(address), extra });
  }
  return { stopped, stopLwp, reason, events };
}

// ─── Disasm / Asm ────────────────────────────────────────────────────────
export async function disasm(
  address: bigint,
  length = 128,
  flags = 0,
): Promise<DisasmInsn[]> {
  const w = new BodyWriter().u64(address).u32(length).u32(flags);
  const res = await getClient().call(Cmd.DISASM, w.finish(), 8000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: DisasmInsn[] = [];
  for (let i = 0; i < count && r.remaining >= 48; i++) {
    const addr = r.u64();
    const size = r.u32();
    const bytesLen = Math.min(16, size);
    const bytes = r.bytes(16).subarray(0, bytesLen);
    const mnemonic = r.cstring(16);
    const operands = r.cstring(48);
    out.push({
      address: addr, addressHex: addrToHex(addr),
      size, bytes, mnemonic, operands,
    });
  }
  return out;
}

export async function asmEncode(address: bigint, source: string): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; error: string }> {
  const text = new TextEncoder().encode(source);
  const w = new BodyWriter().u64(address).u32(text.length).bytes(text);
  const res = await getClient().send(Cmd.ASM_ENCODE, w.finish(), 6000);
  const r = new BodyReader(res.body);
  const flag = r.u32();
  if (res.status !== 0 || flag !== 0) {
    // error prefix: [u32 flag=err][u32 msg_len][utf8]
    const msgLen = r.remaining >= 4 ? r.u32() : 0;
    const msg = msgLen > 0 ? new TextDecoder().decode(r.bytes(Math.min(msgLen, r.remaining))) : "asm error";
    return { ok: false, error: msg };
  }
  const len = r.u32();
  const bytes = r.bytes(Math.min(len, r.remaining));
  return { ok: true, bytes };
}

export async function xrefsTo(address: bigint, maxHits = 64): Promise<bigint[]> {
  const w = new BodyWriter().u64(address).u32(maxHits).u32(0);
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

export const BpType = { SW: 0, HW: 1 } as const;
export const WpType = { READ: 1, WRITE: 2, RW: 3 } as const;
export const CondOp = { NONE: 0, EQ: 1, NEQ: 2, LT: 3, LE: 4, GT: 5, GE: 6 } as const;

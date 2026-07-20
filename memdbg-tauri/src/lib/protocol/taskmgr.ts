/**
 * Task manager operations: batch process info, lifecycle (stop/continue/kill),
 * memory protection changes, remote alloc/free, foreground app.
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, protString } from "./constants";
import { getClient } from "./client";

// ─── Types (match C structs exactly) ─────────────────────────────────────

/** memdbg_process_info_response_t = 260 bytes:
 *  pid(4) + name[48] + title_id[16] + content_id[64] + path[128] */
export interface ProcessInfo {
  pid: number;
  name: string;
  titleId: string;
  contentId: string;
  path: string;
  /** Derived fields (set by store, not on wire) */
  state: number;
  threadCount: number;
  vmRss: bigint;
  vmSize: bigint;
  cpuPercent: number;
}

// ─── Process info ────────────────────────────────────────────────────────

export async function processInfo(pid: number): Promise<ProcessInfo> {
  const body = new BodyWriter().u32(pid).finish();
  const res = await getClient().call(Cmd.PROCESS_INFO, body);
  return decodeInfo(new BodyReader(res));
}

/** memdbg_batch_process_info_request_t = 8 bytes: count(4) + reserved(4),
 *  followed by count × int32_t pid values.
 *  Response: memdbg_batch_process_info_response_t { count(4) + reserved(4) }
 *  followed by count × memdbg_process_info_response_t entries. */
export async function batchProcessInfo(pids: number[]): Promise<ProcessInfo[]> {
  const w = new BodyWriter().u32(pids.length).u32(0); // count + reserved
  for (const p of pids) w.u32(p);
  const res = await getClient().call(Cmd.BATCH_PROCESS_INFO, w.finish());
  const r = new BodyReader(res);
  const count = r.u32();
  r.u32(); // reserved
  const out: ProcessInfo[] = [];
  for (let i = 0; i < count; i++) out.push(decodeInfo(r));
  return out;
}

function decodeInfo(r: BodyReader): ProcessInfo {
  return {
    pid: r.i32(),
    name: r.cstring(48),
    titleId: r.cstring(16),
    contentId: r.cstring(64),
    path: r.cstring(128),
    state: 0, threadCount: 0, vmRss: 0n, vmSize: 0n, cpuPercent: 0,
  };
}

// ─── Process control ─────────────────────────────────────────────────────

/** memdbg_process_control_request_t = 8 bytes: pid(4) + action(4).
 *  Action: 0 = stop, 1 = continue, 2 = kill. */
export const ProcessAction = { STOP: 0, CONTINUE: 1, KILL: 2 } as const;

export async function processStop(pid: number): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(ProcessAction.STOP).finish();
  await getClient().call(Cmd.PROCESS_STOP, body);
}
export async function processContinue(pid: number): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(ProcessAction.CONTINUE).finish();
  await getClient().call(Cmd.PROCESS_CONTINUE, body);
}
export async function processKill(pid: number): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(ProcessAction.KILL).finish();
  await getClient().call(Cmd.PROCESS_KILL, body);
}

// ─── Foreground app ──────────────────────────────────────────────────────

/** memdbg_foreground_app_response_t = 148 bytes:
 *  pid(4) + title_id[16] + content_id[64] + name[48] + app_ver[16] */
export interface ForegroundApp {
  pid: number;
  titleId: string;
  contentId: string;
  name: string;
  appVer: string;
}

export async function foregroundApp(): Promise<ForegroundApp> {
  const res = await getClient().call(Cmd.FOREGROUND_APP, new Uint8Array(0));
  const r = new BodyReader(res);
  return {
    pid: r.i32(),
    titleId: r.cstring(16),
    contentId: r.cstring(64),
    name: r.cstring(48),
    appVer: r.cstring(16),
  };
}

// ─── Memory protection / alloc / free ────────────────────────────────────

/** memdbg_process_protect_request_t = 24 bytes:
 *  pid(4) + protection(4) + address(8) + length(8) */
export async function processProtect(
  pid: number,
  address: bigint,
  size: bigint,
  prot: number,
): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(prot).u64(address).u64(size).finish();
  await getClient().call(Cmd.PROCESS_PROTECT, body);
}

/** memdbg_process_alloc_request_t = 32 bytes:
 *  pid(4) + protection(4) + hint(8) + length(8) + flags(4) + reserved(4)
 *  Response: memdbg_process_alloc_response_t { address(8) + length(8) } */
export async function processAlloc(
  pid: number,
  size: bigint,
  prot: number,
  hint: bigint = 0n,
  flags: number = 0,
): Promise<{ address: bigint; length: bigint }> {
  const body = new BodyWriter()
    .u32(pid).u32(prot).u64(hint).u64(size).u32(flags).u32(0).finish();
  const res = await getClient().call(Cmd.PROCESS_ALLOC, body);
  const r = new BodyReader(res);
  return { address: r.u64(), length: r.u64() };
}

/** memdbg_process_free_request_t = 24 bytes:
 *  pid(4) + reserved(4) + address(8) + length(8) */
export async function processFree(pid: number, address: bigint, size: bigint): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(0).u64(address).u64(size).finish();
  await getClient().call(Cmd.PROCESS_FREE, body);
}

// ─── Helpers ─────────────────────────────────────────────────────────────

export { protString };

/** Process state name from the legacy process_entry list.
 *  For ProcessInfo objects, state defaults to 0 (RUNNING) unless
 *  augmented by the store. */
export function processStateName(state: number): string {
  switch (state) {
    case 0: return "running";
    case 1: return "stopped";
    case 2: return "suspended";
    case 3: return "zombie";
    case 4: return "unknown";
    default: return `state_${state}`;
  }
}

export function formatBytes(n: bigint | number): string {
  const v = typeof n === "bigint" ? Number(n) : n;
  if (v < 1024) return `${v} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
  return `${(v / 1024 ** 3).toFixed(2)} GB`;
}

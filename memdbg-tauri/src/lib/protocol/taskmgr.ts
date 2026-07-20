/**
 * Task manager operations: batch process info, lifecycle (stop/continue/kill),
 * memory protection changes, remote alloc/free, foreground app.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, protString } from "./constants";
import { getClient } from "./client";

export interface ProcessInfo {
  pid: number;
  name: string;
  appId: number;
  titleId: string;
  flags: number;
  parentPid: number;
  threadCount: number;
  vmRss: bigint;
  vmSize: bigint;
  cpuPercent: number;
  state: number;   // 0 running / 1 stopped / 2 zombie
}

export async function processInfo(pid: number): Promise<ProcessInfo> {
  const body = new BodyWriter().u32(pid).finish();
  const res = await getClient().call(Cmd.PROCESS_INFO, body);
  return decodeInfo(new BodyReader(res));
}

export async function batchProcessInfo(pids: number[]): Promise<ProcessInfo[]> {
  const w = new BodyWriter().u32(pids.length);
  for (const p of pids) w.u32(p);
  const res = await getClient().call(Cmd.BATCH_PROCESS_INFO, w.finish());
  const r = new BodyReader(res);
  const count = r.u32();
  const out: ProcessInfo[] = [];
  for (let i = 0; i < count; i++) out.push(decodeInfo(r));
  return out;
}

function decodeInfo(r: BodyReader): ProcessInfo {
  const pid = r.u32();
  const parentPid = r.u32();
  const appId = r.u32();
  const state = r.u32();
  const threadCount = r.u32();
  const flags = r.u32();
  const vmRss = r.u64();
  const vmSize = r.u64();
  const cpuPercent = r.u32() / 100;
  const name = r.cstring(32);
  const titleId = r.cstring(16);
  return {
    pid,
    parentPid,
    appId,
    state,
    threadCount,
    flags,
    vmRss,
    vmSize,
    cpuPercent,
    name,
    titleId,
  };
}

export async function processStop(pid: number): Promise<void> {
  await getClient().call(Cmd.PROCESS_STOP, new BodyWriter().u32(pid).finish());
}
export async function processContinue(pid: number): Promise<void> {
  await getClient().call(Cmd.PROCESS_CONTINUE, new BodyWriter().u32(pid).finish());
}
export async function processKill(pid: number, signal = 9): Promise<void> {
  await getClient().call(Cmd.PROCESS_KILL, new BodyWriter().u32(pid).u32(signal).finish());
}

export async function foregroundApp(): Promise<{ pid: number; name: string; titleId: string }> {
  const res = await getClient().call(Cmd.FOREGROUND_APP, new Uint8Array(0));
  const r = new BodyReader(res);
  const pid = r.u32();
  const name = r.cstring(32);
  const titleId = r.cstring(16);
  return { pid, name, titleId };
}

export async function processProtect(
  pid: number,
  address: bigint,
  size: bigint,
  prot: number,
): Promise<void> {
  const body = new BodyWriter().u32(pid).u64(address).u64(size).u32(prot).finish();
  await getClient().call(Cmd.PROCESS_PROTECT, body);
}

export async function processAlloc(
  pid: number,
  size: bigint,
  prot: number,
  hint: bigint = 0n,
): Promise<bigint> {
  const body = new BodyWriter().u32(pid).u64(hint).u64(size).u32(prot).finish();
  const res = await getClient().call(Cmd.PROCESS_ALLOC, body);
  return new BodyReader(res).u64();
}

export async function processFree(pid: number, address: bigint, size: bigint): Promise<void> {
  const body = new BodyWriter().u32(pid).u64(address).u64(size).finish();
  await getClient().call(Cmd.PROCESS_FREE, body);
}

export { protString };
export function formatBytes(n: bigint | number): string {
  const v = typeof n === "bigint" ? Number(n) : n;
  if (v < 1024) return `${v} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
  return `${(v / 1024 ** 3).toFixed(2)} GB`;
}

export function processStateName(state: number): string {
  return state === 0 ? "running" : state === 1 ? "stopped" : state === 2 ? "zombie" : `s${state}`;
}

/**
 * MDBG Tracer operations (0x0700..0x0703).
 *
 * The tracer is a lightweight execution tracer sitting on top of the
 * debugger. Wire layouts follow the canonical MDBG pattern (u32 count +
 * fixed-size records). Where the exact record layout is not documented in
 * protocol.md we implement the pattern observed in the reference client
 * and expose typed wrappers so adjustments live in one file.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface TracerStatus {
  attached: boolean;
  running: boolean;
  pid: number;
  eventsSeen: number;
  dropped: number;
  crashSignal: number;
  elapsedMs: number;
  dumpPath: string;
}


export interface TracerEvent {
  timestamp: bigint;
  tid: number;
  kind: number;      // event kind (call/ret/branch/exec/mem)
  rip: bigint;
  target: bigint;
  ripHex: string;
  targetHex: string;
  extra: bigint;
}

// event kinds moved to constants.ts (spec §11)
export { tracerEventKindName } from "./constants";


export async function tracerAttach(pid: number, mask = 0xffffffff): Promise<void> {
  const body = new BodyWriter().u32(pid).u32(mask).finish();
  await getClient().call(Cmd.TRACER_ATTACH, body);
}

export async function tracerDetach(): Promise<void> {
  await getClient().call(Cmd.TRACER_DETACH, new Uint8Array(0));
}

export async function tracerStatus(): Promise<TracerStatus> {
  const res = await getClient().call(Cmd.TRACER_STATUS, new Uint8Array(0));
  const r = new BodyReader(res);
  const attached = r.u8() !== 0;
  const running = r.u8() !== 0;
  const crashSignal = r.u16();
  const pid = r.u32();
  const eventsSeen = Number(r.u64());
  const dropped = Number(r.u64());
  const elapsedMs = r.remaining >= 8 ? Number(r.u64()) : 0;
  const dumpPath = r.remaining > 0 ? r.cstring(Math.min(r.remaining, 256)) : "";
  return { attached, running, crashSignal, pid, eventsSeen, dropped, elapsedMs, dumpPath };
}


export async function tracerPoll(max = 256): Promise<TracerEvent[]> {
  const body = new BodyWriter().u32(max).finish();
  const res = await getClient().call(Cmd.TRACER_POLL, body, 5000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: TracerEvent[] = [];
  for (let i = 0; i < count; i++) {
    const timestamp = r.u64();
    const tid = r.u32();
    const kind = r.u32();
    const rip = r.u64();
    const target = r.u64();
    const extra = r.u64();
    out.push({
      timestamp,
      tid,
      kind,
      rip,
      target,
      extra,
      ripHex: addrToHex(rip),
      targetHex: addrToHex(target),
    });
  }
  return out;
}

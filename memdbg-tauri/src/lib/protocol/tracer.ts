/**
 * MDBG Tracer operations (0x0700..0x0703).
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h:
 *   memdbg_tracer_attach_request_t  =  4 bytes
 *   memdbg_tracer_event_t           = 88 bytes
 *   memdbg_tracer_poll_response_prefix_t = 8 bytes
 *   memdbg_tracer_status_response_t = 288 bytes
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

// ─── Types (match C structs exactly) ─────────────────────────────────────

/** memdbg_tracer_status_response_t = 288 bytes:
 *  state(4) + events_total(4) + crash_signal(4) + reserved(4) +
 *  start_time_ns(8) + elapsed_ns(8) + dump_path[256] */
export interface TracerStatus {
  state: number;        // MEMDBG_TRACER_STATE_* (0=idle,1=running,2=crashed,3=exited,4=stopped,5=starting)
  attached: boolean;    // derived: state is RUNNING or STARTING
  running: boolean;     // derived: state === RUNNING
  pid: number;          // derived from session context (set by store)
  eventsTotal: number;
  eventsSeen: number;   // alias for eventsTotal
  crashSignal: number;
  dropped: number;      // derived (set by store, 0 from protocol)
  startTimeNs: bigint;
  elapsedNs: bigint;
  dumpPath: string;
}

export const TracerState = {
  IDLE: 0,
  RUNNING: 1,
  CRASHED: 2,
  EXITED: 3,
  STOPPED: 4,
  STARTING: 5,
} as const;

export function tracerStateName(state: number): string {
  switch (state) {
    case 0: return "idle";
    case 1: return "running";
    case 2: return "crashed";
    case 3: return "exited";
    case 4: return "stopped";
    case 5: return "starting";
    default: return `state_${state}`;
  }
}

/** memdbg_tracer_event_t = 88 bytes:
 *  timestamp_ns(8) + event_type(4) + lwp(4) +
 *  syscall_no(4) + syscall_ret(4) + args[6](48) +
 *  signal(4) + reserved(4) + fault_addr(8) */
export interface TracerEvent {
  timestampNs: bigint;
  timestamp: bigint;    // alias for timestampNs
  eventType: number;    // 1=syscall_entry, 2=syscall_exit, 3=signal, 4=crash
  kind: number;         // alias for eventType
  lwp: number;
  tid: number;          // alias for lwp
  syscallNo: number;
  syscallRet: number;
  args: bigint[];
  signal: number;
  faultAddr: bigint;
  faultAddrHex: string;
  ripHex: string;       // derived from args (caller sets)
  targetHex: string;    // derived from args (caller sets)
  extra: bigint;        // derived from args (caller sets)
}

// ─── Attach / Detach ────────────────────────────────────────────────────

/** memdbg_tracer_attach_request_t = 4 bytes: pid(4) */
export async function tracerAttach(pid: number): Promise<void> {
  const body = new BodyWriter().u32(pid).finish();
  await getClient().call(Cmd.TRACER_ATTACH, body);
}

export async function tracerDetach(): Promise<void> {
  await getClient().call(Cmd.TRACER_DETACH, new Uint8Array(0));
}

// ─── Status ─────────────────────────────────────────────────────────────

export async function tracerStatus(): Promise<TracerStatus> {
  const res = await getClient().call(Cmd.TRACER_STATUS, new Uint8Array(0));
  const r = new BodyReader(res);
  const state = r.i32();
  const eventsTotal = r.u32();
  const crashSignal = r.i32();
  r.skip(4); // reserved
  const startTimeNs = r.u64();
  const elapsedNs = r.u64();
  const dumpPath = r.cstring(256);
  return {
    state,
    attached: state === TracerState.RUNNING || state === TracerState.STARTING,
    running: state === TracerState.RUNNING,
    pid: 0,
    eventsTotal, eventsSeen: eventsTotal,
    crashSignal,
    dropped: 0,
    startTimeNs,
    elapsedNs,
    dumpPath,
  };
}

// ─── Poll ───────────────────────────────────────────────────────────────

/** memdbg_tracer_poll_response_prefix_t = 8 bytes: count(4) + reserved(4)
 *  followed by count × memdbg_tracer_event_t entries. */
export async function tracerPoll(max = 256): Promise<TracerEvent[]> {
  const body = new BodyWriter().u32(max).finish();
  const res = await getClient().call(Cmd.TRACER_POLL, body, 5000);
  const r = new BodyReader(res);
  const count = r.u32();
  r.skip(4); // reserved
  const out: TracerEvent[] = [];
  for (let i = 0; i < count; i++) {
    out.push(decodeEvent(r));
  }
  return out;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function decodeEvent(r: BodyReader): TracerEvent {
  const timestampNs = r.u64();
  const eventType = r.u32();
  const lwp = r.u32();
  const syscallNo = r.u32();
  const syscallRet = r.i32();
  const args: bigint[] = [];
  for (let j = 0; j < 6; j++) args.push(r.u64());
  const signal = r.i32();
  r.skip(4); // reserved
  const faultAddr = r.u64();
  return {
    timestampNs, timestamp: timestampNs,
    eventType, kind: eventType,
    lwp, tid: lwp,
    syscallNo, syscallRet,
    args, signal, faultAddr,
    faultAddrHex: addrToHex(faultAddr),
    ripHex: "", targetHex: "", extra: 0n,
  };
}

function readSkip(n: number): Record<string, never> { return {}; }

// Re-export event kind names from constants
export { tracerEventKindName } from "./constants";

/** Compatibility alias for TracerEvent. */
export type DebugEvent = TracerEvent;

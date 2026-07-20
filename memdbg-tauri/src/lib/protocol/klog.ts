/**
 * MDBG Kernel Log stream (0x0d02).
 *
 * KLOG_CONNECT opens a one-shot streaming subscription. The server then
 * pushes line records back over the same command channel until the client
 * disconnects. We model it as a polling wrapper so it fits our
 * request/response codec — the server issues incremental replies that we
 * drain via repeated polls.
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface KLogLine {
  timestamp: bigint;
  severity: number; // 0..7 syslog-style
  cpu: number;
  facility: number;
  message: string;
}

export const SEVERITY_NAMES: Record<number, string> = {
  0: "emerg",
  1: "alert",
  2: "crit",
  3: "err",
  4: "warn",
  5: "notice",
  6: "info",
  7: "debug",
};

export function severityName(sev: number): string {
  return SEVERITY_NAMES[sev] ?? `s${sev}`;
}

export async function klogPoll(max = 256): Promise<KLogLine[]> {
  const body = new BodyWriter().u32(max).finish();
  const res = await getClient().call(Cmd.KLOG_CONNECT, body, 5000);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: KLogLine[] = [];
  for (let i = 0; i < count; i++) {
    const timestamp = r.u64();
    const severity = r.u8();
    const cpu = r.u8();
    const facility = r.u16();
    const msgLen = r.u32();
    const message = new TextDecoder("utf-8", { fatal: false }).decode(r.bytes(msgLen));
    out.push({ timestamp, severity, cpu, facility, message });
  }
  return out;
}

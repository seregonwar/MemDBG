/**
 * High-level MDBG operations. Wrap raw commands with typed body encoders
 * and decoders so store code stays readable.
 */
import { BodyReader, BodyWriter, addrToHex } from "./codec";
import { Cmd, ValueType, type ValueTypeId, protString } from "./constants";
import { getClient } from "./client";

// ─── Types ───────────────────────────────────────────────────────────────
export interface RemoteProcess {
  pid: number;
  name: string;
  appId: number;
  titleId: string;
  flags: number;
}

export interface MemoryRegion {
  base: bigint;
  size: bigint;
  prot: number;
  protStr: string;
  name: string;
  end: bigint;
}

export interface ScanHit {
  address: bigint;
  addressHex: string;
  value: Uint8Array;
}

// ─── Process ─────────────────────────────────────────────────────────────
export async function listProcesses(): Promise<RemoteProcess[]> {
  const body = await getClient().call(Cmd.PROCESS_LIST, new Uint8Array(0));
  const r = new BodyReader(body);
  const count = r.u32();
  const out: RemoteProcess[] = [];
  for (let i = 0; i < count; i++) {
    const pid = r.u32();
    const name = r.cstring(32);
    const appId = r.u32();
    const titleId = r.cstring(16);
    const flags = r.u32();
    out.push({ pid, name, appId, titleId, flags });
  }
  return out;
}

export async function listMaps(pid: number): Promise<MemoryRegion[]> {
  const body = new BodyWriter().u32(pid).finish();
  const res = await getClient().call(Cmd.PROCESS_MAPS, body);
  const r = new BodyReader(res);
  const count = r.u32();
  const out: MemoryRegion[] = [];
  for (let i = 0; i < count; i++) {
    const base = r.u64();
    const size = r.u64();
    const prot = r.u32();
    const name = r.cstring(32);
    out.push({
      base,
      size,
      prot,
      protStr: protString(prot),
      name,
      end: base + size,
    });
  }
  return out;
}

// ─── Memory ──────────────────────────────────────────────────────────────
export async function readMemory(
  pid: number,
  address: bigint,
  length: number,
): Promise<Uint8Array> {
  const body = new BodyWriter().u32(pid).u64(address).u32(length).finish();
  return getClient().call(Cmd.MEMORY_READ, body, 15000);
}

export async function writeMemory(
  pid: number,
  address: bigint,
  data: Uint8Array,
): Promise<void> {
  const body = new BodyWriter().u32(pid).u64(address).u32(data.length).bytes(data).finish();
  await getClient().call(Cmd.MEMORY_WRITE, body);
}

// ─── Scan ────────────────────────────────────────────────────────────────
export interface ScanFilter {
  rangeStart?: bigint;
  rangeEnd?: bigint;
  maxHits?: number;
}

export async function scanExact(
  pid: number,
  type: ValueTypeId,
  value: Uint8Array,
  filter: ScanFilter = {},
): Promise<ScanHit[]> {
  const w = new BodyWriter()
    .u32(pid)
    .u16(type)
    .u16(value.length)
    .bytes(value)
    .u64(filter.rangeStart ?? 0n)
    .u64(filter.rangeEnd ?? 0n)
    .u32(filter.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_PROCESS_EXACT, w.finish(), 30000);
  return parseScanHits(res, value.length);
}

export async function scanAob(
  pid: number,
  pattern: string,
  filter: ScanFilter = {},
): Promise<ScanHit[]> {
  const { bytes, mask } = compilePattern(pattern);
  const w = new BodyWriter()
    .u32(pid)
    .u16(bytes.length)
    .u16(0)
    .bytes(bytes)
    .bytes(mask)
    .u64(filter.rangeStart ?? 0n)
    .u64(filter.rangeEnd ?? 0n)
    .u32(filter.maxHits ?? 0);
  const res = await getClient().call(Cmd.SCAN_PROCESS_AOB, w.finish(), 30000);
  return parseScanHits(res, bytes.length);
}

function parseScanHits(body: Uint8Array, valueSize: number): ScanHit[] {
  const r = new BodyReader(body);
  const count = r.u32();
  const out: ScanHit[] = [];
  for (let i = 0; i < count; i++) {
    const addr = r.u64();
    const value = valueSize > 0 && r.remaining >= valueSize ? r.bytes(valueSize) : new Uint8Array(0);
    out.push({ address: addr, addressHex: addrToHex(addr), value });
  }
  return out;
}

// ─── Value encode/decode ────────────────────────────────────────────────
export function encodeValue(type: ValueTypeId, input: string): Uint8Array {
  const b = new BodyWriter();
  switch (type) {
    case ValueType.U8: b.u8(Number(input) & 0xff); break;
    case ValueType.U16: b.u16(Number(input) & 0xffff); break;
    case ValueType.U32: b.u32(Number(input)); break;
    case ValueType.U64:
    case ValueType.POINTER: b.u64(BigInt(input || "0")); break;
    case ValueType.F32: {
      const arr = new Float32Array([Number(input)]);
      return new Uint8Array(arr.buffer);
    }
    case ValueType.F64: {
      const arr = new Float64Array([Number(input)]);
      return new Uint8Array(arr.buffer);
    }
    case ValueType.BYTES:
      return hexStringToBytes(input);
  }
  return b.finish();
}

export function decodeValue(type: ValueTypeId, bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  switch (type) {
    case ValueType.U8: return String(dv.getUint8(0));
    case ValueType.U16: return String(dv.getUint16(0, true));
    case ValueType.U32: return String(dv.getUint32(0, true));
    case ValueType.U64: return String(dv.getBigUint64(0, true));
    case ValueType.POINTER: return addrToHex(dv.getBigUint64(0, true));
    case ValueType.F32: return String(dv.getFloat32(0, true));
    case ValueType.F64: return String(dv.getFloat64(0, true));
    case ValueType.BYTES:
      return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  }
  return "";
}

function hexStringToBytes(s: string): Uint8Array {
  const clean = s.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

function compilePattern(pattern: string): { bytes: Uint8Array; mask: Uint8Array } {
  const tokens = pattern.trim().split(/\s+/).filter(Boolean);
  const bytes = new Uint8Array(tokens.length);
  const mask = new Uint8Array(tokens.length);
  tokens.forEach((tok, i) => {
    if (tok === "?" || tok === "??") {
      bytes[i] = 0;
      mask[i] = 0;
    } else {
      bytes[i] = parseInt(tok, 16) & 0xff;
      mask[i] = 0xff;
    }
  });
  return { bytes, mask };
}

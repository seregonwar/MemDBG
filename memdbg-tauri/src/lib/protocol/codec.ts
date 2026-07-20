/**
 * MDBG codec — packet framing, header build/parse, primitives.
 *
 * The MDBG protocol is little-endian and packed. All requests share a
 * 16-byte header; all responses share a 20-byte header. Bodies follow
 * immediately.
 */
import {
  MDBG_MAGIC,
  REQUEST_HEADER_SIZE,
  RESPONSE_HEADER_SIZE,
  type CmdId,
} from "./constants";

// ─── Little-endian helpers ───────────────────────────────────────────────
export const TEXT = new TextDecoder("utf-8");
export const TEXT_ENC = new TextEncoder();

export function readCString(view: DataView, offset: number, max: number): string {
  const bytes = new Uint8Array(view.buffer, view.byteOffset + offset, max);
  let end = bytes.indexOf(0);
  if (end < 0) end = bytes.length;
  return TEXT.decode(bytes.subarray(0, end));
}

export function writeFixedString(
  target: Uint8Array,
  offset: number,
  value: string,
  size: number,
) {
  const bytes = TEXT_ENC.encode(value);
  const copy = Math.min(bytes.length, size - 1);
  target.set(bytes.subarray(0, copy), offset);
  target[offset + copy] = 0;
}

// ─── Header shapes ───────────────────────────────────────────────────────
export interface RequestHeader {
  magic: number;
  version: number;
  command: number;
  requestId: number;
  length: number;
}

export interface ResponseHeader {
  magic: number;
  version: number;
  command: number;
  requestId: number;
  status: number; // int32
  length: number;
}

export function encodeRequest(
  command: CmdId,
  requestId: number,
  body: Uint8Array,
  version = 1,
): Uint8Array {
  const packet = new Uint8Array(REQUEST_HEADER_SIZE + body.length);
  const dv = new DataView(packet.buffer);
  dv.setUint32(0, MDBG_MAGIC, true);
  dv.setUint16(4, version, true);
  dv.setUint16(6, command, true);
  dv.setUint32(8, requestId, true);
  dv.setUint32(12, body.length, true);
  packet.set(body, REQUEST_HEADER_SIZE);
  return packet;
}

export function decodeResponseHeader(buf: Uint8Array): ResponseHeader | null {
  if (buf.length < RESPONSE_HEADER_SIZE) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    magic: dv.getUint32(0, true),
    version: dv.getUint16(4, true),
    command: dv.getUint16(6, true),
    requestId: dv.getUint32(8, true),
    status: dv.getInt32(12, true),
    length: dv.getUint32(16, true),
  };
}

// ─── Stream re-assembler ─────────────────────────────────────────────────
/**
 * Accepts arbitrary WebSocket byte chunks and yields complete MDBG response
 * frames. The bridge is a raw TCP pipe, so WebSocket message boundaries
 * are NOT packet boundaries.
 */
export class MdbgFramer {
  private buf: Uint8Array = new Uint8Array(0);

  push(chunk: Uint8Array) {
    if (this.buf.length === 0) {
      this.buf = chunk;
      return;
    }
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0);
    merged.set(chunk, this.buf.length);
    this.buf = merged;
  }

  *drain(): Generator<{ header: ResponseHeader; body: Uint8Array }> {
    while (this.buf.length >= RESPONSE_HEADER_SIZE) {
      const header = decodeResponseHeader(this.buf);
      if (!header) break;
      if (header.magic !== MDBG_MAGIC) {
        // Attempt resync: find next magic. If none, drop everything.
        const idx = findMagic(this.buf, 1);
        this.buf = idx < 0 ? new Uint8Array(0) : this.buf.subarray(idx);
        continue;
      }
      const total = RESPONSE_HEADER_SIZE + header.length;
      if (this.buf.length < total) break;
      const body = this.buf.subarray(RESPONSE_HEADER_SIZE, total).slice();
      this.buf = this.buf.subarray(total).slice();
      yield { header, body };
    }
  }
}

function findMagic(buf: Uint8Array, from: number): number {
  for (let i = from; i + 4 <= buf.length; i++) {
    if (
      buf[i] === 0x4d &&
      buf[i + 1] === 0x44 &&
      buf[i + 2] === 0x42 &&
      buf[i + 3] === 0x47
    ) {
      return i;
    }
  }
  return -1;
}

// ─── LZ4 block decompression (framed-payload commands only) ─────────────
/**
 * Pure-JS LZ4 block-format decoder. Matches the reference LZ4 block spec
 * used by MemDBG for MEMORY_READ / BATCH_READ / MAPS_V2 / PROCESS_DUMP
 * response bodies (spec §5.3).
 */
export function lz4Decompress(src: Uint8Array, uncompressedSize: number): Uint8Array {
  const out = new Uint8Array(uncompressedSize);
  let s = 0, d = 0;
  while (s < src.length) {
    const token = src[s++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b: number;
      do { b = src[s++]; litLen += b; } while (b === 255 && s < src.length);
    }
    for (let i = 0; i < litLen; i++) out[d++] = src[s++];
    if (s >= src.length) break;
    const offset = src[s++] | (src[s++] << 8);
    if (offset === 0) throw new Error("lz4: invalid offset 0");
    let matchLen = token & 0x0f;
    if (matchLen === 15) {
      let b: number;
      do { b = src[s++]; matchLen += b; } while (b === 255 && s < src.length);
    }
    matchLen += 4;
    const mStart = d - offset;
    if (mStart < 0) throw new Error("lz4: match before dict");
    // byte-wise copy (must not use TypedArray.set — overlapping semantics)
    for (let i = 0; i < matchLen; i++) out[d++] = out[mStart + i];
  }
  return d === uncompressedSize ? out : out.subarray(0, d);
}

/**
 * Unwrap the LZ4/raw sub-frame prefix (0x00 raw / 0x01 lz4 + u32 size).
 * Only call this for {@link FRAMED_RESPONSE_COMMANDS}; other commands
 * carry raw bodies whose first byte must NOT be interpreted as a flag.
 */
export function unwrapCompressed(body: Uint8Array): {
  raw: Uint8Array;
  compressed: boolean;
} {
  if (body.length === 0) return { raw: body, compressed: false };
  const flag = body[0];
  if (flag === 0x00) return { raw: body.subarray(1).slice(), compressed: false };
  if (flag === 0x01) {
    if (body.length < 5) throw new Error("lz4: truncated header");
    const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
    const uncompressed = dv.getUint32(1, true);
    const raw = lz4Decompress(body.subarray(5), uncompressed);
    return { raw, compressed: true };
  }
  // Unknown flag → return body untouched.
  return { raw: body, compressed: false };
}


// ─── Body writers (little-endian, no alignment) ─────────────────────────
export class BodyWriter {
  private chunks: Uint8Array[] = [];
  private len = 0;

  u8(v: number) { this.push(new Uint8Array([v & 0xff])); return this; }
  u16(v: number) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.push(b); return this;
  }
  u32(v: number) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this.push(b); return this;
  }
  i32(v: number) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, v | 0, true);
    this.push(b); return this;
  }
  u64(v: bigint | number) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
    this.push(b); return this;
  }
  bytes(b: Uint8Array) { this.push(b); return this; }

  private push(b: Uint8Array) { this.chunks.push(b); this.len += b.length; }

  finish(): Uint8Array {
    const out = new Uint8Array(this.len);
    let o = 0;
    for (const c of this.chunks) { out.set(c, o); o += c.length; }
    return out;
  }
}

export class BodyReader {
  private dv: DataView;
  private offset = 0;
  constructor(private readonly buf: Uint8Array) {
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  get remaining() { return this.buf.length - this.offset; }
  get position() { return this.offset; }
  skip(n: number) { this.offset += n; return this; }

  u8() { const v = this.dv.getUint8(this.offset); this.offset += 1; return v; }
  u16() { const v = this.dv.getUint16(this.offset, true); this.offset += 2; return v; }
  u32() { const v = this.dv.getUint32(this.offset, true); this.offset += 4; return v; }
  i32() { const v = this.dv.getInt32(this.offset, true); this.offset += 4; return v; }
  u64() { const v = this.dv.getBigUint64(this.offset, true); this.offset += 8; return v; }
  i64() { const v = this.dv.getBigInt64(this.offset, true); this.offset += 8; return v; }
  bytes(n: number) {
    const s = this.buf.subarray(this.offset, this.offset + n).slice();
    this.offset += n;
    return s;
  }
  cstring(size: number) {
    const s = readCString(this.dv, this.offset, size);
    this.offset += size;
    return s;
  }
}

// ─── Address helpers ────────────────────────────────────────────────────
export function addrToHex(a: bigint | number, width = 16): string {
  return "0x" + BigInt(a).toString(16).toUpperCase().padStart(width, "0");
}
export function hexToAddr(s: string): bigint {
  const t = s.trim().replace(/^0x/i, "");
  return BigInt("0x" + (t || "0"));
}

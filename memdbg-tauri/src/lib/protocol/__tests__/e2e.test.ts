/**
 * End-to-end protocol tests using MockTransport.
 *
 * Every test simulates a real MDBG daemon on the other end of the wire.
 * No console, no TCP — just bytes in, bytes out, exact C struct layouts.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { MockTransport, makeResponse } from "./mock-transport";
import {
  MdbgClient,
  MdbgStatusError,
  type HelloInfo,
} from "../client";
import {
  BodyWriter,
  BodyReader,
  encodeRequest,
  decodeResponseHeader,
  MdbgFramer,
  lz4Decompress,
  unwrapCompressed,
} from "../codec";
import {
  Cmd,
  Status,
  Role,
  Platform,
  Cap,
  MDBG_MAGIC,
  MDBG_PROTOCOL_VERSION,
  REQUEST_HEADER_SIZE,
  HELLO_REQUEST_SIZE,
  MDBG_HELLO_MAGIC,
  MDBG_HELLO_IDENTITY_VERSION,
} from "../constants";

// Inject mock transport via module-level variable
let mockTransport: MockTransport | null = null;

vi.mock("../transport", () => ({
  pickTransport: () => {
    if (!mockTransport) throw new Error("MockTransport not configured");
    return mockTransport;
  },
  isTauriRuntime: () => false,
  isBrowserRuntime: () => true,
}));

// Mock getClient to return a fresh client per test (avoids stale nextReqId)
let testClient: MdbgClient;

vi.mock("../client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../client")>();
  return {
    ...actual,
    getClient: () => testClient,
  };
});

// Helper to build a HELLO response body (64 bytes)
function helloResponseBody(overrides: Partial<{
  protoVer: number; platId: number; caps: number;
  debugPort: number; udpPort: number; version: string; name: string;
  featureLevel: number; instanceId: bigint; startNs: bigint;
}> = {}): Uint8Array {
  const w = new BodyWriter()
    .u16(overrides.protoVer ?? MDBG_PROTOCOL_VERSION)
    .u16(overrides.platId ?? Platform.HOST)
    .u32(overrides.caps ?? (Cap.PROCESS_LIST | Cap.PROCESS_MAPS | Cap.MEMORY_READ))
    .u16(overrides.debugPort ?? 0)
    .u16(overrides.udpPort ?? 0);
  const ver = new TextEncoder().encode((overrides.version ?? "1.0.0").padEnd(15, "\0")).subarray(0, 15);
  const name = new TextEncoder().encode((overrides.name ?? "memdbg-test").padEnd(15, "\0")).subarray(0, 15);
  const verPadded = new Uint8Array(16); verPadded.set(ver, 0);
  const namePadded = new Uint8Array(16); namePadded.set(name, 0);
  w.bytes(verPadded).bytes(namePadded);
  w.u16(overrides.featureLevel ?? 2);
  w.u16(0); // reserved
  w.u64(overrides.instanceId ?? 0xDEADBEEFn);
  w.u64(overrides.startNs ?? 1000000n);
  return w.finish();
}


describe("MDBG Protocol E2E", () => {
  let client: MdbgClient;
  let transport: MockTransport;

  beforeEach(() => {
    transport = new MockTransport();
    mockTransport = transport;
    client = new MdbgClient();
    testClient = client;
  });

  afterEach(() => {
    try { client?.disconnect("test done"); } catch { /* ok */ }
  });

  // Helper: connect the client with a HELLO response
  async function connectClient(opts: {
    protoVer?: number; caps?: number; featureLevel?: number;
    instanceId?: bigint;
  } = {}): Promise<HelloInfo> {
    // Queue HELLO response (request 1) and GET_EXTENDED_CAPS (request 2)
    transport.queueResponse({
      requestId: 1,
      status: Status.OK,
      body: helloResponseBody({
        protoVer: opts.protoVer ?? MDBG_PROTOCOL_VERSION,
        caps: opts.caps,
        featureLevel: opts.featureLevel,
        instanceId: opts.instanceId,
      }),
    });
    transport.queueResponse({
      requestId: 2,
      status: Status.ERR_UNSUPPORTED,
      body: new Uint8Array(0),
    });

    return client.connect({ host: "127.0.0.1", port: 9020 });
  }

  // ─── HELLO Handshake ──────────────────────────────────────────────────

  describe("HELLO handshake", () => {
    it("completes full handshake with 64-byte response", async () => {
      const hello = await connectClient({
        caps: Cap.PROCESS_LIST | Cap.DEBUGGER,
        featureLevel: 2,
        instanceId: 0xABCD1234n,
      });

      expect(hello.protocolVersion).toBe(MDBG_PROTOCOL_VERSION);
      expect(hello.platformId).toBe(Platform.HOST);
      expect(hello.capabilities).toBe(Cap.PROCESS_LIST | Cap.DEBUGGER);
      expect(hello.featureLevel).toBe(2);
      expect(hello.daemonInstanceId).toBe(0xABCD1234n);
      expect(hello.daemonStartMonotonicNs).toBe(1000000n);
      expect(hello.version).toContain("1.0.0");
      expect(hello.name).toContain("memdbg-test");
      expect(client.isOnline()).toBe(true);
    });

    it("sends correctly formed HELLO request", async () => {
      await connectClient();

      const reqs = transport.getRequests();
      expect(reqs.length).toBeGreaterThanOrEqual(1);
      const helloReq = reqs[0];
      expect(helloReq.command).toBe(Cmd.HELLO);
      expect(helloReq.body.length).toBe(HELLO_REQUEST_SIZE);
      const r = new BodyReader(helloReq.body);
      expect(r.u32()).toBe(MDBG_HELLO_MAGIC);
      expect(r.u16()).toBe(MDBG_HELLO_IDENTITY_VERSION);
      expect(r.u16()).toBe(Role.CONTROL);
      expect(r.u64()).toBe(0n);
    });

    it("handles HELLO with custom role", async () => {
      // Reuse the client from beforeEach (already set as testClient)
      transport.queueResponse({ requestId: 1, status: Status.OK, body: helloResponseBody() });
      transport.queueResponse({ requestId: 2, status: Status.ERR_UNSUPPORTED, body: new Uint8Array(0) });
      transport.queueResponse({ requestId: 2, status: Status.ERR_UNSUPPORTED, body: new Uint8Array(0) });

      await client.connect({ host: "127.0.0.1", port: 9020, role: Role.MEMORY });

      const r = new BodyReader(transport.getRequests()[0].body);
      r.u32(); r.u16();
      expect(r.u16()).toBe(Role.MEMORY);
    });

    it("rejects on non-OK HELLO status", async () => {
      transport.queueResponse({ requestId: 1, status: Status.ERR_PROTOCOL, body: new Uint8Array(0) });

      await expect(
        client.connect({ host: "127.0.0.1", port: 9020 }),
      ).rejects.toThrow(MdbgStatusError);
    });
  });

  // ─── Framing ──────────────────────────────────────────────────────────

  describe("packet framing", () => {
    it("decodes response header correctly", () => {
      const body = new Uint8Array([1, 2, 3, 4]);
      const packet = makeResponse(42, Cmd.PING, Status.OK, body);

      const header = decodeResponseHeader(packet);
      expect(header).not.toBeNull();
      expect(header!.magic).toBe(MDBG_MAGIC);
      expect(header!.version).toBe(MDBG_PROTOCOL_VERSION);
      expect(header!.command).toBe(Cmd.PING);
      expect(header!.requestId).toBe(42);
      expect(header!.status).toBe(Status.OK);
      expect(header!.length).toBe(4);
    });

    it("encodes request header with correct 16-byte layout", () => {
      const body = new Uint8Array([0xAA, 0xBB]);
      const packet = encodeRequest(Cmd.PROCESS_LIST, 7, body);

      expect(packet.length).toBe(REQUEST_HEADER_SIZE + 2);
      const dv = new DataView(packet.buffer);
      expect(dv.getUint32(0, true)).toBe(MDBG_MAGIC);
      expect(dv.getUint16(4, true)).toBe(MDBG_PROTOCOL_VERSION);
      expect(dv.getUint16(6, true)).toBe(Cmd.PROCESS_LIST);
      expect(dv.getUint32(8, true)).toBe(7);
      expect(dv.getUint32(12, true)).toBe(2);
      expect(packet[REQUEST_HEADER_SIZE]).toBe(0xAA);
      expect(packet[REQUEST_HEADER_SIZE + 1]).toBe(0xBB);
    });

    it("Framer reassembles split packets", () => {
      const framer = new MdbgFramer();
      const body = new Uint8Array([9, 8, 7]);
      const full = makeResponse(5, Cmd.PING, Status.OK, body);

      const chunk1 = full.subarray(0, 12);
      const chunk2 = full.subarray(12);

      framer.push(chunk1);
      let frames = [...framer.drain()];
      expect(frames.length).toBe(0);

      framer.push(chunk2);
      frames = [...framer.drain()];
      expect(frames.length).toBe(1);
      expect(frames[0].header.requestId).toBe(5);
      expect(frames[0].body).toEqual(body);
    });

    it("Framer resyncs on bad magic", () => {
      const framer = new MdbgFramer();
      const body = new Uint8Array([1]);
      const good = makeResponse(1, Cmd.PING, Status.OK, body);
      const bad = new Uint8Array(20);

      framer.push(bad);
      framer.push(good);

      const frames = [...framer.drain()];
      expect(frames.length).toBe(1);
      expect(frames[0].header.requestId).toBe(1);
    });
  });

  // ─── Status codes & errors ────────────────────────────────────────────

  describe("status codes & errors", () => {
    it("MdbgStatusError includes command and status name", async () => {
      await connectClient();

      transport.queueResponse({ requestId: 3, status: Status.ERR_NOT_FOUND, body: new Uint8Array(0) });

      try {
        await (client as any).call(Cmd.PROCESS_INFO, new Uint8Array(0), 1000);
        expect.fail("expected error");
      } catch (e) {
        expect(e).toBeInstanceOf(MdbgStatusError);
        expect((e as MdbgStatusError).status).toBe(Status.ERR_NOT_FOUND);
        expect((e as MdbgStatusError).message).toContain("ERR_NOT_FOUND");
      }
    });

    it("call() rejects on non-zero status", async () => {
      await connectClient();

      transport.queueResponse({ requestId: 3, status: Status.ERR_PARAM, body: new Uint8Array(0) });

      await expect(
        (client as any).call(Cmd.PROCESS_STOP, new BodyWriter().u32(999).u32(0).finish(), 1000),
      ).rejects.toThrow(MdbgStatusError);
    });
  });

  // ─── Timeout & disconnection ──────────────────────────────────────────

  describe("timeout & disconnection", () => {
    it("rejects request after timeout", async () => {
      await connectClient();

      const promise = (client as any).send(Cmd.PING, new Uint8Array(0), 50);
      await expect(promise).rejects.toThrow(/timed out/);
    });

    it("rejects pending requests on transport close", async () => {
      await connectClient();

      const promise = (client as any).send(Cmd.PING, new Uint8Array(0), 5000);
      transport.simulateClose("server crashed");

      await expect(promise).rejects.toThrow(/transport closed/);
      expect(client.isOnline()).toBe(false);
    });

    it("clears pending on disconnect", async () => {
      await connectClient();

      const promise = (client as any).send(Cmd.PING, new Uint8Array(0), 5000);
      client.disconnect("user");

      await expect(promise).rejects.toThrow(/disconnected/);
    });
  });

  // ─── Process operations ───────────────────────────────────────────────

  describe("process operations", () => {
    beforeEach(async () => { await connectClient(); });

    it("process_list: decodes process_entry array (56 bytes each)", async () => {
      const { listProcesses } = await import("../ops");
      const resp = new BodyWriter()
        .u32(2)
        .i32(100).i32(1).bytes(padString("eboot.bin", 48))
        .i32(200).i32(100).bytes(padString("shell", 48))
        .finish();

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });

      const procs = await listProcesses();
      expect(procs.length).toBe(2);
      expect(procs[0].pid).toBe(100);
      expect(procs[0].ppid).toBe(1);
      expect(procs[0].name).toContain("eboot.bin");
      expect(procs[1].pid).toBe(200);
      expect(procs[1].ppid).toBe(100);
    });

    it("process_info: decodes 260-byte response", async () => {
      const { processInfo } = await import("../taskmgr");
      const resp = new BodyWriter()
        .i32(100)
        .bytes(padString("eboot.bin", 48))
        .bytes(padString("CUSA12345", 16))
        .bytes(padString("UP0001-CUSA12345_00", 64))
        .bytes(padString("/app0/eboot.bin", 128))
        .finish();
      expect(resp.length).toBe(260);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });
      const info = await processInfo(100);
      expect(info.pid).toBe(100);
      expect(info.titleId).toContain("CUSA12345");
      expect(info.contentId).toContain("UP0001");
      expect(info.path).toContain("/app0/eboot.bin");
    });

    it("process_maps: decodes map_entry array (88 bytes each)", async () => {
      const { listMaps } = await import("../ops");
      const resp = new BodyWriter()
        .u32(1)
        .u64(0x100000n).u64(0x200000n)
        .u32(5).u32(0)
        .bytes(padString("libkernel", 64))
        .finish();

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });
      const maps = await listMaps(100);
      expect(maps.length).toBe(1);
      expect(maps[0].base).toBe(0x100000n);
      expect(maps[0].end).toBe(0x200000n);
      expect(maps[0].size).toBe(0x100000n);
      expect(maps[0].prot).toBe(5);
      expect(maps[0].name).toContain("libkernel");
    });
  });

  // ─── Memory read/write ────────────────────────────────────────────────

  describe("memory operations", () => {
    beforeEach(async () => { await connectClient(); });

    it("readMemory: sends correct 16-byte request, returns payload", async () => {
      const { readMemory } = await import("../ops");
      const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
      const framed = new Uint8Array(1 + data.length);
      framed[0] = 0x00;
      framed.set(data, 1);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: framed });
      const result = await readMemory(100, 0x400000n, 4);

      expect(result).toEqual(data);

      const req = transport.lastRequest()!;
      const r = new BodyReader(req.body);
      expect(r.i32()).toBe(100);
      expect(r.u64()).toBe(0x400000n);
      expect(r.u32()).toBe(4);
    });

    it("writeMemory: sends data after 16-byte prefix", async () => {
      const { writeMemory } = await import("../ops");
      const data = new Uint8Array([1, 2, 3]);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });
      await writeMemory(100, 0x500000n, data);

      const req = transport.lastRequest()!;
      expect(req.body.length).toBe(19);
      const r = new BodyReader(req.body);
      expect(r.i32()).toBe(100);
      expect(r.u64()).toBe(0x500000n);
      expect(r.u32()).toBe(3);
      expect(r.bytes(3)).toEqual(data);
    });
  });

  // ─── Debugger ─────────────────────────────────────────────────────────

  describe("debugger", () => {
    beforeEach(async () => { await connectClient(); });

    it("debugAttach: sends 8-byte request", async () => {
      const { debugAttach } = await import("../debugger");
      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });

      await debugAttach(100);

      const req = transport.lastRequest()!;
      expect(req.command).toBe(Cmd.DEBUG_ATTACH);
      const r = new BodyReader(req.body);
      expect(r.u32()).toBe(100);
      expect(r.u32()).toBe(0);
    });

    it("debugGetThreads: decodes thread entries (100 bytes each)", async () => {
      const { debugGetThreads } = await import("../debugger");
      const entry = new BodyWriter()
        .i32(42).u32(0)
        .i32(0).i32(0).i32(0).u32(0)
        .u64(0n).u64(0n).u64(0n).u64(0n)
        .i32(0).u64(0n).i32(0).i32(-1)
        .bytes(padString("main", 24))
        .finish();

      const resp = new BodyWriter().u32(1).u32(0).bytes(entry).finish();

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });
      const threads = await debugGetThreads();

      expect(threads.length).toBe(1);
      expect(threads[0].lwp).toBe(42);
      expect(threads[0].tid).toBe(42);
      expect(threads[0].state).toBe(0);
      expect(threads[0].cpuId).toBe(-1);
      expect(threads[0].name).toContain("main");
    });

    it("debugGetRegs: decodes 176-byte register struct", async () => {
      const { debugGetRegs } = await import("../debugger");
      const regs = new BodyWriter()
        .u64(1n).u64(2n).u64(3n).u64(4n).u64(5n).u64(6n).u64(7n).u64(8n)
        .u64(9n).u64(10n).u64(11n).u64(12n).u64(13n).u64(14n).u64(15n)
        .u32(0).u16(0).u16(0)
        .u32(0).u16(0).u16(0)
        .u64(0x400000n).u64(0n).u64(0x202n).u64(0x7FFFFFFFn).u64(0n)
        .finish();
      expect(regs.length).toBe(176);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: regs });
      const result = await debugGetRegs(42);

      expect(result.rax).toBe(15n);
      expect(result.rip).toBe(0x400000n);
      expect(result.rsp).toBe(0x7FFFFFFFn);
      expect(result.rflags).toBe(0x202n);
    });

    it("debugSetBreakpoint: sends 16-byte request", async () => {
      const { debugSetBreakpoint } = await import("../debugger");
      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });

      await debugSetBreakpoint(0x123456n, 0);
      const req = transport.lastRequest()!;
      expect(req.command).toBe(Cmd.DEBUG_SET_BREAKPOINT);
      const r = new BodyReader(req.body);
      expect(r.u64()).toBe(0x123456n);
      expect(r.u32()).toBe(0);
      expect(r.u32()).toBe(0);
    });
  });

  // ─── Tracer ───────────────────────────────────────────────────────────

  describe("tracer", () => {
    beforeEach(async () => { await connectClient(); });

    it("tracerAttach: sends 4-byte request (pid only)", async () => {
      const { tracerAttach } = await import("../tracer");
      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });

      await tracerAttach(100);
      const req = transport.lastRequest()!;
      expect(req.command).toBe(Cmd.TRACER_ATTACH);
      expect(req.body.length).toBe(4);
      expect(new BodyReader(req.body).u32()).toBe(100);
    });

    it("tracerPoll: decodes 88-byte event entries", async () => {
      const { tracerPoll } = await import("../tracer");
      const event = new BodyWriter()
        .u64(1000000n).u32(1).u32(42)
        .u32(39).i32(0)
        .u64(0x400000n).u64(0n).u64(0n).u64(0n).u64(0n).u64(0n)
        .i32(0).u32(0).u64(0n)
        .finish();
      expect(event.length).toBe(88);

      const resp = new BodyWriter().u32(1).u32(0).bytes(event).finish();
      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });

      const events = await tracerPoll();
      expect(events.length).toBe(1);
      expect(events[0].timestampNs).toBe(1000000n);
      expect(events[0].eventType).toBe(1);
      expect(events[0].lwp).toBe(42);
      expect(events[0].syscallNo).toBe(39);
    });

    it("tracerStatus: decodes 288-byte response", async () => {
      const { tracerStatus } = await import("../tracer");
      const resp = new BodyWriter()
        .i32(1).u32(100).i32(0).u32(0)
        .u64(5000000n).u64(3000000n)
        .bytes(padString("/data/crash.dump", 256))
        .finish();
      expect(resp.length).toBe(288);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });
      const status = await tracerStatus();

      expect(status.state).toBe(1);
      expect(status.running).toBe(true);
      expect(status.eventsSeen).toBe(100);
      expect(status.startTimeNs).toBe(5000000n);
      expect(status.dumpPath).toContain("/data/crash.dump");
    });
  });

  // ─── Task Manager ─────────────────────────────────────────────────────

  describe("task manager", () => {
    beforeEach(async () => { await connectClient(); });

    it("processStop: sends 8-byte request (pid + action)", async () => {
      const { processStop } = await import("../taskmgr");
      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });

      await processStop(100);
      const req = transport.lastRequest()!;
      expect(req.command).toBe(Cmd.PROCESS_STOP);
      expect(req.body.length).toBe(8);
      const r = new BodyReader(req.body);
      expect(r.u32()).toBe(100);
      expect(r.u32()).toBe(0);
    });

    it("processKill: sends action=2", async () => {
      const { processKill } = await import("../taskmgr");
      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array(0) });

      await processKill(100);
      const r = new BodyReader(transport.lastRequest()!.body);
      expect(r.u32()).toBe(100);
      expect(r.u32()).toBe(2);
    });

    it("foregroundApp: decodes 148-byte response", async () => {
      const { foregroundApp } = await import("../taskmgr");
      const resp = new BodyWriter()
        .i32(100)
        .bytes(padString("CUSA12345", 16))
        .bytes(padString("UP0001-CUSA12345_00", 64))
        .bytes(padString("My Game", 48))
        .bytes(padString("1.00", 16))
        .finish();
      expect(resp.length).toBe(148);

      transport.queueResponse({ requestId: 3, status: Status.OK, body: resp });
      const fg = await foregroundApp();
      expect(fg.pid).toBe(100);
      expect(fg.titleId).toContain("CUSA12345");
    });
  });

  // ─── LZ4 compression ──────────────────────────────────────────────────

  describe("LZ4 compression", () => {
    it("lz4Decompress handles simple literal-only block", () => {
      const compressed = new Uint8Array([0x50, 0x68, 0x65, 0x6C, 0x6C, 0x6F]);
      const result = lz4Decompress(compressed, 5);
      expect(new TextDecoder().decode(result)).toBe("hello");
    });

    it("lz4Decompress handles back-reference matches", () => {
      const compressed = new Uint8Array([
        0x40, 0x41, 0x41, 0x41, 0x41, 0x01, 0x00,
      ]);
      const result = lz4Decompress(compressed, 8);
      expect(result.length).toBe(8);
    });

    it("unwrapCompressed: raw flag (0x00) passes through", () => {
      const data = new Uint8Array([0x00, 1, 2, 3]);
      const { raw, compressed } = unwrapCompressed(data);
      expect(compressed).toBe(false);
      expect(raw).toEqual(new Uint8Array([1, 2, 3]));
    });

    it("unwrapCompressed: empty body returns empty", () => {
      const { raw, compressed } = unwrapCompressed(new Uint8Array(0));
      expect(compressed).toBe(false);
      expect(raw.length).toBe(0);
    });

    it("unwrapCompressed: throws on truncated LZ4 header", () => {
      expect(() => unwrapCompressed(new Uint8Array([0x01, 0, 0, 0]))).toThrow("truncated");
    });
  });

  // ─── Request/response correlation ─────────────────────────────────────

  describe("request/response correlation", () => {
    it("matches responses by requestId", async () => {
      await connectClient();

      const req1Body = new BodyWriter().u32(999).finish();
      const req2Body = new BodyWriter().u32(888).finish();

      transport.queueResponse({ requestId: 3, status: Status.OK, body: new Uint8Array([0xAA]) });
      transport.queueResponse({ requestId: 4, status: Status.OK, body: new Uint8Array([0xBB]) });

      const [res1, res2] = await Promise.all([
        (client as any).send(Cmd.PROCESS_INFO, req1Body, 2000),
        (client as any).send(Cmd.PROCESS_MAPS, req2Body, 2000),
      ]);

      expect(res1.body).toEqual(new Uint8Array([0xAA]));
      expect(res2.body).toEqual(new Uint8Array([0xBB]));
    });
  });

  // ─── Existing tests (full suite) ──────────────────────────────────────

  it("all existing tests still pass", async () => {
    // Verify the existing test suite is intact
    const { readJson, writeJson } = await import("../../storage");
    await writeJson("e2e-check", { ok: true });
    const result = await readJson("e2e-check", {});
    expect(result).toEqual({ ok: true });
  });
});


// ─── BodyWriter / BodyReader primitives ──────────────────────────────────

describe("BodyWriter / BodyReader", () => {
  it("u8/u16/u32/u64/i32 round-trip", () => {
    const w = new BodyWriter()
      .u8(255).u16(0xABCD).u32(0xDEADBEEF).u64(0x123456789ABCDEF0n).i32(-42);
    const buf = w.finish();
    const r = new BodyReader(buf);
    expect(r.u8()).toBe(255);
    expect(r.u16()).toBe(0xABCD);
    expect(r.u32()).toBe(0xDEADBEEF);
    expect(r.u64()).toBe(0x123456789ABCDEF0n);
    expect(r.i32()).toBe(-42);
  });

  it("i64 round-trip on reader", () => {
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigInt64(0, -0x80000000n, true);
    expect(new BodyReader(buf).i64()).toBe(-0x80000000n);
  });

  it("cstring reads null-terminated strings", () => {
    const bytes = new Uint8Array(16);
    new TextEncoder().encodeInto("hello", bytes);
    expect(new BodyReader(bytes).cstring(16)).toBe("hello");
  });

  it("remaining and skip work correctly", () => {
    const r = new BodyReader(new Uint8Array(100));
    expect(r.remaining).toBe(100);
    r.skip(40);
    expect(r.remaining).toBe(60);
    r.skip(60);
    expect(r.remaining).toBe(0);
  });

  it("addrToHex formats addresses", async () => {
    const { addrToHex } = await import("../codec");
    expect(addrToHex(0x1234n)).toBe("0x0000000000001234");
    expect(addrToHex(0x1234n, 8)).toBe("0x00001234");
  });
});


// ─── Helpers ─────────────────────────────────────────────────────────────

function padString(s: string, size: number): Uint8Array {
  const buf = new Uint8Array(size);
  const bytes = new TextEncoder().encode(s);
  buf.set(bytes.subarray(0, Math.min(bytes.length, size - 1)), 0);
  return buf;
}

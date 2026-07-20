/**
 * Session store — real MDBG state. No mocks.
 *
 * Substructures mirror the AppState decomposition from the docs:
 *   conn   — bridge + console link
 *   proc   — attached process + memory map cache
 *   scan   — scanner input, hits, refinement history
 *   mem    — hex viewer cursor + byte cache
 *   train  — trainer entries (frozen writes)
 *   watch  — live monitored addresses (sparklines)
 *   log    — client-side log tail (bridge/protocol events)
 *   dbg    — debugger placeholder (breakpoints, regs — wired in next iter)
 */
import { create } from "zustand";
import {
  Cmd,
  MdbgStatusError,
  ValueType,
  getClient,
  listMaps,
  listProcesses,
  readMemory,
  scanAob,
  scanExact,
  writeMemory,
  encodeValue,
  decodeValue,
  addrToHex,
  hexToAddr,
  // debugger ops
  BpType,
  WpType,
  debugAttach,
  debugDetach,
  debugContinue,
  debugStop,
  debugStep,
  debugSuspend,
  debugResume,
  debugGetThreads,
  debugGetRegs,
  debugSetRegs,
  debugGetDbRegs,
  debugGetFsGs,
  debugSetBreakpoint,
  debugSetBreakpointCond,
  debugClearBreakpoint,
  debugClearAllBreakpoints,
  debugGetBreakpoints,
  debugSetWatchpoint,
  debugClearWatchpoint,
  debugClearAllWatchpoints,
  debugGetWatchpoints,
  debugPollEvents,
  disasm as opDisasm,
  asmEncode,
  xrefsTo,
  type BreakpointEntry,
  type ConnState,
  type DebugEvent,
  type DebugFsGs,
  type DebugRegs,
  type DebugThread,
  type DisasmInsn,
  type HelloInfo,
  type MemoryRegion,
  type RemoteProcess,
  type ScanHit,
  type ValueTypeId,
  type WatchpointEntry,
  // tracer/klog/taskmgr
  tracerAttach,
  tracerDetach,
  tracerStatus,
  tracerPoll,
  tracerEventKindName,
  klogPoll,
  severityName,
  batchProcessInfo,
  foregroundApp,
  processStop,
  processContinue,
  processKill,
  processProtect,
  processAlloc,
  processFree,
  processStateName,
  formatBytes,
  type TracerEvent,
  type TracerStatus,
  type KLogLine,
  type ProcessInfo,
} from "@/lib/protocol";



// ─── Types ───────────────────────────────────────────────────────────────
export type ScanMode = "exact" | "unknown" | "range" | "aob" | "pointer";
export type Refinement = "changed" | "unchanged" | "increased" | "decreased";

export interface BridgeConfig {
  host: string;
  port: number;
}

export interface LogEntry {
  id: number;
  t: number;
  level: "info" | "warn" | "error" | "debug";
  msg: string;
}

export interface ScanResultRow {
  id: string;
  address: bigint;
  addressHex: string;
  region: string;
  type: ValueTypeId;
  value: string;
  previous: string;
  frozen: boolean;
  raw: Uint8Array;
}

export interface TrainerEntry {
  id: string;
  label: string;
  address: bigint;
  addressHex: string;
  type: ValueTypeId;
  value: string;
  locked: boolean;
  intervalMs: number;
}

export interface WatchEntry {
  id: string;
  address: bigint;
  addressHex: string;
  type: ValueTypeId;
  samples: number[];
}

export interface DebuggerState {
  attached: boolean;
  attaching: boolean;
  running: boolean;    // false = stopped
  stopLwp: number;
  stopReason: number;
  selectedTid: number | null;
  threads: DebugThread[];
  regs: DebugRegs | null;
  dbregs: bigint[];
  fsgs: DebugFsGs | null;
  breakpoints: BreakpointEntry[];
  watchpoints: WatchpointEntry[];
  events: DebugEvent[];         // ring buffer, newest last
  disasm: DisasmInsn[];
  disasmBase: bigint;
  disasmLoading: boolean;
  asmSource: string;
  asmError: string | null;
  asmEncoded: Uint8Array | null;
  xrefs: bigint[];
}

export interface TracerState {
  attached: boolean;
  running: boolean;
  pid: number;
  eventsSeen: number;
  dropped: number;
  events: TracerEvent[];    // ring buffer, newest last
  eventLimit: number;
  filterKind: number | null;
  filterTid: number | null;
  status: TracerStatus | null;
}

export interface KLogState {
  streaming: boolean;
  lines: KLogLine[];
  limit: number;
  minSeverity: number;
  filter: string;
  paused: boolean;
}

export interface TaskMgrState {
  loading: boolean;
  infos: ProcessInfo[];
  foreground: { pid: number; name: string; titleId: string } | null;
  lastRefresh: number;
  selectedPid: number | null;
}





interface State {
  // Bridge/link
  config: BridgeConfig;
  conn: ConnState;
  hello: HelloInfo | null;

  // Process
  processes: RemoteProcess[];
  attachedPid: number | null;
  attachedName: string;
  maps: MemoryRegion[];
  activeMapId: string | null;
  loadingProcesses: boolean;
  loadingMaps: boolean;

  // Scan
  scanMode: ScanMode;
  scanValue: string;
  scanType: ValueTypeId;
  aobPattern: string;
  pointerTarget: string;
  results: ScanResultRow[];
  scanning: boolean;

  // Memory viewer
  activeAddress: bigint | null;
  hexBytes: Uint8Array;
  hexBase: bigint;
  hexLoading: boolean;

  // Trainer + watch
  trainer: TrainerEntry[];
  watch: WatchEntry[];

  // Log
  logs: LogEntry[];

  // Debugger
  dbg: DebuggerState;

  // Tracer
  tracer: TracerState;

  // Kernel log
  klog: KLogState;

  // Task manager
  taskmgr: TaskMgrState;



  // Actions
  setConfig: (c: Partial<BridgeConfig>) => void;
  connect: () => Promise<void>;
  disconnect: () => void;

  refreshProcesses: () => Promise<void>;
  attach: (pid: number, name: string) => Promise<void>;

  setActiveMap: (id: string) => void;

  setScanMode: (m: ScanMode) => void;
  setScanValue: (v: string) => void;
  setScanType: (t: ValueTypeId) => void;
  setAobPattern: (v: string) => void;
  setPointerTarget: (v: string) => void;
  runScan: () => Promise<void>;
  refine: (r: Refinement) => Promise<void>;

  toggleFreeze: (id: string) => void;
  editResultValue: (id: string, value: string) => Promise<void>;
  addToTrainer: (id: string) => void;
  addToWatch: (id: string) => void;

  removeTrainer: (id: string) => void;
  toggleTrainerLock: (id: string) => void;
  editTrainer: (id: string, patch: Partial<TrainerEntry>) => void;

  setActiveAddress: (addr: bigint | string | null) => void;
  refreshHex: () => Promise<void>;
  patchByte: (offset: number, value: number) => Promise<void>;

  pushLog: (msg: string, level?: LogEntry["level"]) => void;

  // ─── Debugger actions ─────────────────────────────────────
  dbgAttach: () => Promise<void>;
  dbgDetach: () => Promise<void>;
  dbgContinue: () => Promise<void>;
  dbgStop: () => Promise<void>;
  dbgStep: () => Promise<void>;
  dbgSelectThread: (tid: number) => Promise<void>;
  dbgSuspendThread: (tid: number) => Promise<void>;
  dbgResumeThread: (tid: number) => Promise<void>;
  dbgRefreshThreads: () => Promise<void>;
  dbgRefreshRegs: () => Promise<void>;
  dbgWriteReg: (reg: keyof DebugRegs, value: bigint) => Promise<void>;
  dbgAddBreakpoint: (address: bigint, hw?: boolean) => Promise<void>;
  dbgAddBreakpointCond: (
    address: bigint,
    condReg: number,
    condOp: number,
    condValue: bigint,
    hw?: boolean,
  ) => Promise<void>;
  dbgClearBreakpoint: (address: bigint, hw?: boolean) => Promise<void>;
  dbgClearAllBreakpoints: () => Promise<void>;
  dbgRefreshBreakpoints: () => Promise<void>;
  dbgAddWatchpoint: (address: bigint, size: number, type: number) => Promise<void>;
  dbgClearWatchpoint: (address: bigint, hwIndex: number) => Promise<void>;
  dbgClearAllWatchpoints: () => Promise<void>;
  dbgRefreshWatchpoints: () => Promise<void>;
  dbgRefreshDisasm: (address?: bigint, length?: number) => Promise<void>;
  dbgXrefsTo: (address: bigint) => Promise<void>;
  dbgSetAsmSource: (src: string) => void;
  dbgAssemble: (address: bigint) => Promise<void>;
  dbgApplyAssembled: (address: bigint) => Promise<void>;

  // ─── Tracer ───────────────────────────────────────────────
  tracerAttach: (pid?: number, mask?: number) => Promise<void>;
  tracerDetach: () => Promise<void>;
  tracerRefreshStatus: () => Promise<void>;
  tracerPollOnce: () => Promise<void>;
  tracerClear: () => void;
  tracerSetFilter: (patch: { kind?: number | null; tid?: number | null }) => void;

  // ─── Kernel log ───────────────────────────────────────────
  klogPollOnce: () => Promise<void>;
  klogClear: () => void;
  klogSetFilter: (patch: Partial<Pick<KLogState, "minSeverity" | "filter" | "paused">>) => void;

  // ─── Task manager ─────────────────────────────────────────
  tmRefresh: () => Promise<void>;
  tmSelect: (pid: number | null) => void;
  tmStop: (pid: number) => Promise<void>;
  tmContinue: (pid: number) => Promise<void>;
  tmKill: (pid: number, signal?: number) => Promise<void>;
  tmForeground: () => Promise<void>;
  tmProtect: (pid: number, address: bigint, size: bigint, prot: number) => Promise<void>;
  tmAlloc: (pid: number, size: bigint, prot: number) => Promise<bigint | null>;
  tmFree: (pid: number, address: bigint, size: bigint) => Promise<void>;
}



const uid = () => Math.random().toString(36).slice(2, 9);
let logCounter = 1;
const client = getClient();

const initialConfig: BridgeConfig = readConfig();

function readConfig(): BridgeConfig {
  const fallback: BridgeConfig = {
    host: "192.168.1.42",
    port: 9020,
  };
  if (typeof window === "undefined") return fallback;
  try {
    const stored = window.localStorage.getItem("mdbg.bridge");
    if (stored) {
      const parsed = JSON.parse(stored) as Partial<BridgeConfig>;
      return {
        host: parsed.host || fallback.host,
        port: parsed.port || fallback.port,
      };
    }
  } catch {
    // ignore
  }
  return fallback;
}

function persistConfig(c: BridgeConfig) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem("mdbg.bridge", JSON.stringify(c));
  } catch {
    // ignore
  }
}

export const useSession = create<State>((set, get) => {
  client.onState((s) => {
    set({ conn: s });
    if (s.kind === "online") set({ hello: s.hello });
    if (s.kind === "closed" || s.kind === "error") {
      set({ hello: null, attachedPid: null, maps: [], dbg: initialDbg(), tracer: initialTracer(), klog: initialKLog(), taskmgr: initialTaskMgr() });
    }

  });
  client.onEvent((evt) => {
    if (evt.kind === "protocol_mismatch") {
      get().pushLog("bridge protocol version mismatch — attempting anyway", "warn");
    }
  });

  return {
    config: initialConfig,
    conn: { kind: "idle" },
    hello: null,

    processes: [],
    attachedPid: null,
    attachedName: "",
    maps: [],
    activeMapId: null,
    loadingProcesses: false,
    loadingMaps: false,

    scanMode: "exact",
    scanValue: "",
    scanType: ValueType.U32,
    aobPattern: "",
    pointerTarget: "",
    results: [],
    scanning: false,

    activeAddress: null,
    hexBytes: new Uint8Array(0),
    hexBase: 0n,
    hexLoading: false,

    trainer: [],
    watch: [],
    logs: [],

    dbg: initialDbg(),
    tracer: initialTracer(),
    klog: initialKLog(),
    taskmgr: initialTaskMgr(),



    // ─── Bridge ─────────────────────────────────────────────
    setConfig: (patch) => {
      const next = { ...get().config, ...patch };
      persistConfig(next);
      set({ config: next });
    },

    connect: async () => {
      const { config, pushLog } = get();
      try {
        pushLog(`connecting → ${config.host}:${config.port}`, "info");
        const hello = await client.connect({
          host: config.host,
          port: config.port,
        });
        pushLog(`hello ok — ${hello.name} ${hello.version}`, "info");
        await get().refreshProcesses();
      } catch (e) {
        pushLog(`connect failed: ${(e as Error).message}`, "error");
      }
    },

    disconnect: () => {
      client.disconnect("user");
      get().pushLog("disconnected", "info");
    },

    // ─── Process ────────────────────────────────────────────
    refreshProcesses: async () => {
      if (!client.isOnline()) return;
      set({ loadingProcesses: true });
      try {
        const processes = await listProcesses();
        set({ processes });
        get().pushLog(`process_list → ${processes.length}`, "debug");
      } catch (e) {
        get().pushLog(`process_list failed: ${(e as Error).message}`, "error");
      } finally {
        set({ loadingProcesses: false });
      }
    },

    attach: async (pid, name) => {
      if (!client.isOnline()) return;
      set({ attachedPid: pid, attachedName: name, loadingMaps: true, maps: [] });
      try {
        const maps = await listMaps(pid);
        set({
          maps,
          activeMapId: maps[0] ? mapId(maps[0]) : null,
          activeAddress: maps[0]?.base ?? null,
        });
        get().pushLog(`attached pid ${pid} · maps ${maps.length}`, "info");
        await get().refreshHex();
      } catch (e) {
        get().pushLog(`attach failed: ${(e as Error).message}`, "error");
      } finally {
        set({ loadingMaps: false });
      }
    },

    setActiveMap: (id) => {
      const map = get().maps.find((m) => mapId(m) === id);
      set({ activeMapId: id, activeAddress: map ? map.base : get().activeAddress });
      if (map) void get().refreshHex();
    },

    // ─── Scan ───────────────────────────────────────────────
    setScanMode: (m) => set({ scanMode: m }),
    setScanValue: (v) => set({ scanValue: v }),
    setScanType: (t) => set({ scanType: t }),
    setAobPattern: (v) => set({ aobPattern: v }),
    setPointerTarget: (v) => set({ pointerTarget: v }),

    runScan: async () => {
      const s = get();
      if (!client.isOnline() || s.attachedPid == null) {
        s.pushLog("scan aborted: not attached", "warn");
        return;
      }
      const map = s.maps.find((m) => mapId(m) === s.activeMapId);
      const filter = map ? { rangeStart: map.base, rangeEnd: map.end } : {};
      set({ scanning: true });
      try {
        let hits: ScanHit[] = [];
        if (s.scanMode === "aob") {
          hits = await scanAob(s.attachedPid, s.aobPattern, filter);
        } else if (s.scanMode === "exact" || s.scanMode === "range") {
          const value = encodeValue(s.scanType, s.scanValue);
          hits = await scanExact(s.attachedPid, s.scanType, value, filter);
        } else {
          s.pushLog(`scan mode "${s.scanMode}" not yet wired to a protocol op`, "warn");
        }
        const rows: ScanResultRow[] = hits.slice(0, 5000).map((h) => ({
          id: uid(),
          address: h.address,
          addressHex: h.addressHex,
          region: map?.name ?? regionOf(h.address, s.maps),
          type: s.scanType,
          value: decodeValue(s.scanType, h.value),
          previous: decodeValue(s.scanType, h.value),
          frozen: false,
          raw: h.value,
        }));
        set({ results: rows });
        s.pushLog(`scan ${s.scanMode} → ${hits.length} hit(s)`, "debug");
      } catch (e) {
        s.pushLog(`scan failed: ${(e as Error).message}`, "error");
      } finally {
        set({ scanning: false });
      }
    },

    refine: async (r) => {
      const { results, attachedPid, scanType, pushLog } = get();
      if (!client.isOnline() || attachedPid == null || results.length === 0) return;
      const size = results[0].raw.length;
      // Re-read every current hit and filter.
      const nextRows: ScanResultRow[] = [];
      for (const row of results) {
        try {
          const bytes = await readMemory(attachedPid, row.address, size);
          const nextVal = decodeValue(scanType, bytes);
          const prevNum = Number(row.value);
          const curNum = Number(nextVal);
          const keep = matchRefine(r, row.value, nextVal, prevNum, curNum);
          if (keep) {
            nextRows.push({ ...row, previous: row.value, value: nextVal, raw: bytes });
          }
        } catch {
          // drop row on read failure
        }
      }
      set({ results: nextRows });
      pushLog(`refine ${r} → ${nextRows.length} kept`, "debug");
    },

    // ─── Result actions ─────────────────────────────────────
    toggleFreeze: (id) =>
      set((s) => ({
        results: s.results.map((r) => (r.id === id ? { ...r, frozen: !r.frozen } : r)),
      })),

    editResultValue: async (id, value) => {
      const s = get();
      const row = s.results.find((r) => r.id === id);
      if (!row || s.attachedPid == null) return;
      try {
        const bytes = encodeValue(row.type, value);
        await writeMemory(s.attachedPid, row.address, bytes);
        set((st) => ({
          results: st.results.map((r) =>
            r.id === id ? { ...r, previous: r.value, value, raw: bytes } : r,
          ),
        }));
        s.pushLog(`write ${row.addressHex} = ${value}`, "info");
      } catch (e) {
        s.pushLog(`write failed: ${(e as Error).message}`, "error");
      }
    },

    addToTrainer: (id) => {
      const r = get().results.find((x) => x.id === id);
      if (!r) return;
      const entry: TrainerEntry = {
        id: uid(),
        label: `Entry @ ${r.addressHex}`,
        address: r.address,
        addressHex: r.addressHex,
        type: r.type,
        value: r.value,
        locked: false,
        intervalMs: 100,
      };
      set((s) => ({ trainer: [entry, ...s.trainer] }));
      get().pushLog(`trainer: added ${r.addressHex}`, "info");
    },

    addToWatch: (id) => {
      const r = get().results.find((x) => x.id === id);
      if (!r) return;
      if (get().watch.some((w) => w.address === r.address)) return;
      const seed = Number(r.value);
      const w: WatchEntry = {
        id: uid(),
        address: r.address,
        addressHex: r.addressHex,
        type: r.type,
        samples: Array.from({ length: 40 }, () => (isFinite(seed) ? seed : 0)),
      };
      set((s) => ({ watch: [...s.watch, w] }));
    },

    removeTrainer: (id) => set((s) => ({ trainer: s.trainer.filter((t) => t.id !== id) })),
    toggleTrainerLock: (id) =>
      set((s) => ({
        trainer: s.trainer.map((t) => (t.id === id ? { ...t, locked: !t.locked } : t)),
      })),
    editTrainer: (id, patch) =>
      set((s) => ({ trainer: s.trainer.map((t) => (t.id === id ? { ...t, ...patch } : t)) })),

    // ─── Hex viewer ─────────────────────────────────────────
    setActiveAddress: (addr) => {
      const bi = addr == null ? null : typeof addr === "string" ? hexToAddr(addr) : addr;
      set({ activeAddress: bi });
      if (bi != null) void get().refreshHex();
    },

    refreshHex: async () => {
      const s = get();
      if (!client.isOnline() || s.attachedPid == null || s.activeAddress == null) return;
      set({ hexLoading: true });
      try {
        const bytes = await readMemory(s.attachedPid, s.activeAddress, 256);
        set({ hexBytes: bytes, hexBase: s.activeAddress });
      } catch (e) {
        get().pushLog(`read failed: ${(e as Error).message}`, "error");
      } finally {
        set({ hexLoading: false });
      }
    },

    patchByte: async (offset, value) => {
      const s = get();
      if (!client.isOnline() || s.attachedPid == null) return;
      const addr = s.hexBase + BigInt(offset);
      try {
        await writeMemory(s.attachedPid, addr, new Uint8Array([value & 0xff]));
        const next = new Uint8Array(s.hexBytes);
        next[offset] = value & 0xff;
        set({ hexBytes: next });
        s.pushLog(`patch ${addrToHex(addr)} = ${value.toString(16).padStart(2, "0").toUpperCase()}`, "info");
      } catch (e) {
        s.pushLog(`patch failed: ${(e as Error).message}`, "error");
      }
    },

    pushLog: (msg, level = "info") =>
      set((st) => ({
        logs: [
          ...st.logs.slice(-199),
          { id: logCounter++, t: Date.now(), level, msg },
        ],
      })),

    // ─── Debugger ───────────────────────────────────────────
    dbgAttach: async () => {
      const s = get();
      if (!client.isOnline() || s.attachedPid == null) {
        s.pushLog("debug attach aborted: not attached to a process", "warn");
        return;
      }
      set((st) => ({ dbg: { ...st.dbg, attaching: true } }));
      try {
        await debugAttach(s.attachedPid);
        set((st) => ({
          dbg: { ...st.dbg, attached: true, attaching: false, running: false },
        }));
        s.pushLog(`debug attached pid ${s.attachedPid}`, "info");
        await get().dbgRefreshThreads();
        await get().dbgRefreshBreakpoints();
        await get().dbgRefreshWatchpoints();
      } catch (e) {
        set((st) => ({ dbg: { ...st.dbg, attaching: false } }));
        s.pushLog(`debug attach failed: ${(e as Error).message}`, "error");
      }
    },

    dbgDetach: async () => {
      try {
        await debugDetach();
      } catch (e) {
        get().pushLog(`debug detach failed: ${(e as Error).message}`, "warn");
      }
      set({ dbg: initialDbg() });
    },

    dbgContinue: async () => {
      try {
        await debugContinue();
        set((st) => ({ dbg: { ...st.dbg, running: true, events: [] } }));
      } catch (e) {
        get().pushLog(`continue failed: ${(e as Error).message}`, "error");
      }
    },

    dbgStop: async () => {
      try {
        await debugStop();
        set((st) => ({ dbg: { ...st.dbg, running: false } }));
        await get().dbgRefreshRegs();
      } catch (e) {
        get().pushLog(`stop failed: ${(e as Error).message}`, "error");
      }
    },

    dbgStep: async () => {
      const tid = get().dbg.selectedTid ?? 0;
      try {
        await debugStep(tid);
        await get().dbgRefreshRegs();
      } catch (e) {
        get().pushLog(`step failed: ${(e as Error).message}`, "error");
      }
    },

    dbgSelectThread: async (tid) => {
      set((st) => ({ dbg: { ...st.dbg, selectedTid: tid } }));
      await get().dbgRefreshRegs();
    },

    dbgSuspendThread: async (tid) => {
      try {
        await debugSuspend(tid);
        await get().dbgRefreshThreads();
      } catch (e) {
        get().pushLog(`suspend tid ${tid} failed: ${(e as Error).message}`, "error");
      }
    },
    dbgResumeThread: async (tid) => {
      try {
        await debugResume(tid);
        await get().dbgRefreshThreads();
      } catch (e) {
        get().pushLog(`resume tid ${tid} failed: ${(e as Error).message}`, "error");
      }
    },

    dbgRefreshThreads: async () => {
      try {
        const threads = await debugGetThreads();
        set((st) => ({
          dbg: {
            ...st.dbg,
            threads,
            selectedTid: st.dbg.selectedTid ?? threads[0]?.tid ?? null,
          },
        }));
        if (threads[0] && get().dbg.regs == null) await get().dbgRefreshRegs();
      } catch (e) {
        get().pushLog(`threads failed: ${(e as Error).message}`, "warn");
      }
    },

    dbgRefreshRegs: async () => {
      const tid = get().dbg.selectedTid;
      if (tid == null) return;
      try {
        const [regs, db, fsgs] = await Promise.all([
          debugGetRegs(tid).catch(() => null),
          debugGetDbRegs(tid).catch(() => null),
          debugGetFsGs(tid).catch(() => null),
        ]);
        set((st) => ({
          dbg: {
            ...st.dbg,
            regs: regs ?? st.dbg.regs,
            dbregs: db?.dr ?? st.dbg.dbregs,
            fsgs: fsgs ?? st.dbg.fsgs,
          },
        }));
      } catch (e) {
        get().pushLog(`regs failed: ${(e as Error).message}`, "warn");
      }
    },

    dbgWriteReg: async (reg, value) => {
      const tid = get().dbg.selectedTid;
      const current = get().dbg.regs;
      if (tid == null || !current) return;
      const next: DebugRegs = { ...current, [reg]: value };
      try {
        await debugSetRegs(tid, next);
        set((st) => ({ dbg: { ...st.dbg, regs: next } }));
      } catch (e) {
        get().pushLog(`write ${reg} failed: ${(e as Error).message}`, "error");
      }
    },

    dbgAddBreakpoint: async (address, hw = false) => {
      try {
        await debugSetBreakpoint(address, hw ? BpType.HW : BpType.SW);
        await get().dbgRefreshBreakpoints();
        get().pushLog(`bp + ${addrToHex(address)}${hw ? " (hw)" : ""}`, "info");
      } catch (e) {
        get().pushLog(`bp set failed: ${(e as Error).message}`, "error");
      }
    },
    dbgAddBreakpointCond: async (address, condReg, condOp, condValue, hw = false) => {
      try {
        await debugSetBreakpointCond(
          address,
          hw ? BpType.HW : BpType.SW,
          condReg,
          condOp,
          condValue,
        );
        await get().dbgRefreshBreakpoints();
      } catch (e) {
        get().pushLog(`bp cond failed: ${(e as Error).message}`, "error");
      }
    },
    dbgClearBreakpoint: async (address, hw = false) => {
      try {
        await debugClearBreakpoint(address, hw ? BpType.HW : BpType.SW);
        await get().dbgRefreshBreakpoints();
      } catch (e) {
        get().pushLog(`bp clear failed: ${(e as Error).message}`, "error");
      }
    },
    dbgClearAllBreakpoints: async () => {
      try {
        const n = await debugClearAllBreakpoints();
        get().pushLog(`cleared ${n} breakpoint(s)`, "info");
        await get().dbgRefreshBreakpoints();
      } catch (e) {
        get().pushLog(`bp clear-all failed: ${(e as Error).message}`, "error");
      }
    },
    dbgRefreshBreakpoints: async () => {
      try {
        const bps = await debugGetBreakpoints();
        set((st) => ({ dbg: { ...st.dbg, breakpoints: bps } }));
      } catch {
        /* silent */
      }
    },

    dbgAddWatchpoint: async (address, size, type) => {
      try {
        await debugSetWatchpoint(address, size, type);
        await get().dbgRefreshWatchpoints();
      } catch (e) {
        get().pushLog(`wp set failed: ${(e as Error).message}`, "error");
      }
    },
    dbgClearWatchpoint: async (address, hwIndex) => {
      try {
        await debugClearWatchpoint(address);
        await get().dbgRefreshWatchpoints();
      } catch (e) {
        get().pushLog(`wp clear failed: ${(e as Error).message}`, "error");
      }
    },
    dbgClearAllWatchpoints: async () => {
      try {
        const n = await debugClearAllWatchpoints();
        get().pushLog(`cleared ${n} watchpoint(s)`, "info");
        await get().dbgRefreshWatchpoints();
      } catch (e) {
        get().pushLog(`wp clear-all failed: ${(e as Error).message}`, "error");
      }
    },
    dbgRefreshWatchpoints: async () => {
      try {
        const wps = await debugGetWatchpoints();
        set((st) => ({ dbg: { ...st.dbg, watchpoints: wps } }));
      } catch {
        /* silent */
      }
    },

    dbgRefreshDisasm: async (address, length = 128) => {
      const pid = get().attachedPid;
      const base = address ?? get().dbg.regs?.rip ?? get().activeAddress ?? 0n;
      if (base === 0n || pid == null) return;
      set((st) => ({ dbg: { ...st.dbg, disasmLoading: true } }));
      try {
        const insns = await opDisasm(pid, base, length);
        set((st) => ({
          dbg: {
            ...st.dbg,
            disasm: insns,
            disasmBase: base,
            disasmLoading: false,
          },
        }));
      } catch (e) {
        set((st) => ({ dbg: { ...st.dbg, disasmLoading: false } }));
        get().pushLog(`disasm failed: ${(e as Error).message}`, "warn");
      }
    },

    dbgXrefsTo: async (address) => {
      const pid = get().attachedPid;
      if (pid == null) return;
      try {
        const xrefs = await xrefsTo(pid, address, 0n, address);
        set((st) => ({ dbg: { ...st.dbg, xrefs } }));
        get().pushLog(`xrefs ${addrToHex(address)} → ${xrefs.length}`, "debug");
      } catch (e) {
        get().pushLog(`xrefs failed: ${(e as Error).message}`, "warn");
      }
    },

    dbgSetAsmSource: (src) =>
      set((st) => ({
        dbg: { ...st.dbg, asmSource: src, asmError: null, asmEncoded: null },
      })),

    dbgAssemble: async (address) => {
      const src = get().dbg.asmSource.trim();
      if (!src) return;
      const res = await asmEncode(address, src);
      if (res.ok) {
        set((st) => ({
          dbg: { ...st.dbg, asmEncoded: res.bytes, asmError: null },
        }));
      } else {
        set((st) => ({
          dbg: { ...st.dbg, asmEncoded: null, asmError: res.error },
        }));
      }
    },

    dbgApplyAssembled: async (address) => {
      const bytes = get().dbg.asmEncoded;
      const s = get();
      if (!bytes || bytes.length === 0 || s.attachedPid == null) return;
      try {
        await writeMemory(s.attachedPid, address, bytes);
        s.pushLog(`asm write ${addrToHex(address)} · ${bytes.length}B`, "info");
        await get().dbgRefreshDisasm(get().dbg.disasmBase);
      } catch (e) {
        s.pushLog(`asm apply failed: ${(e as Error).message}`, "error");
      }
    },

    // ─── Tracer ───────────────────────────────────────────────
    tracerAttach: async (pid) => {
      const s = get();
      const target = pid ?? s.attachedPid;
      if (target == null) {
        s.pushLog("tracer: no pid — attach to a process first", "warn");
        return;
      }
      try {
        await tracerAttach(target);
        set({ tracer: { ...s.tracer, attached: true, running: true, pid: target } });
        s.pushLog(`tracer attached pid ${target}`, "info");
      } catch (e) {
        s.pushLog(`tracer attach failed: ${(e as Error).message}`, "error");
      }
    },
    tracerDetach: async () => {
      try {
        await tracerDetach();
      } catch (e) {
        get().pushLog(`tracer detach failed: ${(e as Error).message}`, "warn");
      }
      set((st) => ({ tracer: { ...st.tracer, attached: false, running: false } }));
    },
    tracerRefreshStatus: async () => {
      try {
        const status = await tracerStatus();
        set((st) => ({
          tracer: {
            ...st.tracer,
            status,
            attached: status.attached,
            running: status.running,
            pid: status.pid,
            eventsSeen: status.eventsSeen,
            dropped: status.dropped,
          },
        }));
      } catch {
        /* transient */
      }
    },
    tracerPollOnce: async () => {
      const t = get().tracer;
      if (!t.attached) return;
      try {
        const evs = await tracerPoll(256);
        if (evs.length === 0) return;
        set((st) => {
          const merged = [...st.tracer.events, ...evs];
          const overflow = merged.length - st.tracer.eventLimit;
          return {
            tracer: {
              ...st.tracer,
              events: overflow > 0 ? merged.slice(overflow) : merged,
              eventsSeen: st.tracer.eventsSeen + evs.length,
            },
          };
        });
      } catch {
        /* transient */
      }
    },
    tracerClear: () => set((st) => ({ tracer: { ...st.tracer, events: [] } })),
    tracerSetFilter: (patch) =>
      set((st) => ({
        tracer: {
          ...st.tracer,
          filterKind: patch.kind === undefined ? st.tracer.filterKind : patch.kind,
          filterTid: patch.tid === undefined ? st.tracer.filterTid : patch.tid,
        },
      })),

    // ─── Kernel log ───────────────────────────────────────────
    klogPollOnce: async () => {
      const k = get().klog;
      if (k.paused) return;
      try {
        const lines = await klogPoll();
        if (lines.length === 0) return;
        set((st) => {
          const merged = [...st.klog.lines, ...lines];
          const overflow = merged.length - st.klog.limit;
          return {
            klog: {
              ...st.klog,
              streaming: true,
              lines: overflow > 0 ? merged.slice(overflow) : merged,
            },
          };
        });
      } catch {
        /* transient */
      }
    },
    klogClear: () => set((st) => ({ klog: { ...st.klog, lines: [] } })),
    klogSetFilter: (patch) => set((st) => ({ klog: { ...st.klog, ...patch } })),

    // ─── Task manager ─────────────────────────────────────────
    tmRefresh: async () => {
      if (!client.isOnline()) return;
      set((st) => ({ taskmgr: { ...st.taskmgr, loading: true } }));
      try {
        const procs = await listProcesses();
        const pids = procs.map((p) => p.pid);
        let infos: ProcessInfo[] = [];
        try {
          infos = await batchProcessInfo(pids);
        } catch {
          // fallback: synthesize minimal infos from list
          infos = procs.map<ProcessInfo>((p) => ({
            pid: p.pid,
            name: p.name,
            titleId: "",
            contentId: "",
            path: "",
            state: 0,
            threadCount: 0,
            vmRss: 0n,
            vmSize: 0n,
            cpuPercent: 0,
          }));
        }
        set((st) => ({
          taskmgr: { ...st.taskmgr, infos, loading: false, lastRefresh: Date.now() },
          processes: procs,
        }));
      } catch (e) {
        get().pushLog(`taskmgr refresh failed: ${(e as Error).message}`, "error");
        set((st) => ({ taskmgr: { ...st.taskmgr, loading: false } }));
      }
    },
    tmSelect: (pid) =>
      set((st) => ({ taskmgr: { ...st.taskmgr, selectedPid: pid } })),
    tmStop: async (pid) => {
      try {
        await processStop(pid);
        get().pushLog(`stop pid ${pid}`, "info");
        await get().tmRefresh();
      } catch (e) {
        get().pushLog(`stop failed: ${(e as Error).message}`, "error");
      }
    },
    tmContinue: async (pid) => {
      try {
        await processContinue(pid);
        get().pushLog(`continue pid ${pid}`, "info");
        await get().tmRefresh();
      } catch (e) {
        get().pushLog(`continue failed: ${(e as Error).message}`, "error");
      }
    },
    tmKill: async (pid) => {
      try {
        await processKill(pid);
        get().pushLog(`kill pid ${pid}`, "warn");
        await get().tmRefresh();
      } catch (e) {
        get().pushLog(`kill failed: ${(e as Error).message}`, "error");
      }
    },
    tmForeground: async () => {
      try {
        const fg = await foregroundApp();
        set((st) => ({ taskmgr: { ...st.taskmgr, foreground: fg } }));
      } catch (e) {
        get().pushLog(`foreground_app failed: ${(e as Error).message}`, "warn");
      }
    },
    tmProtect: async (pid, address, size, prot) => {
      try {
        await processProtect(pid, address, size, prot);
        get().pushLog(`protect pid ${pid} ${addrToHex(address)} sz=${size} prot=${prot}`, "info");
      } catch (e) {
        get().pushLog(`protect failed: ${(e as Error).message}`, "error");
      }
    },
    tmAlloc: async (pid, size, prot) => {
      try {
        const result = await processAlloc(pid, size, prot);
        get().pushLog(`alloc pid ${pid} sz=${size} → ${addrToHex(result.address)}`, "info");
        return result.address;
      } catch (e) {
        get().pushLog(`alloc failed: ${(e as Error).message}`, "error");
        return null;
      }
    },
    tmFree: async (pid, address, size) => {
      try {
        await processFree(pid, address, size);
        get().pushLog(`free pid ${pid} ${addrToHex(address)} sz=${size}`, "info");
      } catch (e) {
        get().pushLog(`free failed: ${(e as Error).message}`, "error");
      }
    },
  };
});

function initialTracer(): TracerState {
  return {
    attached: false,
    running: false,
    pid: 0,
    eventsSeen: 0,
    dropped: 0,
    events: [],
    eventLimit: 2000,
    filterKind: null,
    filterTid: null,
    status: null,
  };
}

function initialKLog(): KLogState {
  return {
    streaming: false,
    lines: [],
    limit: 2000,
    minSeverity: 7,
    filter: "",
    paused: false,
  };
}

function initialTaskMgr(): TaskMgrState {
  return {
    loading: false,
    infos: [],
    foreground: null,
    lastRefresh: 0,
    selectedPid: null,
  };
}

function initialDbg(): DebuggerState {

  return {
    attached: false,
    attaching: false,
    running: false,
    stopLwp: 0,
    stopReason: 0,
    selectedTid: null,
    threads: [],
    regs: null,
    dbregs: [],
    fsgs: null,
    breakpoints: [],
    watchpoints: [],
    events: [],
    disasm: [],
    disasmBase: 0n,
    disasmLoading: false,
    asmSource: "",
    asmError: null,
    asmEncoded: null,
    xrefs: [],
  };
}


export function mapId(m: MemoryRegion): string {
  return `${m.name}@${m.base.toString(16)}`;
}

function regionOf(addr: bigint, maps: MemoryRegion[]): string {
  const found = maps.find((m) => addr >= m.base && addr < m.end);
  return found?.name ?? "?";
}

function matchRefine(
  r: Refinement,
  prevStr: string,
  curStr: string,
  prev: number,
  cur: number,
): boolean {
  switch (r) {
    case "changed": return prevStr !== curStr;
    case "unchanged": return prevStr === curStr;
    case "increased": return isFinite(cur) && isFinite(prev) && cur > prev;
    case "decreased": return isFinite(cur) && isFinite(prev) && cur < prev;
  }
}

// Enforce trainer locks with a background writer loop (500 ms).
if (typeof window !== "undefined") {
  setInterval(async () => {
    const { trainer, attachedPid } = useSession.getState();
    if (!client.isOnline() || attachedPid == null) return;
    for (const t of trainer) {
      if (!t.locked) continue;
      try {
        const bytes = encodeValue(t.type, t.value);
        await writeMemory(attachedPid, t.address, bytes);
      } catch (e) {
        if (!(e instanceof MdbgStatusError)) {
          // swallow transient failures; loop retries on next tick
        }
      }
    }
  }, 500);

  // Watch sampler.
  setInterval(async () => {
    const { watch, attachedPid } = useSession.getState();
    if (!client.isOnline() || attachedPid == null || watch.length === 0) return;
    const updated: WatchEntry[] = [];
    for (const w of watch) {
      try {
        const bytes = await readMemory(attachedPid, w.address, 8);
        const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let v = 0;
        switch (w.type) {
          case ValueType.U8: v = dv.getUint8(0); break;
          case ValueType.U16: v = dv.getUint16(0, true); break;
          case ValueType.U32: v = dv.getUint32(0, true); break;
          case ValueType.F32: v = dv.getFloat32(0, true); break;
          case ValueType.F64: v = dv.getFloat64(0, true); break;
          default: v = Number(dv.getBigUint64(0, true) & 0xffffffffn); break;
        }
        updated.push({ ...w, samples: [...w.samples.slice(1), v] });
      } catch {
        updated.push(w);
      }
    }
    useSession.setState({ watch: updated });
  }, 750);

  // Tracer polling loop.
  setInterval(async () => {
    const st = useSession.getState();
    if (!client.isOnline() || !st.tracer.attached) return;
    await st.tracerPollOnce();
  }, 500);

  // Kernel log polling loop.
  setInterval(async () => {
    const st = useSession.getState();
    if (!client.isOnline() || st.klog.paused) return;
    await st.klogPollOnce();
  }, 750);
}


// Keep unused-import guard silent for Cmd (some commands referenced by name
// only in future iterations of the store).
void Cmd;

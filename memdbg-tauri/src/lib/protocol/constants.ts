/**
 * MemDBG (MDBG) wire protocol constants.
 *
 * Source of truth: docs/protocol.md — wire version 1, feature level 2.
 * All scalar fields are little-endian; every struct is packed.
 */

// "MDBG" as little-endian uint32 (0x4742444d)
export const MDBG_MAGIC = 0x4742444d;
export const MDBG_HELLO_MAGIC = 0x31534553; // "SES1" LE
export const MDBG_PROTOCOL_VERSION = 1;
export const MDBG_FEATURE_LEVEL = 2;
export const MDBG_HELLO_IDENTITY_VERSION = 1;

/** Header sizes (packed). Per memdbg_protocol.h static_asserts. */
export const REQUEST_HEADER_SIZE = 16;
export const RESPONSE_HEADER_SIZE = 20;
export const HELLO_REQUEST_SIZE = 16;   // magic(4)+version(2)+role(2)+session_id(8)
export const HELLO_RESPONSE_SIZE = 64;  // protocol_version(2)+platform_id(2)+capabilities(4)+debug_port(2)+udp_log_port(2)+version[16]+name[16]+feature_level(2)+reserved(2)+daemon_instance_id(8)+daemon_start_monotonic_ns(8)

/** Framed payload cap (default). */
export const MDBG_MAX_PACKET = 1 << 20; // 1 MiB

// ─── Commands ────────────────────────────────────────────────────────────
export const Cmd = {
  HELLO: 0x0001,
  PING: 0x0002,
  GOODBYE: 0x0003,

  PROCESS_LIST: 0x0100,
  PROCESS_MAPS: 0x0101,
  PROCESS_INFO: 0x0102,
  FOREGROUND_APP: 0x0103,
  PROCESS_STOP: 0x0104,
  PROCESS_CONTINUE: 0x0105,
  PROCESS_KILL: 0x0106,
  BATCH_PROCESS_INFO: 0x0107,
  PROCESS_PROTECT: 0x0108,
  PROCESS_ALLOC: 0x0109,
  PROCESS_FREE: 0x010a,
  PROCESS_STACK: 0x010b,
  PROCESS_CALL: 0x010c,
  PROCESS_ELF_LOAD: 0x010d,
  PROCESS_HIJACK: 0x010e,
  PROCESS_DUMP: 0x010f,
  PROCESS_MAPS_V2: 0x0110,

  MEMORY_READ: 0x0200,
  MEMORY_WRITE: 0x0201,
  BATCH_READ: 0x0202,
  BATCH_WRITE: 0x0203,
  BATCH_WRITE_ADV: 0x0204,

  SCAN_EXACT: 0x0300,
  SCAN_PROCESS_EXACT: 0x0301,
  SCAN_AOB: 0x0302,
  SCAN_POINTER: 0x0303,
  SCAN_UNKNOWN: 0x0304,
  SCAN_PROCESS_AOB: 0x0305,
  SCAN_UNKNOWN_V2: 0x0306,
  SCAN_PROCESS_EXACT_TRACKED: 0x0307,
  SCAN_JOB_STATUS: 0x0308,
  SCAN_JOB_CANCEL: 0x0309,

  TELEMETRY: 0x0400,

  DEBUG_ATTACH: 0x0600,
  DEBUG_DETACH: 0x0601,
  DEBUG_STOP: 0x0602,
  DEBUG_CONTINUE: 0x0603,
  DEBUG_STEP: 0x0604,
  DEBUG_GET_THREADS: 0x0605,
  DEBUG_GET_REGS: 0x0606,
  DEBUG_SET_REGS: 0x0607,
  DEBUG_GET_DBREGS: 0x0608,
  DEBUG_SET_DBREGS: 0x0609,
  DEBUG_SET_BREAKPOINT: 0x060a,
  DEBUG_CLEAR_BREAKPOINT: 0x060b,
  DEBUG_SET_WATCHPOINT: 0x060c,
  DEBUG_CLEAR_WATCHPOINT: 0x060d,
  DEBUG_SUSPEND_THREAD: 0x060e,
  DEBUG_RESUME_THREAD: 0x060f,
  DEBUG_POLL_EVENTS: 0x0610,
  DEBUG_GET_BREAKPOINTS: 0x0611,
  DEBUG_GET_WATCHPOINTS: 0x0612,
  DEBUG_SET_BREAKPOINT_COND: 0x0613,
  DEBUG_CLEAR_ALL_BREAKPOINTS: 0x0614,
  DEBUG_CLEAR_ALL_WATCHPOINTS: 0x0615,
  DEBUG_GET_FPREGS: 0x0616,
  DEBUG_SET_FPREGS: 0x0617,
  DEBUG_GET_FSGSBASE: 0x0618,
  DEBUG_SET_FSGSBASE: 0x0619,

  TRACER_ATTACH: 0x0700,
  TRACER_DETACH: 0x0701,
  TRACER_POLL: 0x0702,
  TRACER_STATUS: 0x0703,

  KERNEL_BASE: 0x0800,
  KERNEL_READ: 0x0801,
  KERNEL_WRITE: 0x0802,

  CONSOLE_NOTIFY: 0x0900,
  CONSOLE_PRINT: 0x0901,
  CONSOLE_REBOOT: 0x0902,

  ASM_ENCODE: 0x0a00,
  DISASM: 0x0a01,
  XREFS_TO: 0x0a02,

  QUICKSCAN_CAPS: 0x0b00,
  QUICKSCAN_START: 0x0b01,
  QUICKSCAN_COUNT: 0x0b02,
  QUICKSCAN_FETCH: 0x0b03,
  QUICKSCAN_END: 0x0b04,
  QUICKSCAN_CONFIG: 0x0b05,
  QUICKSCAN_REGIONS: 0x0b06,
  QUICKSCAN_CANCEL: 0x0b07,

  PTWALK_DISCOVER: 0x0c00,
  PTWALK_AUGMENT: 0x0c01,
  PTWALK_READ: 0x0c02,
  PTWALK_WRITE: 0x0c03,
  PTWALK_PROBE: 0x0c04,

  AUTH_KEY: 0x0d00,
  ARENA_CONFIG: 0x0d01,
  KLOG_CONNECT: 0x0d02,
  GET_EXTENDED_CAPS: 0x0d03,

  SHUTDOWN: 0x7f00,
} as const;

export type CmdId = (typeof Cmd)[keyof typeof Cmd];

// ─── Status ──────────────────────────────────────────────────────────────
export const Status = {
  OK: 0,
  ERR_PARAM: -1,
  ERR_NOMEM: -2,
  ERR_IO: -3,
  ERR_NET: -4,
  ERR_PROTOCOL: -5,
  ERR_UNSUPPORTED: -6,
  ERR_NOT_FOUND: -7,
  ERR_PERMISSION: -8,
  ERR_OVERFLOW: -9,
  ERR_STATE: -10,
} as const;

export function statusName(code: number): string {
  const found = Object.entries(Status).find(([, v]) => v === code)?.[0];
  return found ?? `UNKNOWN(${code})`;
}

// ─── Roles (HELLO body) ──────────────────────────────────────────────────
export const Role = {
  CONTROL: 0,
  MEMORY: 1,
  SCAN: 2,
  POLL: 3,
  TOOL: 4,
} as const;
export type RoleId = (typeof Role)[keyof typeof Role];

// ─── Platform IDs ────────────────────────────────────────────────────────
export const Platform = {
  UNKNOWN: 0,
  PS4: 4,
  PS5: 5,
  HOST: 100,
} as const;
export function platformName(id: number): string {
  return (
    Object.entries(Platform).find(([, v]) => v === id)?.[0] ?? `PLATFORM_${id}`
  );
}

// ─── Value types (scanner) ───────────────────────────────────────────────
export const ValueType = {
  BYTES: 0,
  U8: 1,
  U16: 2,
  U32: 3,
  U64: 4,
  F32: 5,
  F64: 6,
  POINTER: 7,
} as const;
export type ValueTypeId = (typeof ValueType)[keyof typeof ValueType];
export function valueTypeSize(t: ValueTypeId): number {
  switch (t) {
    case ValueType.U8: return 1;
    case ValueType.U16: return 2;
    case ValueType.U32:
    case ValueType.F32: return 4;
    case ValueType.U64:
    case ValueType.F64:
    case ValueType.POINTER: return 8;
    default: return 0;
  }
}
export function valueTypeLabel(t: ValueTypeId): string {
  return (
    Object.entries(ValueType).find(([, v]) => v === t)?.[0] ?? `T${t}`
  ).toLowerCase();
}

// ─── Capabilities (HELLO.capabilities bitmap) ────────────────────────────
export const Cap = {
  PROCESS_LIST: 1 << 0,
  PROCESS_MAPS: 1 << 1,
  MEMORY_READ: 1 << 2,
  MEMORY_WRITE: 1 << 3,
  SCAN_EXACT: 1 << 4,
  UDP_LOG: 1 << 5,
  SCAN_PROCESS_EXACT: 1 << 6,
  SCAN_TELEMETRY: 1 << 7,
  PROCESS_INFO: 1 << 8,
  SCAN_AOB: 1 << 9,
  SCAN_POINTER: 1 << 10,
  FOREGROUND_APP: 1 << 11,
  PROCESS_CONTROL: 1 << 12,
  BATCH_READ: 1 << 13,
  PERF_TELEMETRY: 1 << 14,
  SCAN_UNKNOWN: 1 << 15,
  BATCH_WRITE: 1 << 16,
  LZ4: 1 << 17,
  SCAN_PROCESS_AOB: 1 << 18,
  DISCOVERY: 1 << 19,
  DEBUGGER: 1 << 20,
  TRACER: 1 << 21,
  MEMORY_PROTECT: 1 << 22,
  MEMORY_ALLOC: 1 << 23,
  STACK_WALK: 1 << 24,
  REMOTE_CALL: 1 << 25,
  KERNEL_ACCESS: 1 << 26,
  CONSOLE_UI: 1 << 27,
  DEBUG_FPREGS: 1 << 28,
  DEBUG_FSGS: 1 << 29,
  DISASSEMBLY: 1 << 30,
  KLOG_FORWARD: 1 << 31,
} as const;

/**
 * Extended capabilities (returned by GET_EXTENDED_CAPS 0x0D03 as u32 words).
 * Word 0 bits — matches protocol.md §7.6.
 */
export const ExtCap = {
  QUICKSCAN: 1 << 0,
  PTWALK: 1 << 1,
  ALIAS: 1 << 2,
  SIMD: 1 << 3,
  KLOG_SERVER: 1 << 4,
  AUTH: 1 << 5,
  ARENA: 1 << 6,
  BATCH_WRITE_ADV: 1 << 7,
  HIJACK: 1 << 8,
  SCAN_JOBS: 1 << 9,
} as const;

export function hasCap(capabilities: number, bit: number): boolean {
  return (capabilities & bit) === bit;
}
export function hasExtCap(words: readonly number[], bit: number): boolean {
  return words.length > 0 && ((words[0] & bit) === bit);
}

// ─── Map protection flags ────────────────────────────────────────────────
export const MapProt = {
  READ: 1 << 0,
  WRITE: 1 << 1,
  EXEC: 1 << 2,
} as const;

export function protString(prot: number): string {
  return (
    (prot & MapProt.READ ? "r" : "-") +
    (prot & MapProt.WRITE ? "w" : "-") +
    (prot & MapProt.EXEC ? "x" : "-")
  );
}

/**
 * Commands whose response body carries the LZ4/raw framed prefix.
 * All other responses are raw and must NOT be passed through unwrap.
 */
export const FRAMED_RESPONSE_COMMANDS: ReadonlySet<number> = new Set<number>([
  0x0200, // MEMORY_READ
  0x0202, // BATCH_READ
  0x0110, // PROCESS_MAPS_V2
  0x010f, // PROCESS_DUMP (chunked, framed)
]);

// ─── Tracer event kinds (spec §11) ───────────────────────────────────────
export const TracerEventKind = {
  SYSCALL_ENTRY: 1,
  SYSCALL_EXIT: 2,
  SIGNAL: 3,
  CRASH: 4,
} as const;
export function tracerEventKindName(kind: number): string {
  switch (kind) {
    case 1: return "syscall_entry";
    case 2: return "syscall_exit";
    case 3: return "signal";
    case 4: return "crash";
    default: return `k${kind}`;
  }
}


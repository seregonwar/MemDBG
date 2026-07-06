# ps5debug Compatibility Layer

MemDBG exposes its native `MDBG` protocol on TCP port `9020`. The legacy
compatibility layer adds a second TCP listener that speaks the ps5debug wire
protocol used by older trainer and debugger clients, including tools that expect
the historical port `744`.

This layer is a translation boundary. It does not replace the native MemDBG
protocol, and it must not add ps5debug framing or command assumptions to normal
`MDBG` dispatch.

## Goals

- Let older clients connect to MemDBG without client-side changes.
- Keep the native MemDBG protocol capability-driven and versioned.
- Translate stable ps5debug process and memory commands onto MemDBG PAL/debug
  APIs.
- Fail unsupported legacy commands with ps5debug-style status words instead of
  closing the modern MemDBG endpoint.

## Source Of Truth

The reference protocol is kept under
[`reference/ps5debug-NG-master/`](../reference/ps5debug-NG-master/).

The compatibility layer follows these wire-level properties:

| Property | Value |
|---|---|
| TCP command port | `744` |
| Packet magic | `0xFFAABBCC` |
| Packet header | `uint32 magic`, `uint32 command`, `uint32 data_len` |
| Byte order | Little-endian host order, matching ps5debug payloads |
| Success status | Server constant `0x40000000`, sent as wire `0x80000000` |
| Error status | Server constant `0xF0000002`, sent as wire `0xF0000001` |
| Null-data status | Server constant and wire value `0xF0000003` |

ps5debug status values are passed through the original adjacent-bit swap before
they are written to the socket:

```c
wire = ((value >> 1) & 0x55555555u) | ((value << 1) & 0xAAAAAAAAu);
```

Some metadata commands, such as version and branding, do not send a status word.
They return the exact payload shape expected by ps5debug clients.

## Runtime Model

On console builds the compatibility listener is enabled by default and binds to
`MEMDBG_DEFAULT_LEGACY_PORT` (`744`). On host builds it is opt-in so local tests
do not unexpectedly bind a public legacy port.

Useful flags:

| Flag | Behavior |
|---|---|
| `--legacy-compat` | Enable the ps5debug-compatible listener. |
| `--no-legacy-compat` | Disable it, even on console builds. |
| `--legacy-port=PORT` | Override the legacy TCP port. |
| `--allow=ADDR` | Applies to both native and legacy TCP listeners. |

The listener is best-effort. If port `744` is busy, MemDBG logs a warning and
continues serving the native protocol on `9020`.

## Implemented Commands

These commands focus on the operations used by classic trainers for process selection,
map discovery, patching, and simple code caves.

- `CMD_VERSION` (`0xBD000001`): static length-prefixed `"1.3"`.
- `CMD_FW_VERSION` (`0xBD000500`): returns `0` when firmware is not available
  through PAL.
- `CMD_BRANDING` (`0xBD000501`): static MemDBG brand string with a capability
  suffix after the first NUL byte.
- `CMD_PLATFORM_ID` (`0xBD000502`): `5` on PS5, `4` on PS4, `0` on host.
- `CMD_PROC_NOP` (`0xBDAACC06`): ps5debug success status.
- `CMD_PROC_AUTH` (`0xBDAACCFF`): no-op success because MemDBG performs
  privilege setup at daemon start.
- `CMD_PROC_INSTALL` (`0xBDAA0005`): no-op success plus a zero RPC stub.

## Command Reference Matrix

All commands use the legacy packet header `{uint32 magic=0xFFAABBCC, uint32 command, uint32 data_len}`.
Status words are adjacent-bit-swapped before wire transmission (see [Source Of Truth](#source-of-truth)).

### Metadata & Liveness

| Command | ID | Request | Response |
|---|---|---|---|
| `CMD_VERSION` | `0xBD000001` | none | `uint32 len` + `len` bytes of ASCII (static `"1.3"`) |
| `CMD_FW_VERSION` | `0xBD000500` | none | `uint16 fw_version` (0 on host) |
| `CMD_BRANDING` | `0xBD000501` | none | `uint32 len` + `len` bytes (MemDBG brand string with capability suffix after NUL) |
| `CMD_PLATFORM_ID` | `0xBD000502` | none | `uint16 platform` (5=PS5, 4=PS4, 0=host) |
| `CMD_PROC_NOP` | `0xBDAACC06` | none | `uint32 status` (always `CMD_SUCCESS`) |
| `CMD_PROC_AUTH` | `0xBDAACCFF` | none | `uint32 status` (always `CMD_SUCCESS`, no-op) |

### Process Operations

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_PROC_LIST` | `0xBDAA0001` | none | `uint32 status` + `uint32 count` + `count × {char name[32], int32 pid}` (36B each) |
| `CMD_PROC_MAPS` | `0xBDAA0004` | `uint32 pid` | `uint32 status` + `uint32 count` + `count × {char name[32], uint64 start, uint64 end, uint64 offset, uint16 prot}` (58B each) |
| `CMD_PROC_INFO` | `0xBDAA000A` | `uint32 pid` | `uint32 status` + `{uint32 pid, char name[40], char path[64], char title_id[16], char content_id[64]}` (188B) |
| `CMD_PROC_INSTALL` | `0xBDAA0005` | none | `uint32 status` + `uint64 rpc_stub` (always 0) |
| `CMD_PROC_PROTECT` | `0xBDAA0008` | `{uint32 pid, uint64 addr, uint32 len, uint32 prot}` (20B) | `uint32 status` |
| `CMD_PROC_ALLOC` | `0xBDAA000B` | `{uint32 pid, uint32 length}` (8B) | `uint32 status` + `{uint64 address}` (8B) |
| `CMD_PROC_ALLOC_HINTED` | `0xBDAA000E` | `{uint32 pid, uint64 hint, uint32 length}` (16B) | `uint32 status` + `{uint64 address}` (8B) |
| `CMD_PROC_FREE` | `0xBDAA000C` | `{uint32 pid, uint64 addr, uint32 length}` (16B) | `uint32 status` |
| `CMD_PROC_FIRST_MAP` | `0xBDAA000D` | `uint32 pid` | `uint32 status` + `int64 first_address` |

### Memory Operations

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_PROC_READ` | `0xBDAA0002` | `{uint32 pid, uint64 addr, uint32 length}` (16B) | `uint32 status` + streamed data in 64 KiB chunks (short reads zero-filled) |
| `CMD_PROC_WRITE` | `0xBDAA0003` | `{uint32 pid, uint64 addr, uint32 length}` (16B) + inline data | `uint32 status` (ack) → stream inline data in 64 KiB chunks → `uint32 status` (final) |
| `CMD_PROC_WRITE_MULTI` | `0xBDAACC04` | `{uint32 pid, uint32 count, uint32 flags}` (12B) + streamed `count × {uint64 addr, uint32 len}` (12B each) + inline data | `uint32 status` (ack) → stream data → `uint32 status` (final) + optional `count` status bytes if `flags & 0x1` |

### Scanner

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_SCAN` | `0xBDAA0009` | `{uint8 type, uint8 val_len, uint8 align, uint8 rsvd[5], uint64 start, uint64 end, uint32 max}` (28B) + `val_len` bytes | streaming: `uint32 count` (0–4096) + `count × uint64 addr`; terminated by `uint32 0` |
| `CMD_SCAN_AOB` | `0xBDAACC01` | `{uint64 start, uint64 end, uint32 pat_len}` (20B) + `pat_len` bytes pattern + `pat_len` bytes mask | same streaming format as `CMD_SCAN` |
| `CMD_SCAN_CONT` | `0xBDAACC02` | none | next chunk: `uint32 count` + `count × uint64 addr` + `uint32 0` terminator when exhausted |
| `CMD_SCAN_FETCH` | `0xBDAACC03` | none | alias for `CMD_SCAN_CONT` |

### Debugger

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_DEBUG_ATTACH` | `0xBDAA0006` | `uint32 pid` | `uint32 status`; after success, daemon connects back to client on TCP port 755 |
| `CMD_DEBUG_DETACH` | `0xBDAA0007` | none | `uint32 status` |
| `CMD_DEBUG_STOP` | `0xBDAA0010` | none | `uint32 status` |
| `CMD_DEBUG_CONTINUE` | `0xBDAA0011` | none | `uint32 status` |
| `CMD_DEBUG_STEP` | `0xBDAA0012` | `int32 lwp` | `uint32 status` |
| `CMD_DEBUG_GET_REGS` | `0xBDAA0013` | `int32 lwp` | `uint32 status` + `legacy_debug_regs_t` (128B: 15×uint64 + uint32 + 4×uint16 + uint32 + 2×uint64) |
| `CMD_DEBUG_SET_REGS` | `0xBDAA0014` | `int32 lwp` + `legacy_debug_regs_t` (132B) | `uint32 status` |
| `CMD_DEBUG_SET_BP` | `0xBDAA0015` | `{uint64 address, uint32 kind}` (12B) | `uint32 status` |
| `CMD_DEBUG_CLEAR_BP` | `0xBDAA0016` | `{uint64 address, uint32 kind}` (12B) | `uint32 status` |
| `CMD_DEBUG_SET_WP` | `0xBDAA0017` | `{uint64 address, uint32 length, uint32 type}` (16B) | `uint32 status` |
| `CMD_DEBUG_CLEAR_WP` | `0xBDAA0018` | `{uint64 address, uint32 length, uint32 type}` (16B) | `uint32 status` |
| `CMD_DEBUG_GET_THREADS` | `0xBDAA0019` | none | `uint32 status` + `uint32 count` + `count × {int32 lwp, uint32 state, char name[24]}` (32B each) |
| `CMD_DEBUG_SUSPEND` | `0xBDAA001A` | `int32 lwp` | `uint32 status` |
| `CMD_DEBUG_RESUME` | `0xBDAA001B` | `int32 lwp` | `uint32 status` |

**Async interrupt (port 755):** `{bitswapped CMD_INTERRUPT (0xBDAACC07), uint32 lwp}` (8B).
Sent when the debugged process stops. Background poll thread runs every 100ms.
Session auto-cleans on client disconnect.

### Kernel

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_KERN_BASE` | `0xBDAA001C` | none | `uint32 status` + `{uint64 text_base, uint64 data_base}` (16B) |
| `CMD_KERN_READ` | `0xBDAA001D` | `{uint64 address, uint32 length}` (12B) | `uint32 status` + inline data blob |
| `CMD_KERN_WRITE` | `0xBDAA001E` | `{uint64 address, uint32 length}` (12B) + inline data | `uint32 status` |

All gated behind `pal_kernel_supported()`. Lengths capped by `cfg.max_read_bytes`.

### Code Analysis (disassembly / xref / remote call / ELF)

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_DISASM` | `0xBDAA001F` | `{int32 pid, uint64 addr, uint32 max_count}` (16B) + inline code bytes | `uint32 status` + `uint32 count` + `count × legacy_disasm_entry_t` (32B each: addr, rip_rel_target, mem_disp, byte_len, opcode_kind, base/index reg, scale, mnemonic_id) |
| `CMD_XREFS` | `0xBDAA0020` | `{int32 pid, uint64 scan_addr, uint64 scan_len, uint64 target}` (28B) | `uint32 status` + `uint64 count` + `count × uint64 addr` |
| `CMD_PROC_CALL` | `0xBDAA0021` | `{int32 pid, uint64 func_addr, uint64 args[6]}` (60B) | `uint32 status` + `uint64 rax` (12B total) |
| `CMD_PROC_ELF_LOAD` | `0xBDAA0022` | `{int32 pid, uint32 flags, uint64 image_size}` (16B) + inline ELF bytes | `uint32 status` + `{uint64 entry, uint64 base}` (20B total) |

Disasm/xref/remote-call/ELF-load bridges use `socketpair(AF_UNIX, SOCK_STREAM)` to
capture native MemDBG handler output, then translate to legacy format.
`CMD_PROC_CALL` performs a full ptrace trampoline (attach→stop→inject→continue→wait→read rax)
and may block up to 5 seconds.

### FlashScan (server-resident scanning with snapshots)

| Command | ID | Request Body | Response |
|---|---|---|---|
| `CMD_QUICKSCAN_CAPS` | `0xBDAACC08` | none | `uint32 status` (bitswapped) + `{uint32 v, uint32 flags, uint32 workers, uint32 rsvd}` (16B: caps response) |
| `CMD_QUICKSCAN_START` | `0xBDAACC09` | `{int32 pid, uint32 type, uint32 cmp, uint32 align, uint32 val_len, uint32 flags, uint64 addr, uint64 len}` (40B) + compare data + optional mask | `uint32 status` (bitswapped) + `uint32 ack` + native FlashScan response body (plan, progress, summary, or resident header + streaming results) |
| `CMD_QUICKSCAN_COUNT` | `0xBDAACC0A` | `{int32 pid, uint32 type, uint32 cmp, uint32 val_len, uint32 flags, uint64 base}` (28B) + compare data + optional mask | `uint32 status` (bitswapped) + native FlashScan response body (progress sentinel + hit count) |
| `CMD_QUICKSCAN_FETCH` | `0xBDAACC0B` | `{uint32 start, uint32 count, uint32 flags}` (12B) | `uint32 status` (bitswapped) + `uint32 hdr` (msb = has_first) + entries (slots × `{uint64 addr, uint8 val[vlen], uint8 prev[vlen], optional uint8 first[vlen]}`) |
| `CMD_QUICKSCAN_END` | `0xBDAACC0C` | none | `uint32 status` (bitswapped) |
| `CMD_QUICKSCAN_CONFIG` | `0xBDAACC0D` | `{uint32 ram_limit_mb, uint32 spill_path_len}` (8B) + `spill_path_len` bytes | `uint32 status` (bitswapped) |
| `CMD_QUICKSCAN_REGIONS` | `0xBDAACC0E` | `{int32 pid, uint32 max, uint32 probe, uint32 rsvd}` (16B) | `uint32 status` (bitswapped) + `uint32 count` + `count × {uint64 start, uint64 end, uint32 prot, uint32 flags, uint32 read_mbps, uint32 rsvd}` (32B each) + trailing `uint32 ack` |

FlashScan bridges use `socketpair(AF_UNIX, SOCK_STREAM)` to capture native
FlashScan handler output, then forward it with a bitswapped status prefix.
**Limitations:** `SNAP_SEGMENTS` flag rejected on START (handlers read segments
interactively from the fd). Non-resident COUNT returns empty results for the
same reason. Snapshot/resident paths are fully supported.

## Extension Plan

1. **Client matrix:** validate against MultiTrainer, Reaper Studio, ps5debug
   Python scripts, and older PS4/PS5 trainer clients using recorded command
   traces.

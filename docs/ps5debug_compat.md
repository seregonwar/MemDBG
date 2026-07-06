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

## Implemented Phase 1 Commands

Phase 1 focuses on the commands used by classic trainers for process selection,
map discovery, patching, and simple code caves.

Metadata and liveness:

- `CMD_VERSION` (`0xBD000001`): static length-prefixed `"1.3"`.
- `CMD_FW_VERSION` (`0xBD000500`): returns `0` when firmware is not available
  through PAL.
- `CMD_BRANDING` (`0xBD000501`): static MemDBG brand string with a capability
  suffix after the first NUL byte.
- `CMD_PLATFORM_ID` (`0xBD000502`): `5` on PS5, `4` on PS4, `0` on host.
- `CMD_PROC_NOP` (`0xBDAACC06`): ps5debug success status.
- `CMD_PROC_AUTH` (`0xBDAACCFF`): no-op success because MemDBG performs
  privilege setup at daemon start.

Process and memory:

- Process list (`0xBDAA0001`): `memdbg_process_list`, converted from
  `pid + name[48]` to legacy `name[32] + pid`.
- Process read (`0xBDAA0002`): `memdbg_memory_read`, streamed in fixed-size
  chunks after one success status. Short reads are zero-filled like ps5debug.
- Process write (`0xBDAA0003`): `memdbg_memory_write`; sends an initial ack,
  consumes trailing bytes, then sends a final status.
- Process maps (`0xBDAA0004`): `memdbg_process_maps`, converted to legacy
  `name[32], start, end, offset, prot`.
- Process install (`0xBDAA0005`): no-op success plus a zero RPC stub.
- Process protect (`0xBDAA0008`): `pal_memory_protect`, using MemDBG protection
  bits `1=R`, `2=W`, `4=X`.
- Process info (`0xBDAA000A`): `memdbg_process_info`, converted to legacy
  field widths.
- Process alloc (`0xBDAA000B`): `pal_memory_alloc`, RWX for old-client
  compatibility.
- Process free (`0xBDAA000C`): `pal_memory_free`.
- First map (`0xBDAA000D`): returns the first mapped address from
  `memdbg_process_maps`.
- Hinted alloc (`0xBDAA000E`): `pal_memory_alloc` with the legacy hint.
- Write multi (`0xBDAACC04`): streamed batch writes via `memdbg_memory_write`,
  including optional per-entry status bytes.

Unsupported legacy commands currently return ps5debug `CMD_ERROR`.

## Intentional Limits

Legacy read/write requests are capped by `cfg.max_read_bytes`, the same
operational limit used by the native protocol. This prevents a legacy client
from accidentally turning one request into an unbounded multi-gigabyte stream.

The layer does not currently implement:

- ps5debug async scanner sessions (`0xBDAA0009`, `0xBDAACC01..03`);
- turboscan extensions;
- disassembly and xref helpers;
- remote calls and ELF/RPC load;
- kernel read/write commands;
- debugger attach, breakpoint, watchpoint, and interrupt event channel on TCP
  port `755`.

Those commands need deeper semantic translation, not just packet conversion.
Debugger compatibility is especially separate because ps5debug connects back to
the client on an asynchronous interrupt socket, while MemDBG uses native
capability-gated debugger event polling.

## Extension Plan

1. **Scanner bridge:** translate the legacy exact/AOB scan request shapes to
   MemDBG scanner APIs and preserve ps5debug streaming result records.
2. **Kernel bridge:** map legacy kernel read/write only when
   `pal_kernel_supported()` is true and the native capability bitmap advertises
   kernel access.
3. **Debugger bridge:** implement a ps5debug interrupt socket adapter that
   converts MemDBG debugger events into the legacy async channel.
4. **Client matrix:** validate against MultiTrainer, Reaper Studio, ps5debug
   Python scripts, and older PS4/PS5 trainer clients using recorded command
   traces.

Each new command should be added only after its wire shape is documented here,
covered by a host smoke test where possible, and gated by the matching MemDBG
backend capability.

# MemDBG Internal Protocol Specification

Status: stable wire version `MEMDBG_PROTOCOL_VERSION` 1, feature level 2
Canonical header: [`include/memdbg/core/memdbg_protocol.h`](../include/memdbg/core/memdbg_protocol.h)  
Canonical daemon dispatch: [`src/core/daemon/dispatch.c`](../src/core/daemon/dispatch.c)  
Canonical frontend client: [`frontend/src/core/client/memdbg_client.cpp`](../frontend/src/core/client/memdbg_client.cpp)

This document defines the MemDBG internal wire protocol, also called the MDBG
protocol. It is intended to be the stable contract between payloads, desktop
frontends, automation tools, tests, plugins, and future third-party clients.

The C header remains the ABI source of truth. This document explains how the
fields are serialized, how commands are grouped, which behaviors are normative,
and how the protocol should evolve without breaking existing clients.

`MEMDBG_PROTOCOL_VERSION` identifies the packet framing and remains `1` for
backward compatibility. `MEMDBG_PROTOCOL_FEATURE_LEVEL` identifies the
append-only command/HELLO feature set and is currently `2`. User interfaces
must therefore present the negotiated pair as **feature level v2 (wire v1)**,
not simply "Protocol v1". A v2 client accepts the shorter legacy HELLO body and
defaults its missing feature level to `1`; a v2 payload appends the negotiated
feature level without changing any v1 field offsets.

## Goals

The protocol is designed for jailbroken-console memory debugging where a client
needs predictable low-latency primitives and enough feature discovery to survive
platform differences.

The main design goals are:

- compact binary framing with fixed-size packed headers;
- deterministic request/response correlation;
- little-endian scalar encoding across all current targets;
- capability-driven feature negotiation instead of platform guessing;
- bounded packet sizes suitable for payload memory budgets;
- optional compression for large read-heavy responses;
- append-only command and capability registries.

The protocol is not a general RPC framework. It deliberately exposes memory,
process, debugger, scanner, tracer, kernel, and console operations as explicit
command families with command-specific request and response bodies.

## Transport

The primary control transport is TCP. Payloads listen on `debug_port`, which
defaults to `9020`. Host builds bind to `127.0.0.1` by default; console payloads
bind to `0.0.0.0` by default. A daemon may reject peers through the configured
allowlist before any protocol frame is processed.

Each accepted TCP connection is a sequential request stream:

1. Client writes one request header.
2. Client writes exactly `header.length` body bytes.
3. Daemon writes one response header.
4. Daemon writes exactly `response.length` body bytes.
5. The same connection may be reused for the next request.

The daemon dispatch path is synchronous per connection but supports
request pipelining: after processing each request, the daemon performs a
non-blocking poll for more data. If additional requests are already queued in
the TCP buffer, they are processed in a tight loop without returning to the
accept poll. This allows clients to batch-send N requests in a single TCP write
and receive N responses back-to-back, eliminating N-1 round-trip delays.

### Connection Pooling

Clients MAY open multiple TCP connections to the same daemon for parallel
operation. The daemon's thread pool handles each connection independently,
enabling true concurrency:

| Role | Connection | Typical commands |
|---|---|---|
| Control | 1 (required) | HELLO, process control, debugger, tracer |
| Memory | 2 (optional) | MEMORY_READ, MEMORY_WRITE, BATCH_READ, BATCH_WRITE |
| Scan | 3 (optional) | SCAN_*, AOB, Pointer, QuickScan |
| Poll | 4 (optional) | PING, TELEMETRY |

Each connection runs its own HELLO handshake. The client must validate that
capabilities are consistent across connections. Operations that require
exclusive daemon state (debugger attach, tracer attach) must always use the
Control connection.

When a dedicated role connection is not available, the client falls back to
the Control connection transparently.

### Request Pipelining

Clients MAY send multiple requests on a single connection without waiting for
individual responses, then read all responses in one batch. This pipelining
eliminates round-trip latency for independent operations.

**Protocol-level contract:**

1. Client serializes N requests into a single TCP write: headers and bodies
   concatenated back-to-back.
2. Daemon processes requests sequentially in the order received.
3. Daemon writes N responses back-to-back on the same connection.
4. Client reads N response headers and bodies in order, validating each
   `request_id` for correlation.

**Constraints:**

- Pipelining does NOT change the per-request semantics; each request is
  processed independently as if it were sent alone.
- Requests must be independent — a pipelined `DEBUG_ATTACH` followed by
  `DEBUG_GET_REGS` is safe because the daemon processes them in order, but a
  pipelined `MEMORY_WRITE` followed by `MEMORY_READ` at the same address may
  see the write result if they are processed in order.
- The daemon does NOT reorder responses; they always match the request order.
- Client-side buffer limits (1 MB default) prevent TCP deadlock from
  oversized pipelined writes.
- The `request_id` field in each response echoes the corresponding request's
  `request_id` and must be validated by the client.

**Client API (C++ frontend):**

```cpp
// Queue requests without I/O
uint32_t r1 = client.pipeline_send(MEMDBG_CMD_MEMORY_READ, &req1, sizeof(req1));
uint32_t r2 = client.pipeline_send(MEMDBG_CMD_MEMORY_READ, &req2, sizeof(req2));

// Send all queued requests and read all responses
if (!client.pipeline_flush()) { /* handle error */ }

// Retrieve individual response bodies
std::vector<uint8_t> body1, body2;
client.read_pipeline_response(r1, body1);
client.read_pipeline_response(r2, body2);

// Or discard without sending:
client.pipeline_reset();
```

Discovery and log streaming are separate transports:

- discovery uses UDP broadcast on `discovery_port`, default `9022`;
- UDP log output uses `udp_log_port`, default `9023`;
- PS5 KLOG streaming is negotiated on the main TCP socket, then consumed from a
  separate TCP stream returned by `KLOG_CONNECT`.

## Binary Encoding

All integer fields are serialized in little-endian byte order. All current
targets are little-endian, and the implementation writes packed C structs
directly. A portable non-C client must still encode and decode every scalar as
little-endian and must not rely on its host ABI.

All protocol structs are packed with no implicit padding unless the struct
declares explicit `reserved`, `_pad`, or alignment fields. Reserved fields must
be sent as zero by clients and ignored by receivers unless a future extension
assigns meaning to them.

Fixed-size string fields are UTF-8 byte arrays. They may be NUL-terminated when
there is room, but clients must treat the first NUL or the fixed field length as
the end of the string.

Variable-length bodies are encoded as:

- a fixed packed prefix struct;
- zero or more inline records;
- optional byte blobs whose length is declared by the prefix.

Every receiver must validate that declared lengths fit inside the enclosing
packet body before reading inline data.

## Request Header

Every control request starts with `memdbg_packet_header_t`.

| Offset | Size | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | `uint32_t` | Must be `0x4742444d`, the little-endian value for `"MDBG"`. |
| 4 | 2 | `version` | `uint16_t` | Must be `1` for this specification. |
| 6 | 2 | `command` | `uint16_t` | One value from the command registry. |
| 8 | 4 | `request_id` | `uint32_t` | Client-selected correlation id. |
| 12 | 4 | `length` | `uint32_t` | Body size in bytes. |

The request body immediately follows the header and is exactly `length` bytes.

If `magic`, `version`, or `length` are invalid, the daemon sends
`MEMDBG_ERR_PROTOCOL` when possible and closes the connection. `length` must not
exceed the daemon configuration limit, which defaults to
`MEMDBG_PROTOCOL_MAX_PACKET` (`1 MiB`).

## Response Header

Every control response starts with `memdbg_response_header_t`.

| Offset | Size | Field | Type | Description |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | `uint32_t` | `0x4742444d`. |
| 4 | 2 | `version` | `uint16_t` | Protocol version used by the daemon. |
| 6 | 2 | `command` | `uint16_t` | Echo of the request command. |
| 8 | 4 | `request_id` | `uint32_t` | Echo of the request id. |
| 12 | 4 | `status` | `int32_t` | `memdbg_status_t`. `0` means success; errors are negative values. |
| 16 | 4 | `length` | `uint32_t` | Response body size in bytes. |

When `status != MEMDBG_OK`, the response body is usually empty. Some commands
may return partial per-entry status arrays with a success header status; command
sections call that out explicitly.

Clients must validate `magic`, `version`, `command`, and `request_id` before
parsing the response body.

## Status Codes

| Status | Value | Meaning |
|---|---:|---|
| `MEMDBG_OK` | `0` | Request completed successfully. |
| `MEMDBG_ERR_PARAM` | `-1` | Well-formed request with invalid semantic parameters. |
| `MEMDBG_ERR_NOMEM` | `-2` | Payload could not allocate required memory. |
| `MEMDBG_ERR_IO` | `-3` | Platform I/O, ptrace, memory, or kernel operation failed. |
| `MEMDBG_ERR_NET` | `-4` | Socket write/read failure while servicing the request. |
| `MEMDBG_ERR_PROTOCOL` | `-5` | Malformed frame, wrong body size, or unknown command. |
| `MEMDBG_ERR_UNSUPPORTED` | `-6` | Command is valid but unavailable on this platform/payload. |
| `MEMDBG_ERR_NOT_FOUND` | `-7` | Target process, map, thread, or object was not found. |
| `MEMDBG_ERR_PERMISSION` | `-8` | Target denied the requested operation. |
| `MEMDBG_ERR_OVERFLOW` | `-9` | Size, count, address, or packet limit would overflow. |
| `MEMDBG_ERR_STATE` | `-10` | Operation conflicts with current daemon/debugger/scanner state. |

`MEMDBG_ERR_PROTOCOL` is for framing and ABI violations. Clients should prefer
`MEMDBG_ERR_PARAM` when a request is syntactically valid but not meaningful.

## Session Bootstrap

A client should always begin a connection with `HELLO`.

`HELLO` has no request body. The response body is `memdbg_hello_response_t`:

| Field | Description |
|---|---|
| `protocol_version` | Protocol version implemented by the daemon. |
| `platform_id` | `UNKNOWN`, `PS4`, `PS5`, or `HOST`. |
| `capabilities` | 32-bit capability bitmap. |
| `debug_port` | TCP control port. |
| `udp_log_port` | UDP log port, or `0` when disabled. |
| `version[16]` | Payload version string. |
| `name[16]` | Payload name, currently `MemDBG`. |

Clients must gate optional UI and commands from `capabilities`, not from
`platform_id`. Platform id is descriptive; capability bits are authoritative.

`PING` has no request or response body and is the cheapest liveness check.

`SHUTDOWN` has no request or response body. A successful response means the
daemon accepted remote termination and requested its listener to stop.

## Framed Payload Compression

The TCP request and response headers are never compressed. Only selected
response bodies contain a command-local compressed sub-frame.

The compressed sub-frame format is:

| Byte(s) | Meaning |
|---:|---|
| `0` | `0x00` means raw payload follows. |
| `1..` | Raw payload bytes when byte 0 is `0x00`. |
| `0` | `0x01` means LZ4 payload follows. |
| `1..4` | Little-endian uncompressed size. |
| `5..` | LZ4 compressed bytes. |

The daemon currently frames large memory-read payloads through this format:

- `MEMORY_READ`: response body is exactly the framed payload.
- `BATCH_READ`: response body is `result[count] | framed_data`.

Compression is attempted for payloads at or above 4096 bytes and is used only
when the compressed size is meaningfully smaller. Otherwise the daemon sends a
raw sub-frame with prefix `0x00`.

Clients must not try to decompress arbitrary response bodies. Only commands
documented as returning framed payloads use this sub-frame.

## Limits

| Limit | Value | Notes |
|---|---:|---|
| `MEMDBG_PROTOCOL_MAX_PACKET` | `1 MiB` | Default maximum request body and many response bodies. |
| `MEMDBG_PROTOCOL_MAX_MAP_RESPONSE` | `8 MiB` | Dedicated `PROCESS_MAPS` response cap for titles with very large map tables. |
| `MEMDBG_PROTOCOL_MAX_READ` | `1 MiB` | Default single memory read/write byte cap. |
| `MEMDBG_BATCH_READ_MAX_ITEMS` | `64` | Maximum batch read items. |
| `MEMDBG_BATCH_WRITE_MAX_ITEMS` | `64` | Maximum batch write items. |
| `MEMDBG_BATCH_READ_MAX_ITEM_BYTES` | `64 MiB` | Per-item read cap used internally to avoid offset overflow. |
| `MEMDBG_SCAN_VALUE_MAX` | `16` | Inline exact-scan value bytes. |
| AOB pattern length | `1..256` | Pattern and mask have the same length. |
| `MEMDBG_DEBUG_FPREGS_MAX` | `1024` | Max floating-point / xstate register blob. |
| `MEMDBG_STACK_MAX_FRAMES` | `64` | Max stack frames per stack walk. |
| `MEMDBG_BATCH_WRITE_ADV_MAX_ENTRIES` | `65535` | Advanced batch write entry cap. |
| `MEMDBG_BATCH_WRITE_ADV_MAX_ENTRY` | `1 MiB` | Per advanced write entry cap. |

Daemon configuration may further reduce packet, read, and scan result limits.

## Command Ranges

Command values are grouped by the high byte.

| Range | Family |
|---:|---|
| `0x0000` | Session and lifecycle. |
| `0x0100` | Process metadata, lifecycle, allocation, stack, call, ELF, hijack. |
| `0x0200` | Memory and batch memory operations. |
| `0x0300` | Scanners. |
| `0x0400` | Telemetry. |
| `0x0500` | UDP discovery. |
| `0x0600` | Debugger. |
| `0x0700` | Tracer. |
| `0x0800` | Kernel memory. |
| `0x0900` | Console UI actions. |
| `0x0A00` | Assembler, disassembler, xrefs. |
| `0x0B00` | FlashScan / QuickScan. |
| `0x0C00` | Page-table walk / DMAP introspection. |
| `0x0D00` | Auth, arena, KLOG, and other privileged extensions. |
| `0x7F00` | Administrative shutdown. |

New command families should reserve an unused high-byte range. New commands in
an existing family must be appended and must not reuse retired values.

## Command Registry

| Command | Value | Request body | Success response body |
|---|---:|---|---|
| `MEMDBG_CMD_HELLO` | `0x0001` | empty | `memdbg_hello_response_t` |
| `MEMDBG_CMD_PING` | `0x0002` | empty | empty |
| `MEMDBG_CMD_PROCESS_LIST` | `0x0100` | empty | `uint32_t count` + `memdbg_process_entry_t[]` |
| `MEMDBG_CMD_PROCESS_MAPS` | `0x0101` | `memdbg_process_maps_request_t` | `uint32_t count` + `memdbg_map_entry_t[]` |
| `MEMDBG_CMD_PROCESS_INFO` | `0x0102` | `memdbg_process_info_request_t` | `memdbg_process_info_response_t` |
| `MEMDBG_CMD_FOREGROUND_APP` | `0x0103` | empty | `memdbg_foreground_app_response_t` |
| `MEMDBG_CMD_PROCESS_STOP` | `0x0104` | `memdbg_process_control_request_t` with `action=1` | empty |
| `MEMDBG_CMD_PROCESS_CONTINUE` | `0x0105` | `memdbg_process_control_request_t` with `action=2` | empty |
| `MEMDBG_CMD_PROCESS_KILL` | `0x0106` | `memdbg_process_control_request_t` with `action=3` | empty |
| `MEMDBG_CMD_BATCH_PROCESS_INFO` | `0x0107` | prefix + `int32_t pid[]` | prefix + `memdbg_process_info_response_t[]` |
| `MEMDBG_CMD_PROCESS_PROTECT` | `0x0108` | `memdbg_process_protect_request_t` | `memdbg_process_protect_response_t` |
| `MEMDBG_CMD_PROCESS_ALLOC` | `0x0109` | `memdbg_process_alloc_request_t` | `memdbg_process_alloc_response_t` |
| `MEMDBG_CMD_PROCESS_FREE` | `0x010A` | `memdbg_process_free_request_t` | empty |
| `MEMDBG_CMD_PROCESS_STACK` | `0x010B` | `memdbg_process_stack_request_t` | prefix + frames + data blob |
| `MEMDBG_CMD_PROCESS_CALL` | `0x010C` | `memdbg_process_call_request_t` | `memdbg_process_call_response_t` |
| `MEMDBG_CMD_PROCESS_ELF_LOAD` | `0x010D` | `memdbg_process_elf_load_request_t` + ELF bytes | `memdbg_process_elf_load_response_t` |
| `MEMDBG_CMD_PROCESS_HIJACK` | `0x010E` | `memdbg_process_hijack_request_t` + ELF bytes | `memdbg_process_hijack_response_t` |
| `MEMDBG_CMD_PROCESS_DUMP` | `0x010F` | `memdbg_process_dump_request_t` | streamed dump response |
| `MEMDBG_CMD_PROCESS_MAPS_V2` | `0x0110` | `memdbg_process_maps_request_t` | raw/LZ4 framed map list |
| `MEMDBG_CMD_MEMORY_READ` | `0x0200` | `memdbg_memory_request_t` | framed bytes |
| `MEMDBG_CMD_MEMORY_WRITE` | `0x0201` | `memdbg_memory_request_t` + bytes | `uint32_t written` |
| `MEMDBG_CMD_BATCH_READ` | `0x0202` | prefix + `memdbg_batch_read_item_t[]` | result entries + framed bytes |
| `MEMDBG_CMD_BATCH_WRITE` | `0x0203` | prefix + streamed write entries | `memdbg_batch_write_result_entry_t[]` |
| `MEMDBG_CMD_BATCH_WRITE_ADV` | `0x0204` | `memdbg_batch_write_adv_request_t` + streamed entries | command-defined per-entry result when requested |
| `MEMDBG_CMD_SCAN_EXACT` | `0x0300` | `memdbg_scan_exact_request_t` | `memdbg_scan_response_prefix_t` + result entries |
| `MEMDBG_CMD_SCAN_PROCESS_EXACT` | `0x0301` | `memdbg_scan_process_exact_request_t` | scan prefix + result entries |
| `MEMDBG_CMD_SCAN_AOB` | `0x0302` | prefix + pattern + mask | scan prefix + result entries |
| `MEMDBG_CMD_SCAN_POINTER` | `0x0303` | `memdbg_scan_pointer_request_t` | scan prefix + pointer chain entries |
| `MEMDBG_CMD_SCAN_UNKNOWN` | `0x0304` | `memdbg_scan_process_exact_request_t` | scan prefix + result entries |
| `MEMDBG_CMD_SCAN_PROCESS_AOB` | `0x0305` | prefix + pattern + mask | scan prefix + result entries |
| `MEMDBG_CMD_TELEMETRY` | `0x0400` | empty | `memdbg_telemetry_response_t` |
| `MEMDBG_CMD_DISCOVERY` | `0x0500` | not used on TCP | see UDP discovery |
| `MEMDBG_CMD_DEBUG_ATTACH` | `0x0600` | `memdbg_debug_attach_request_t` | empty |
| `MEMDBG_CMD_DEBUG_DETACH` | `0x0601` | empty | empty |
| `MEMDBG_CMD_DEBUG_STOP` | `0x0602` | empty | empty |
| `MEMDBG_CMD_DEBUG_CONTINUE` | `0x0603` | empty | empty |
| `MEMDBG_CMD_DEBUG_STEP` | `0x0604` | `memdbg_debug_thread_request_t` | empty |
| `MEMDBG_CMD_DEBUG_GET_THREADS` | `0x0605` | empty | prefix + `memdbg_debug_thread_entry_t[]` |
| `MEMDBG_CMD_DEBUG_GET_REGS` | `0x0606` | `memdbg_debug_thread_request_t` | `memdbg_debug_regs_t` |
| `MEMDBG_CMD_DEBUG_SET_REGS` | `0x0607` | `memdbg_debug_thread_request_t` + regs | empty |
| `MEMDBG_CMD_DEBUG_GET_DBREGS` | `0x0608` | `memdbg_debug_thread_request_t` | `memdbg_debug_dbregs_t` |
| `MEMDBG_CMD_DEBUG_SET_DBREGS` | `0x0609` | `memdbg_debug_thread_request_t` + dbregs | empty |
| `MEMDBG_CMD_DEBUG_SET_BREAKPOINT` | `0x060A` | `memdbg_debug_breakpoint_request_t` | empty |
| `MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT` | `0x060B` | `memdbg_debug_breakpoint_request_t` | empty |
| `MEMDBG_CMD_DEBUG_SET_WATCHPOINT` | `0x060C` | `memdbg_debug_watchpoint_request_t` | empty |
| `MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT` | `0x060D` | `memdbg_debug_watchpoint_request_t` | empty |
| `MEMDBG_CMD_DEBUG_SUSPEND_THREAD` | `0x060E` | `memdbg_debug_thread_request_t` | empty |
| `MEMDBG_CMD_DEBUG_RESUME_THREAD` | `0x060F` | `memdbg_debug_thread_request_t` | empty |
| `MEMDBG_CMD_DEBUG_POLL_EVENTS` | `0x0610` | empty | `memdbg_debug_poll_response_t` |
| `MEMDBG_CMD_DEBUG_GET_BREAKPOINTS` | `0x0611` | empty | prefix + breakpoint entries |
| `MEMDBG_CMD_DEBUG_GET_WATCHPOINTS` | `0x0612` | empty | prefix + watchpoint entries |
| `MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND` | `0x0613` | `memdbg_debug_breakpoint_cond_request_t` | empty |
| `MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS` | `0x0614` | empty | `memdbg_debug_clear_all_response_t` |
| `MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS` | `0x0615` | empty | `memdbg_debug_clear_all_response_t` |
| `MEMDBG_CMD_DEBUG_GET_FPREGS` | `0x0616` | `memdbg_debug_thread_request_t` | `memdbg_debug_fpregs_t` |
| `MEMDBG_CMD_DEBUG_SET_FPREGS` | `0x0617` | `memdbg_debug_thread_request_t` + fpregs | empty |
| `MEMDBG_CMD_DEBUG_GET_FSGSBASE` | `0x0618` | `memdbg_debug_thread_request_t` | `memdbg_debug_fsgsbase_t` |
| `MEMDBG_CMD_DEBUG_SET_FSGSBASE` | `0x0619` | `memdbg_debug_thread_request_t` + fsgsbase | empty |
| `MEMDBG_CMD_TRACER_ATTACH` | `0x0700` | `memdbg_tracer_attach_request_t` | empty |
| `MEMDBG_CMD_TRACER_DETACH` | `0x0701` | empty | empty |
| `MEMDBG_CMD_TRACER_POLL` | `0x0702` | empty | prefix + `memdbg_tracer_event_t[]` |
| `MEMDBG_CMD_TRACER_STATUS` | `0x0703` | empty | `memdbg_tracer_status_response_t` |
| `MEMDBG_CMD_KERNEL_BASE` | `0x0800` | empty | `memdbg_kernel_base_response_t` |
| `MEMDBG_CMD_KERNEL_READ` | `0x0801` | `memdbg_kernel_memory_request_t` | raw bytes |
| `MEMDBG_CMD_KERNEL_WRITE` | `0x0802` | `memdbg_kernel_memory_request_t` + bytes | empty |
| `MEMDBG_CMD_CONSOLE_NOTIFY` | `0x0900` | `memdbg_console_text_request_t` + UTF-8 bytes | empty |
| `MEMDBG_CMD_CONSOLE_PRINT` | `0x0901` | `memdbg_console_text_request_t` + UTF-8 bytes | empty |
| `MEMDBG_CMD_CONSOLE_REBOOT` | `0x0902` | empty | empty |
| `MEMDBG_CMD_ASM_ENCODE` | `0x0A00` | `memdbg_asm_encode_request_t` + UTF-8 asm | ok or error prefix + bytes |
| `MEMDBG_CMD_DISASM` | `0x0A01` | one or more `memdbg_disasm_request_t` records | disassembly records |
| `MEMDBG_CMD_XREFS_TO` | `0x0A02` | one or more `memdbg_xrefs_to_request_t` records | xref records |
| `MEMDBG_CMD_QUICKSCAN_CAPS` | `0x0B00` | empty | `memdbg_quickscan_caps_response_t` |
| `MEMDBG_CMD_QUICKSCAN_START` | `0x0B01` | prefix + compare bytes + optional mask | streamed or resident scan result |
| `MEMDBG_CMD_QUICKSCAN_COUNT` | `0x0B02` | prefix + compare bytes + optional mask | count/result update |
| `MEMDBG_CMD_QUICKSCAN_FETCH` | `0x0B03` | `memdbg_quickscan_fetch_request_t` | resident result entries |
| `MEMDBG_CMD_QUICKSCAN_END` | `0x0B04` | empty | empty |
| `MEMDBG_CMD_QUICKSCAN_CONFIG` | `0x0B05` | `memdbg_quickscan_config_request_t` + path bytes | empty |
| `MEMDBG_CMD_QUICKSCAN_REGIONS` | `0x0B06` | `memdbg_quickscan_regions_request_t` | region info entries |
| `MEMDBG_CMD_QUICKSCAN_CANCEL` | `0x0B07` | empty | empty |
| `MEMDBG_CMD_PTWALK_DISCOVER` | `0x0C00` | empty | `memdbg_ptwalk_discover_response_t` |
| `MEMDBG_CMD_PTWALK_AUGMENT` | `0x0C01` | `memdbg_ptwalk_augment_request_t` | map entries with ptwalk augmentation |
| `MEMDBG_CMD_PTWALK_READ` | `0x0C02` | `memdbg_ptwalk_io_request_t` | raw bytes |
| `MEMDBG_CMD_PTWALK_WRITE` | `0x0C03` | `memdbg_ptwalk_io_request_t` + bytes | empty |
| `MEMDBG_CMD_PTWALK_PROBE` | `0x0C04` | `memdbg_ptwalk_probe_request_t` | `memdbg_ptwalk_probe_response_t` |
| `MEMDBG_CMD_AUTH_KEY` | `0x0D00` | `memdbg_auth_key_request_t` | empty; status is in the normal response header |
| `MEMDBG_CMD_ARENA_CONFIG` | `0x0D01` | `memdbg_arena_config_request_t` | empty; status is in the normal response header |
| `MEMDBG_CMD_KLOG_CONNECT` | `0x0D02` | `memdbg_klog_connect_request_t` | `uint32_t klog_port` |
| `MEMDBG_CMD_GET_EXTENDED_CAPS` | `0x0D03` | empty | `uint32_t count` + `uint32_t capability_words[count]` |
| `MEMDBG_CMD_SHUTDOWN` | `0x7F00` | empty | empty |

## Capabilities

Capabilities are advertised by `HELLO.capabilities`. Clients must treat a set
bit as permission to show and attempt that feature. A clear bit means the client
should hide the feature or present it as unavailable. A daemon may still return
`MEMDBG_ERR_UNSUPPORTED` for finer platform restrictions.

| Capability | Bit | Meaning |
|---|---:|---|
| `MEMDBG_CAP_PROCESS_LIST` | 0 | Process enumeration. |
| `MEMDBG_CAP_PROCESS_MAPS` | 1 | Virtual memory map enumeration. |
| `MEMDBG_CAP_MEMORY_READ` | 2 | Process memory reads. |
| `MEMDBG_CAP_MEMORY_WRITE` | 3 | Process memory writes. |
| `MEMDBG_CAP_SCAN_EXACT` | 4 | Range exact-value scanner. |
| `MEMDBG_CAP_UDP_LOG` | 5 | UDP log output. |
| `MEMDBG_CAP_SCAN_PROCESS_EXACT` | 6 | Process-wide exact scanner. |
| `MEMDBG_CAP_SCAN_TELEMETRY` | 7 | Scan timing and read telemetry in responses. |
| `MEMDBG_CAP_PROCESS_INFO` | 8 | Process metadata details. |
| `MEMDBG_CAP_SCAN_AOB` | 9 | Range AOB scanner. |
| `MEMDBG_CAP_SCAN_POINTER` | 10 | Pointer scanner. |
| `MEMDBG_CAP_FOREGROUND_APP` | 11 | Foreground app metadata. |
| `MEMDBG_CAP_PROCESS_CONTROL` | 12 | Stop, continue, and kill commands. |
| `MEMDBG_CAP_BATCH_READ` | 13 | Batch memory reads. |
| `MEMDBG_CAP_PERF_TELEMETRY` | 14 | Daemon telemetry command. |
| `MEMDBG_CAP_SCAN_UNKNOWN` | 15 | Unknown-value scan path. |
| `MEMDBG_CAP_BATCH_WRITE` | 16 | Batch memory writes. |
| `MEMDBG_CAP_LZ4` | 17 | LZ4 framed payload support. |
| `MEMDBG_CAP_SCAN_PROCESS_AOB` | 18 | Process-wide AOB scanner. |
| `MEMDBG_CAP_DISCOVERY` | 19 | UDP discovery. |
| `MEMDBG_CAP_DEBUGGER` | 20 | Debugger attach/control/register path. |
| `MEMDBG_CAP_TRACER` | 21 | Syscall tracer. |
| `MEMDBG_CAP_MEMORY_PROTECT` | 22 | Target memory protection changes. |
| `MEMDBG_CAP_MEMORY_ALLOC` | 23 | Target memory allocation/free. |
| `MEMDBG_CAP_STACK_WALK` | 24 | Server-side stack walk. |
| `MEMDBG_CAP_REMOTE_CALL` | 25 | Remote function call trampoline. |
| `MEMDBG_CAP_KERNEL_ACCESS` | 26 | Kernel base/read/write. |
| `MEMDBG_CAP_CONSOLE_UI` | 27 | Console notification/print/reboot UI. |
| `MEMDBG_CAP_DEBUG_FPREGS` | 28 | Floating point / xstate register access. |
| `MEMDBG_CAP_DEBUG_FSGS` | 29 | FS/GS base access. |
| `MEMDBG_CAP_DISASSEMBLY` | 30 | Assembler/disassembler/xref helpers. |
| `MEMDBG_CAP_KLOG_FORWARD` | 31 | KLOG forwarding. Also currently aliases hijack-capability signaling. |

Extended feature macros such as `MEMDBG_EXT_CAP_QUICKSCAN`,
`MEMDBG_EXT_CAP_PTWALK`, `MEMDBG_EXT_CAP_ALIAS`, `MEMDBG_EXT_CAP_SIMD`,
`MEMDBG_EXT_CAP_KLOG_SERVER`, `MEMDBG_EXT_CAP_AUTH`,
`MEMDBG_EXT_CAP_ARENA`, `MEMDBG_EXT_CAP_BATCH_WRITE_ADV`, and
`MEMDBG_EXT_CAP_HIJACK` describe extension subsystems. Since the `HELLO.capabilities`
word has 32 bits with many already assigned, these extended capabilities are
exposed through `MEMDBG_CMD_GET_EXTENDED_CAPS`. The response body is a single
`uint32_t count` followed by `count` little-endian `uint32_t` capability words.
Clients should call this once after HELLO and cache the mask of supported
extensions.

## Platform IDs

| Platform | Value | Meaning |
|---|---:|---|
| `MEMDBG_PLATFORM_UNKNOWN` | `0` | Unknown or not reported. |
| `MEMDBG_PLATFORM_PS4` | `4` | PS4 payload. |
| `MEMDBG_PLATFORM_PS5` | `5` | PS5 payload. |
| `MEMDBG_PLATFORM_HOST` | `100` | Host daemon build. |

Platform IDs are informational. Capability bits remain authoritative.

## Value Types

Scan commands use `memdbg_value_type_t`.

| Value type | Value | Meaning |
|---|---:|---|
| `MEMDBG_VALUE_BYTES` | `0` | Raw byte sequence. |
| `MEMDBG_VALUE_U8` | `1` | Unsigned 8-bit integer. |
| `MEMDBG_VALUE_U16` | `2` | Unsigned 16-bit integer. |
| `MEMDBG_VALUE_U32` | `3` | Unsigned 32-bit integer. |
| `MEMDBG_VALUE_U64` | `4` | Unsigned 64-bit integer. |
| `MEMDBG_VALUE_F32` | `5` | 32-bit float. |
| `MEMDBG_VALUE_F64` | `6` | 64-bit float. |
| `MEMDBG_VALUE_POINTER` | `7` | Target pointer width value. |

`value_length` must match the selected value type unless the command explicitly
allows arbitrary bytes.

## Process Commands

`PROCESS_LIST` response body is:

```text
uint32_t count
memdbg_process_entry_t entry[count]
```

`PROCESS_MAPS` response body is:

```text
uint32_t count
memdbg_map_entry_t entry[count]
```

`PROCESS_MAPS_V2` carries the same logical body in the standard raw/LZ4
response frame. A client may probe V2 once per connection and fall back to
`PROCESS_MAPS` when an older payload returns `MEMDBG_ERR_UNSUPPORTED` (or the
historical `MEMDBG_ERR_PROTOCOL` used for unknown commands). This preserves
wire compatibility while reducing large map-table transfers on both PS4 and
PS5.

Map protection uses `MEMDBG_MAP_PROT_READ`, `MEMDBG_MAP_PROT_WRITE`, and
`MEMDBG_MAP_PROT_EXEC`.

`PROCESS_INFO` returns a single metadata record for one PID. Fixed strings use
the generic fixed-string rules.

`BATCH_PROCESS_INFO` request body is:

```text
memdbg_batch_process_info_request_t
int32_t pid[count]
```

The response body is:

```text
memdbg_batch_process_info_response_t
memdbg_process_info_response_t entry[count]
```

`PROCESS_PROTECT`, `PROCESS_ALLOC`, and `PROCESS_FREE` are only available when
the corresponding capability bits are present. `PROCESS_ALLOC.flags` bit 0 asks
the platform to honor `hint` when supported.

`PROCESS_STACK` response body is:

```text
memdbg_process_stack_response_prefix_t
memdbg_process_stack_frame_t frame[count]
uint8_t data[data_size]
```

Each frame entry references stack and code bytes by offset into the trailing
data blob.

`PROCESS_CALL` uses the platform debugger/PAL to call one target function with
up to six integer/pointer arguments. On x86-64 targets, arguments map to the
standard `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` order and `rax` is returned.

`PROCESS_ELF_LOAD` and `PROCESS_HIJACK` append ELF bytes to their fixed request
prefix. `target_region` may be empty, otherwise region matching is controlled by
`MEMDBG_MATCH_EXACT`, `MEMDBG_MATCH_CASE_SENSITIVE`, `MEMDBG_MATCH_REGEX`, and
`MEMDBG_MATCH_FULLPATH`.

## Memory Commands

`MEMORY_READ` request body is `memdbg_memory_request_t`. `length` must not
exceed the daemon read limit. The success response body is a framed payload
containing the bytes actually read.

`MEMORY_WRITE` request body is:

```text
memdbg_memory_request_t
uint8_t data[length]
```

The success response body is optional. When present it contains a
little-endian `uint32_t` with the bytes actually written. A `MEMDBG_OK`
status with an empty body means all bytes were written successfully. A
partial write returns `MEMDBG_ERR_IO`.

`BATCH_READ` request body is:

```text
memdbg_batch_read_request_t
memdbg_batch_read_item_t item[count]
```

The response body is:

```text
memdbg_batch_read_result_entry_t result[count]
framed_data
```

Each result entry reports the requested address, bytes read, and per-item
status. Successful item bytes are concatenated in item order in `framed_data`.

`BATCH_WRITE` request body is:

```text
memdbg_batch_write_request_t
repeat count times:
  memdbg_batch_write_item_t item
  uint8_t data[item.length]
```

The response body is `memdbg_batch_write_result_entry_t result[count]`. The
response header status is `MEMDBG_OK` unless the streamed request itself is
malformed; individual failures are encoded per entry.

## Scanner Commands

Standard scanner responses use:

```text
memdbg_scan_response_prefix_t
entry[count]
```

The prefix includes `count`, `truncated`, `bytes_scanned`, `elapsed_ns`,
`read_calls`, `regions_scanned`, and `read_errors`. Exact, process-exact,
unknown, AOB, and process-AOB scans use `memdbg_scan_result_entry_t`. Pointer
scan uses `memdbg_pointer_chain_entry_t`, whose `base_address` is the primary
address.

AOB request bodies are:

```text
memdbg_scan_aob_request_t or memdbg_scan_process_aob_request_t
uint8_t pattern[pattern_length]
uint8_t mask[pattern_length]
```

A non-zero mask byte means the corresponding pattern byte must match. A zero
mask byte is a wildcard.

If `max_results` is zero or greater than the daemon limit, the daemon clamps it
to the configured default.

## Debugger Commands

The debugger command family operates on the daemon's active debug session.
`DEBUG_ATTACH` may stop an active tracer first because the tracer and debugger
both own ptrace-style process control.

Thread lists are encoded as:

```text
memdbg_debug_threads_response_prefix_t
memdbg_debug_thread_entry_t entry[count]
```

`memdbg_debug_thread_entry_t` includes thread id, abstract thread state, stop
information, scheduling fields, and a fixed-size thread name.

General registers use `memdbg_debug_regs_t`. Debug registers use
`memdbg_debug_dbregs_t`. Floating point/xstate registers use
`memdbg_debug_fpregs_t`, where `length` declares the valid byte count inside the
fixed 1024-byte data buffer.

Breakpoint and watchpoint list responses use a count prefix followed by fixed
entries. `DEBUG_SET_BREAKPOINT` remains the legacy unconditional breakpoint
request. `DEBUG_SET_BREAKPOINT_COND` extends it with `cond_reg`, `cond_op`, and
`cond_value`; `cond_reg = 0` means unconditional.

`DEBUG_POLL_EVENTS` returns `memdbg_debug_poll_response_t`, where `stopped`
indicates whether the attached process is stopped and `stop_lwp` identifies the
thread when known.

## Tracer Commands

The tracer is a daemon-owned syscall/crash event recorder. It is separate from
the debugger but targets the same kind of process-control surface.

`TRACER_ATTACH` takes `memdbg_tracer_attach_request_t`. `TRACER_POLL` returns:

```text
memdbg_tracer_poll_response_prefix_t
memdbg_tracer_event_t event[count]
```

Event types are:

- `1`: syscall entry;
- `2`: syscall exit;
- `3`: signal;
- `4`: crash.

`TRACER_STATUS` returns `memdbg_tracer_status_response_t`, including state,
event count, crash signal, elapsed time, and optional dump path.

## Kernel And Page-Table Commands

Kernel access commands require `MEMDBG_CAP_KERNEL_ACCESS`.

`KERNEL_BASE` returns text and data base addresses. `KERNEL_READ` returns raw
bytes; unlike process `MEMORY_READ`, it is not wrapped in the LZ4 sub-frame.
`KERNEL_WRITE` appends bytes after `memdbg_kernel_memory_request_t`.

Page-table walk commands are an introspection extension:

- `PTWALK_DISCOVER` returns DMAP and pmap layout hints.
- `PTWALK_AUGMENT` reuses process map output with page-table augmentation.
- `PTWALK_READ` and `PTWALK_WRITE` access target memory through ptwalk helpers.
- `PTWALK_PROBE` returns physical address, page size, raw PTE, level, and cache
  attribute information for one virtual address.

These commands should be hidden unless the payload advertises or otherwise
proves the relevant ptwalk extension support.

## Assembler And Disassembler Commands

`ASM_ENCODE` request body is:

```text
memdbg_asm_encode_request_t
uint8_t source[length - sizeof(prefix)]
```

The source is UTF-8 assembly text. Success returns `memdbg_asm_encode_ok_t`
followed by encoded machine code. Assembly errors return an error prefix and a
UTF-8 message using the command's own body format.

`DISASM` and `XREFS_TO` accept one or more fixed request records in a single
command body. The daemon validates that the body contains at least one complete
record and returns command-specific records.

Clients should gate this family on `MEMDBG_CAP_DISASSEMBLY`.

## QuickScan Commands

QuickScan, also called FlashScan in the implementation, is a server-resident
scan engine. It can keep survivor lists on the payload, use snapshots, and
materialize paged result windows.

`QUICKSCAN_CAPS` returns engine-local capabilities:

| Flag | Meaning |
|---|---|
| `MEMDBG_QS_F_SIMD` | SIMD compare support. |
| `MEMDBG_QS_F_RESIDENT` | Server-kept result sets. |
| `MEMDBG_QS_F_SNAPSHOT` | Snapshot scan support. |
| `MEMDBG_QS_F_SNAP_SEGMENTS` | Disjoint snapshot segments. |
| `MEMDBG_QS_F_SNAP_CONFIG` | Configurable snapshot storage. |
| `MEMDBG_QS_F_SNAP_FIRST` | Compare against first snapshot. |
| `MEMDBG_QS_F_SNAP_PREVIOUS` | Compare against previous snapshot. |
| `MEMDBG_QS_F_PARALLEL` | Parallel scan workers. |
| `MEMDBG_QS_F_ALIAS_RESCAN` | Alias-assisted rescan path. |

Request flags mirror many engine flags:

| Flag | Meaning |
|---|---|
| `MEMDBG_QS_FL_ALIAS_READ` | Use alias read path when available. |
| `MEMDBG_QS_FL_SERVER_KEEP` | Keep results server-side. |
| `MEMDBG_QS_FL_SNAPSHOT` | Build or use snapshot state. |
| `MEMDBG_QS_FL_SNAP_NOZERO` | Drop zero-valued snapshot slots. |
| `MEMDBG_QS_FL_SNAP_SEGMENTS` | Use segment descriptors. |
| `MEMDBG_QS_FL_SNAP_FIRST` | Compare against first snapshot. |
| `MEMDBG_QS_FL_SNAP_PREVIOUS` | Compare against previous snapshot. |
| `MEMDBG_QS_FL_PARALLEL` | Enable parallel worker mode. |
| `MEMDBG_QS_FL_ALIAS_RESCAN` | Enable alias rescan mode. |

`QUICKSCAN_START` and `QUICKSCAN_COUNT` append compare bytes after their fixed
prefix. Between comparisons append two values. AOB-style values additionally
append a mask of `value_length` bytes.

`MEMDBG_QS_FL_SNAP_SEGMENTS` is not advertised or accepted by the framed v1
transport. The original engine attempted to read the segment count and records
directly from the socket after the request frame, which could consume the next
packet and permanently desynchronize a pooled connection. Disjoint segments
will require a future framed command version in which the count and every
descriptor are included in the declared request body.

`QUICKSCAN_FETCH` pages resident results with `start_index` and `count`.
`QUICKSCAN_END` releases server-side state. `QUICKSCAN_CANCEL` immediately
aborts any in-progress scan and frees its resources without waiting for
completion. `QUICKSCAN_CONFIG` may append a
spill-directory path. `QUICKSCAN_REGIONS` probes candidate regions and returns
`memdbg_quickscan_region_info` records.

Because QuickScan is stateful, clients should treat `MEMDBG_ERR_STATE` as a
normal conflict signal and expose an explicit end/reset action.

## Discovery

UDP discovery uses two packed structs that reuse `MEMDBG_PACKET_MAGIC`.

The frontend sends `memdbg_discovery_ping_t` to the broadcast address on
`discovery_port`. Payloads reply directly to the sender with
`memdbg_discovery_response_t`, which mirrors the important fields from `HELLO`.

Discovery is advisory. Clients must still open a TCP connection and run `HELLO`
before enabling features.

## KLOG Streaming

`KLOG_CONNECT` is sent over the main TCP control socket with
`memdbg_klog_connect_request_t`. On supported payloads the response body is a
little-endian `uint32_t` TCP port. The client then opens a separate TCP
connection to that port and consumes kernel-log text from that stream.

On unsupported platforms, the response header status is
`MEMDBG_ERR_UNSUPPORTED` and the body is empty.

## Compatibility Rules

Protocol version 1 follows these compatibility rules:

- Command ids, status values, platform ids, and value-type ids are never reused.
- Existing fixed structs may only gain meaning in reserved fields; their size
  must not change in protocol version 1.
- Variable-length extensions must be appended after a fixed prefix and guarded
  by an explicit size, count, flag, or capability bit.
- Clients must ignore unknown capability bits and unsupported command families.
- Daemons must return `MEMDBG_ERR_PROTOCOL` for malformed frames and
  `MEMDBG_ERR_UNSUPPORTED` for valid but unavailable features.
- New optional features require a capability bit, a command-local caps response,
  or a protocol version bump.
- A future protocol version may negotiate extended capabilities after `HELLO`,
  but version 1 clients must keep working against the original `HELLO` body.

## Client Implementation Checklist

A compliant client should:

1. Open TCP to `debug_port`.
2. Send `HELLO` with a non-zero `request_id`.
3. Validate response header fields and `HELLO.protocol_version`.
4. Store capability bits and platform id.
5. Gate optional command families from capabilities.
6. Send requests sequentially per socket, optionally pipelining N requests in a single TCP write for reduced latency.
7. Check `status` before parsing response bodies.
8. Apply command-local decompression only for framed payload commands.
9. Validate every response count and length before indexing arrays.
10. Treat `MEMDBG_ERR_STATE`, `MEMDBG_ERR_UNSUPPORTED`, and
    `MEMDBG_ERR_PERMISSION` as expected runtime outcomes, not transport errors.

## Extension Checklist

When adding a new command or payload extension:

1. Reserve a command id in the appropriate family range.
2. Add packed request/response structs to `memdbg_protocol.h`.
3. Add or document the capability bit that gates the feature.
4. Validate body size and inline lengths before dereferencing in the daemon.
5. Return `MEMDBG_ERR_PARAM` for bad values and `MEMDBG_ERR_PROTOCOL` for bad
   framing.
6. Keep response bodies bounded by `MEMDBG_PROTOCOL_MAX_PACKET` unless the
   command explicitly streams or pages data.
7. Add client parsing that verifies counts and lengths before use.
8. Add an E2E or protocol unit test for the frame shape.
9. Update this document and the command registry in the same change.

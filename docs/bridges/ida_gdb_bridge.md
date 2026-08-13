# IDA GDB Bridge

*Available in: [English](ida_gdb_bridge.md) · [Italiano](../i18n/ida_gdb_bridge.it.md)*

Host-side proxy that exposes a **GDB Remote Serial Protocol (RSP)** endpoint for
IDA Pro’s Remote GDB Debugger, translating packets onto MemDBG’s native `MDBG`
protocol (TCP `9020`).

This is the implementation for [issue #37](https://github.com/seregonwar/MemDBG/issues/37).

## Architecture

```
IDA Pro (Remote GDB)  --RSP-->  memdbg_gdb_bridge  --MDBG-->  console payload
     127.0.0.1:23946              (host PC)                   IP:9020
```

The payload is unchanged. The bridge reuses the same frontend `Client` used by
`memdbg_probe` and the desktop UI.

## Build

Release binaries ship `memdbg_gdb_bridge` inside
`MemDBG-frontend-{linux,macos,windows}` and as standalone
`MemDBG-ida-gdb-bridge-{linux,macos,windows}` assets on GitHub Releases / nightlies.

Official targets live in the frontend CMake project (`memdbg_gdb_bridge`,
`memdbg_gdb_bridge_test`). For a faster host-only build that skips ImGui/GLFW
FetchContent:

```bash
cmake -S tools/gdb_bridge -B build/gdb_bridge
cmake --build build/gdb_bridge --config Release --target memdbg_gdb_bridge memdbg_gdb_bridge_test
# or: make gdb-bridge && make test-gdb-bridge
```

```bash
cmake --build <frontend-build-dir> --target memdbg_gdb_bridge memdbg_gdb_bridge_test
```

## Usage

```text
memdbg_gdb_bridge --host 192.168.1.50 --port 9020 \
                  --listen 127.0.0.1:23946 --pid 123

# or resolve by process name:
memdbg_gdb_bridge --host 192.168.1.50 --name eboot.bin --verbose
```

Release packages ship `memdbg_gdb_bridge` inside the frontend archives and as a
standalone asset (`MemDBG-ida-gdb-bridge-{windows,linux,macos}`).

| Flag | Meaning |
|---|---|
| `--host` | Console IP / hostname (required) |
| `--port` | MDBG debug port (default `9020`) |
| `--listen` | RSP bind address (`[host:]port`, default `127.0.0.1:23946`) |
| `--pid` | Optional PID (**decimal**) to attach on first halt (`?`) |
| `--name` | Resolve PID via `process_list` (e.g. `eboot.bin`) |
| `--verbose` | Also log RSP replies and MDBG attach/continue/detach details |
| `--once` | Exit after the first GDB/IDA client disconnects |

The bridge prints the current process list immediately after connecting to the
payload, so a PID can be selected without opening the desktop frontend. Incoming
GDB/IDA commands, replies, and the MDBG debugger lifecycle are logged with
`--verbose`; binary packet bytes are escaped before printing. It pings the payload every ~10s (idle
timeout is 30s). During detach it stops the target first, restores debugger
state, and lets `PT_DETACH` resume execution safely.

## IDA Pro setup

1. Start the MemDBG payload on the console and confirm port `9020` is reachable.
2. Run `memdbg_gdb_bridge` as above.
3. In IDA: **Debugger → Attach → Remote GDB debugger**.
4. Hostname `127.0.0.1`, port `23946`.
5. In debugger-specific options, set CPU to **x86_64** / `metapc`.
6. Attach to the process. RSP `vAttach` PIDs are **hexadecimal**: decimal `88`
   must be entered as `58`, or prefer `--pid`/`--name` on the bridge.

You can also use stock GDB:

```text
(gdb) target remote 127.0.0.1:23946
```

## Supported RSP subset

- `qSupported`, `QStartNoAckMode`, `QNonStop:0`, `qAttached`, `qC`, `qHostInfo`, `qOffsets`, `qSymbol`
- Threads: `qfThreadInfo` / `qsThreadInfo`, `qThreadExtraInfo`, `qThreadStopInfo`, `qXfer:threads:read`, `H`, `T`
- `qXfer:features:read` → the intentionally minimal `i386:x86-64` target description used by IDA
- `qXfer:memory-map:read` → map from `process_maps` (`ram` entries)
- `qXfer:libraries:read`, `qXfer:exec-file:read`, `qXfer:osdata:read:processes`
- `qMemoryRegionInfo` and `qSearch:memory`
- `vAttach`, validated `vCont` (`c`/`C`/`s`/`S`), `vKill`, `?`, `D`, `k`
- Registers: `g` / `G` / `p` / `P` (GPR, x87 and SSE via FXSAVE / `debug_get_fpregs`)
- Memory: `m` / `M` / binary `X`, with mapped-range and overflow validation
- Breakpoints: `Z0`/`z0` (software), `Z1`/`z1` (hardware)
- Watchpoints: `Z2`–`Z4` / `z2`–`z4`
- Stop replies via polling `DEBUG_POLL_EVENTS` (all-stop); Ctrl-C → `debug_stop`

Process attach uses bridge `--pid` / `--name` (or IDA `vAttach` in hex). The OS
process list and loaded image mappings are also available through RSP XML.

Unsupported packets receive an empty RSP reply (`$#00`).

## Limits

- Single attached PID (same constraint as the MemDBG debugger session).
- All-stop only (no GDB non-stop mode).
- No `vRun` / spawn, no on-console `gdbsrv`.
- The target description stays minimal for IDA compatibility; x87/SSE remain
  available through individual `p`/`P` packets.

## Source

| Path | Role |
|---|---|
| [`tools/gdb_bridge/`](../../tools/gdb_bridge/) | Bridge sources |
| [`tools/gdb_bridge/gdb_regs.cpp`](../../tools/gdb_bridge/gdb_regs.cpp) | FreeBSD/`memdbg_debug_regs_t` ↔ GDB register order |
| [`tools/gdb_bridge/rsp_handler.cpp`](../../tools/gdb_bridge/rsp_handler.cpp) | Session state and packet dispatcher |
| [`tools/gdb_bridge/rsp_handler_query.cpp`](../../tools/gdb_bridge/rsp_handler_query.cpp) | Queries and XML transfers |
| [`tools/gdb_bridge/rsp_handler_memory.cpp`](../../tools/gdb_bridge/rsp_handler_memory.cpp) | Memory read/write/search |
| [`tools/gdb_bridge/rsp_handler_registers.cpp`](../../tools/gdb_bridge/rsp_handler_registers.cpp) | Core, x87 and SSE register packets |
| [`tools/gdb_bridge/rsp_handler_run.cpp`](../../tools/gdb_bridge/rsp_handler_run.cpp) | Attach, resume, step and breakpoints |
| [`tools/gdb_bridge/rsp_protocol.cpp`](../../tools/gdb_bridge/rsp_protocol.cpp) | Strict parsing and shared RSP primitives |
| [`tools/gdb_bridge/rsp_backend.cpp`](../../tools/gdb_bridge/rsp_backend.cpp) | Production `Client` adapter; tests use a deterministic fake backend |

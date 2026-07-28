# x64dbg bridge for MemDBG

Host plugin that connects **x64dbg** to a MemDBG payload over the native
`MDBG` protocol (TCP `9020`), without going through GDB RSP.

Implements [issue #39](https://github.com/seregonwar/MemDBG/issues/39)
(bridge half; the UI disassembly fix is separate and uses Zydis in the frontend).

## Architecture

```
x64dbg (MemDBG.dp64 plugin)  --MDBG-->  console payload
        (host PC)                       IP:9020
```

The payload is unchanged. The plugin reuses the same frontend `Client` as
`memdbg_gdb_bridge` and the desktop UI.

> Note: x64dbg is **not** a native GDB client, so it does not reuse
> `memdbg_gdb_bridge`. For IDA/GDB keep using the RSP bridge (#37).

## Build

Official / nightly releases publish `MemDBG-x64dbg-plugin.zip` with a
prebuilt `MemDBG.dp64` (job `plugin-x64dbg`).

CMake automatically downloads the official
[`x64dbg-pluginsdk-cmake.zip`](https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk-cmake.zip)
(release **2026.05.27**: headers + `x64dbg.lib` / `x64bridge.lib`). Requires **Windows** and an MSVC x64 toolchain.

```bash
cmake -S tools/x64dbg_plugin -B build/x64dbg_plugin -A x64
cmake --build build/x64dbg_plugin --config Release --target memdbg_x64dbg_plugin
# or: make x64dbg-plugin
```

To use an already-extracted SDK (same layout as the cmake zip):

```bash
cmake -S tools/x64dbg_plugin -B build/x64dbg_plugin -A x64 \
  -DMEMDBG_X64DBG_SDK=/path/to/x64dbg-pluginsdk-cmake
```

Copy `MemDBG.dp64` into x64dbg’s `plugins` folder (x64 build).

## Usage

1. Start the MemDBG payload on the console (`9020` reachable).
2. Start x64dbg and confirm the plugin loaded (`[MemDBG] plugin loaded`).
3. In the x64dbg command bar:

```text
MemDBGConnect 192.168.1.50 9020
MemDBGAttach 123
MemDBGRegs
MemDBGRead 0x200000000 128
MemDBGBp 0x200001234
MemDBGStep
MemDBGContinue
MemDBGStop
MemDBGDetach
MemDBGDisconnect
```

**Plugins → MemDBG** exposes the same actions (argument-bearing ops use the
commands above).

## Commands

| Command | Meaning |
|---|---|
| `MemDBGConnect <host> [port]` | MDBG hello (default port `9020`) |
| `MemDBGDisconnect` | Close session |
| `MemDBGAttach <pid>` | Debugger attach |
| `MemDBGDetach` | Detach |
| `MemDBGStop` / `MemDBGContinue` / `MemDBGStep` | All-stop run-control |
| `MemDBGRegs` | Dump GPRs |
| `MemDBGRead <addr> [len]` | Hex dump (default 64, max 1 MiB) |
| `MemDBGWrite <addr> <hex>` | Write bytes (e.g. `90 90 C3`) |
| `MemDBGBp <addr>` / `MemDBGHwBp <addr>` / `MemDBGBc <addr>` | Soft/HW breakpoint |
| `MemDBGWatch <addr> [len] [r\|w\|rw\|x]` | Hardware watchpoint (default len=8, type=w) |
| `MemDBGUnwatch <addr>` | Clear watchpoint |
| `MemDBGPoll` | Poll stop events (updates LWP; syncs CPU/Dump on stop) |
| `MemDBGSetReg <name> <value>` | Write a GPR (`rax`…`rip`, `rflags`) |
| `MemDBGMaps` | List process memory maps |
| `MemDBGFpRegs` | Dump MXCSR + XMM0–15 (FXSAVE) |
| `MemDBGSync [dump_addr]` | Anchor CPU@RIP and Dump@RSP (or `dump_addr`) via `GuiDisasmAt`/`GuiDumpAt` |

## Limits

- Single attached PID (same as MemDBG debugger sessions).
- All-stop only; no non-stop.
- Does not replace x64dbg’s TitanEngine: ops go through plugin commands.
  `MemDBGSync` moves CIP/VA in the native views, but those views still read the
  **local** TitanEngine debuggee (not remote PS4/PS5 memory).
- X87 st0–st7 not pretty-printed (FXSAVE XMM/MXCSR yes).

## Sources

| Path | Role |
|---|---|
| [`tools/x64dbg_plugin/`](../tools/x64dbg_plugin/) | Plugin + MDBG session |
| [`memdbg_session.*`](../tools/x64dbg_plugin/memdbg_session.cpp) | Thread-safe `Client` wrapper |
| [`plugin_util.*`](../tools/x64dbg_plugin/plugin_util.cpp) | Parse/GPR/sync plan (unit-tested) |
| [`plugin_main.cpp`](../tools/x64dbg_plugin/plugin_main.cpp) | x64dbg exports + commands/menus |

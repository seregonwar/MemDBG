# Bridge x64dbg per MemDBG

Plugin host che collega **x64dbg** al payload MemDBG tramite il protocollo
nativo `MDBG` (TCP `9020`), senza passare da GDB RSP.

Implementazione di [issue #39](https://github.com/seregonwar/MemDBG/issues/39)
(parte bridge; il fix del disassembly UI è separato e usa Zydis nel frontend).

## Architettura

```
x64dbg (plugin MemDBG.dp64)  --MDBG-->  payload console
        (PC host)                        IP:9020
```

Il payload non viene modificato. Il plugin riusa lo stesso `Client` del frontend
usato da `memdbg_gdb_bridge` e dall’UI desktop.

> Nota: x64dbg **non** è un client GDB nativo, quindi non riusa
> `memdbg_gdb_bridge`. Per IDA/GDB resta il bridge RSP (#37).

## Build

Il CMake scarica automaticamente l’SDK ufficiale
[`x64dbg-pluginsdk-cmake.zip`](https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk-cmake.zip)
(release **2026.05.27**: header + `x64dbg.lib` / `x64bridge.lib`). Richiede **Windows** e un toolchain MSVC x64.

```bash
cmake -S tools/x64dbg_plugin -B build/x64dbg_plugin -A x64
cmake --build build/x64dbg_plugin --config Release --target memdbg_x64dbg_plugin
# oppure: make x64dbg-plugin
```

Per usare un SDK già espanso (stesso layout del zip cmake):

```bash
cmake -S tools/x64dbg_plugin -B build/x64dbg_plugin -A x64 \
  -DMEMDBG_X64DBG_SDK=/path/to/x64dbg-pluginsdk-cmake
```

Copia `MemDBG.dp64` nella cartella `plugins` di x64dbg (build x64).

## Uso

1. Avvia il payload MemDBG sulla console (porta `9020` raggiungibile).
2. Avvia x64dbg e verifica che il plugin sia caricato (log `[MemDBG] plugin loaded`).
3. Nella console comandi di x64dbg:

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

Il menu **Plugins → MemDBG** espone le stesse azioni (per connect/attach/read/BP
usa i comandi con argomenti).

## Comandi

| Comando | Significato |
|---|---|
| `MemDBGConnect <host> [port]` | Hello MDBG (default port `9020`) |
| `MemDBGDisconnect` | Chiude la sessione |
| `MemDBGAttach <pid>` | Attach debugger |
| `MemDBGDetach` | Detach |
| `MemDBGStop` / `MemDBGContinue` / `MemDBGStep` | Run-control all-stop |
| `MemDBGRegs` | Dump GPR |
| `MemDBGRead <addr> [len]` | Hex dump (default 64, max 1 MiB) |
| `MemDBGWrite <addr> <hex>` | Write bytes (es. `90 90 C3`) |
| `MemDBGBp <addr>` / `MemDBGHwBp <addr>` / `MemDBGBc <addr>` | Soft/HW breakpoint |
| `MemDBGWatch <addr> [len] [r\|w\|rw\|x]` | Hardware watchpoint (default len=8, type=w) |
| `MemDBGUnwatch <addr>` | Clear watchpoint |
| `MemDBGPoll` | Poll stop events (aggiorna LWP; sync CPU/Dump se stoppato) |
| `MemDBGSetReg <name> <value>` | Scrive un GPR (`rax`…`rip`, `rflags`) |
| `MemDBGMaps` | Elenca le mappe di memoria del PID |
| `MemDBGFpRegs` | Dump MXCSR + XMM0–15 (FXSAVE) |
| `MemDBGSync [dump_addr]` | Ancora CPU@RIP e Dump@RSP (o `dump_addr`) via `GuiDisasmAt`/`GuiDumpAt` |

## Limiti

- Un solo PID attached (stesso vincolo della sessione debugger MemDBG).
- Solo all-stop; niente non-stop.
- Non sostituisce il motore TitanEngine di x64dbg: ops via comandi plugin.
  `MemDBGSync` sposta CIP/VA nelle view native, ma quelle view leggono il
  debuggee **locale** TitanEngine (non la memoria remota PS4/PS5).
- X87 st0–st7 non formattati (blob FXSAVE sì per XMM/MXCSR).

## Sorgenti

| Path | Ruolo |
|---|---|
| [`tools/x64dbg_plugin/`](../tools/x64dbg_plugin/) | Plugin + sessione MDBG |
| [`memdbg_session.*`](../tools/x64dbg_plugin/memdbg_session.cpp) | Wrapper thread-safe sul `Client` |
| [`plugin_util.*`](../tools/x64dbg_plugin/plugin_util.cpp) | Parse/GPR/sync plan (unit-testati) |
| [`plugin_main.cpp`](../tools/x64dbg_plugin/plugin_main.cpp) | Export x64dbg + comandi/menu |

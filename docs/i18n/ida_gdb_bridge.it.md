# Bridge GDB per IDA

*Disponibile in: [English](../bridges/ida_gdb_bridge.md) · [Italiano](ida_gdb_bridge.it.md)*

Proxy host che espone un endpoint **GDB Remote Serial Protocol (RSP)** per il
Remote GDB Debugger di IDA Pro, traducendo i pacchetti sul protocollo nativo
MemDBG `MDBG` (TCP `9020`).

Implementazione di [issue #37](https://github.com/seregonwar/MemDBG/issues/37).

## Architettura

```
IDA Pro (Remote GDB)  --RSP-->  memdbg_gdb_bridge  --MDBG-->  payload console
     127.0.0.1:23946              (PC host)                   IP:9020
```

Il payload non viene modificato. Il bridge riusa lo stesso `Client` del frontend
usato da `memdbg_probe` e dall’UI desktop.

## Build

I binary di release includono `memdbg_gdb_bridge` nei pacchetti
`MemDBG-frontend-{linux,macos,windows}` e come asset standalone
`MemDBG-ida-gdb-bridge-{linux,macos,windows}` su GitHub Releases / nightly.

I target ufficiali sono nel CMake del frontend (`memdbg_gdb_bridge`,
`memdbg_gdb_bridge_test`). Per una build host più veloce senza FetchContent
ImGui/GLFW:

```bash
cmake -S tools/gdb_bridge -B build/gdb_bridge
cmake --build build/gdb_bridge --config Release --target memdbg_gdb_bridge memdbg_gdb_bridge_test
# oppure: make gdb-bridge && make test-gdb-bridge
```

```bash
cmake --build <frontend-build-dir> --target memdbg_gdb_bridge memdbg_gdb_bridge_test
```

## Uso

```text
memdbg_gdb_bridge --host 192.168.1.50 --port 9020 \
                  --listen 127.0.0.1:23946 --pid 123

# oppure per nome processo:
memdbg_gdb_bridge --host 192.168.1.50 --name eboot.bin --verbose
```

I pacchetti di release includono `memdbg_gdb_bridge` negli archivi frontend e
come asset dedicato (`MemDBG-ida-gdb-bridge-{windows,linux,macos}`).

| Flag | Significato |
|---|---|
| `--host` | IP / hostname della console (obbligatorio) |
| `--port` | Porta debug MDBG (default `9020`) |
| `--listen` | Indirizzo RSP (`[host:]port`, default `127.0.0.1:23946`) |
| `--pid` | PID opzionale (**decimale**) da attachare al primo halt (`?`) |
| `--name` | Risolve il PID via `process_list` (es. `eboot.bin`) |
| `--verbose` | Registra anche risposte RSP e dettagli attach/continue/detach MDBG |
| `--once` | Esci dopo la disconnessione del primo client GDB/IDA |

Subito dopo la connessione al payload il bridge stampa l'elenco dei processi,
permettendo di scegliere il PID senza aprire il frontend desktop. I comandi
GDB/IDA, le risposte e il ciclo di vita del debugger MDBG vengono registrati con
`--verbose`; i byte binari sono sottoposti a escaping prima della stampa. Il bridge fa ping al payload ogni
~10s (idle timeout 30s). Durante il detach ferma prima il target, ripristina lo
stato del debugger e lascia che `PT_DETACH` riprenda l'esecuzione in sicurezza.

## Setup IDA Pro

1. Avvia il payload MemDBG sulla console e verifica che la porta `9020` sia raggiungibile.
2. Lancia `memdbg_gdb_bridge` come sopra.
3. In IDA: **Debugger → Attach → Remote GDB debugger**.
4. Hostname `127.0.0.1`, porta `23946`.
5. Nelle opzioni specifiche del debugger, imposta la CPU su **x86_64** / `metapc`.
6. Fai attach. I PID di `vAttach` RSP sono **esadecimali**: il decimale `88`
   va inserito come `58`, oppure usa `--pid`/`--name` sul bridge.

Oppure con GDB stock:

```text
(gdb) target remote 127.0.0.1:23946
```

## Subset RSP supportato

- `qSupported`, `QStartNoAckMode`, `QNonStop:0`, `qAttached`, `qC`, `qHostInfo`, `qOffsets`, `qSymbol`
- Thread: `qfThreadInfo` / `qsThreadInfo`, `qThreadExtraInfo`, `qThreadStopInfo`, `qXfer:threads:read`, `H`, `T`
- `qXfer:features:read` → descrizione target minimale `i386:x86-64`, mantenuta per compatibilità IDA
- `qXfer:memory-map:read` → mappa da `process_maps` (tipo `ram`)
- `qXfer:libraries:read`, `qXfer:exec-file:read`, `qXfer:osdata:read:processes`
- `qMemoryRegionInfo` e `qSearch:memory`
- `vAttach`, `vCont` validato (`c`/`C`/`s`/`S`), `vKill`, `?`, `D`, `k`
- Registri: `g` / `G` / `p` / `P` (GPR, x87 e SSE via FXSAVE/`debug_get_fpregs`)
- Memoria: `m` / `M` / `X` binario, con validazione mapping e overflow
- Breakpoint: `Z0`/`z0` (software), `Z1`/`z1` (hardware)
- Watchpoint: `Z2`–`Z4` / `z2`–`z4`
- Stop reply via polling `DEBUG_POLL_EVENTS` (all-stop); Ctrl-C → `debug_stop`

I breakpoint software (`Z0`) scrivono un INT3 (`0xCC`) nel target, come farebbe
un vero stub GDB. Il bridge ricorda il byte originale di ogni breakpoint inserito
e lo rimaschera nelle letture di memoria, così IDA disassembla l’istruzione reale
invece di `db 0CCh`; gli hit dei breakpoint riportano il motivo `swbreak:` standard.

L’attach di processo usa `--pid` / `--name` sul bridge (oppure `vAttach` IDA in
hex). La lista processi e i mapping delle immagini caricate sono disponibili
anche tramite XML RSP.

I pacchetti non supportati ricevono una risposta RSP vuota (`$#00`).

## Limiti

- Un solo PID attached (stesso vincolo della sessione debugger MemDBG).
- Solo all-stop (niente non-stop GDB).
- Niente `vRun` / spawn, niente `gdbsrv` on-console.
- La descrizione target resta minimale per compatibilità IDA; x87/SSE sono
  comunque disponibili tramite pacchetti individuali `p`/`P`.

## Sorgenti

| Path | Ruolo |
|---|---|
| [`tools/gdb_bridge/`](../../tools/gdb_bridge/) | Sorgenti del bridge |
| [`tools/gdb_bridge/gdb_regs.cpp`](../../tools/gdb_bridge/gdb_regs.cpp) | Mapping FreeBSD/`memdbg_debug_regs_t` ↔ ordine registri GDB |
| [`tools/gdb_bridge/rsp_handler.cpp`](../../tools/gdb_bridge/rsp_handler.cpp) | Stato sessione e dispatcher pacchetti |
| [`tools/gdb_bridge/rsp_handler_query.cpp`](../../tools/gdb_bridge/rsp_handler_query.cpp) | Query e trasferimenti XML |
| [`tools/gdb_bridge/rsp_handler_memory.cpp`](../../tools/gdb_bridge/rsp_handler_memory.cpp) | Lettura, scrittura e ricerca memoria |
| [`tools/gdb_bridge/rsp_handler_registers.cpp`](../../tools/gdb_bridge/rsp_handler_registers.cpp) | Pacchetti registri core, x87 e SSE |
| [`tools/gdb_bridge/rsp_handler_run.cpp`](../../tools/gdb_bridge/rsp_handler_run.cpp) | Attach, resume, step e breakpoint |
| [`tools/gdb_bridge/rsp_protocol.cpp`](../../tools/gdb_bridge/rsp_protocol.cpp) | Parsing rigoroso e primitive RSP comuni |
| [`tools/gdb_bridge/rsp_backend.cpp`](../../tools/gdb_bridge/rsp_backend.cpp) | Adattatore `Client`; i test usano un backend finto deterministico |

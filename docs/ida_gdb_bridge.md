# Bridge GDB per IDA

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
| `--verbose` | Log pacchetti RSP e attach/continue/detach MDBG |
| `--once` | Esci dopo la disconnessione del primo client GDB/IDA |

Il bridge fa ping al payload ogni ~10s (idle timeout 30s) e fa resume del
target prima del detach così il processo console non resta congelato.

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

- `qSupported`, `QStartNoAckMode`, `qAttached`, `qC`
- Thread: `qfThreadInfo` / `qsThreadInfo`, `qThreadExtraInfo` (nome), `H`, `T`
- `qXfer:features:read` → XML core GPR + SSE (`xmm0`–`xmm15`, `mxcsr`)
- `qXfer:memory-map:read` → mappa da `process_maps` (tipo `ram`)
- `vAttach`, `vCont` (`c`/`s`), `?`, `D`
- Registri: `g` / `G` / `p` / `P` (GPR + SSE via FXSAVE/`debug_get_fpregs`)
- Memoria: `m` / `M`
- Breakpoint: `Z0`/`z0` (software), `Z1`/`z1` (hardware)
- Watchpoint: `Z2`–`Z4` / `z2`–`z4`
- Stop reply via polling `DEBUG_POLL_EVENTS` (all-stop); Ctrl-C → `debug_stop`

L’attach di processo usa `--pid` / `--name` sul bridge (oppure `vAttach` IDA in
hex). Non c’è process-list OS via RSP (`qXfer:osdata`); PS3 / moduli stile
deci3dbg sono fuori scope.

I pacchetti non supportati ricevono una risposta RSP vuota (`$#00`).

## Limiti

- Un solo PID attached (stesso vincolo della sessione debugger MemDBG).
- Solo all-stop (niente non-stop GDB).
- Niente `vRun` / spawn, niente `gdbsrv` on-console.
- X87 (st0–st7 / fctrl…) non ancora in `target.xml` (SSE sì).

## Sorgenti

| Path | Ruolo |
|---|---|
| [`tools/gdb_bridge/`](../tools/gdb_bridge/) | Sorgenti del bridge |
| [`tools/gdb_bridge/gdb_regs.cpp`](../tools/gdb_bridge/gdb_regs.cpp) | Mapping FreeBSD/`memdbg_debug_regs_t` ↔ ordine registri GDB |
| [`tools/gdb_bridge/rsp_handler.cpp`](../tools/gdb_bridge/rsp_handler.cpp) | RSP → API debug/memoria del `Client` |

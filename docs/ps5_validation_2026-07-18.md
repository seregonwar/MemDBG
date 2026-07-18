# PS5 Protocol, Stability, and Performance Validation

- **Validation date:** 2026-07-18
- **Payload:** MemDBG 0.2.0-beta.2
- **Platform:** PlayStation 5
- **Protocol:** feature level 2, wire version 1
- **Target:** live `eboot.bin`, PID 95
- **Native endpoint:** TCP 9020
- **Legacy endpoint:** TCP 744

## Executive Summary

MemDBG was tested on a freshly restarted PS5 with a game running and no stale
test payloads. The production payload was uploaded through the console loader,
validated through HELLO, replaced repeatedly, exercised through the complete
non-destructive protocol matrix, and benchmarked against the live game.

The validation completed without a protocol failure, game memory write, or
unexpected connection loss. The normal workload reached a 9.92 ms average warm
maps latency, an 11.52 ms four-connection maps burst, 8.60 MiB/s aggregate
memory-read throughput, and 25.55 MiB/s server-side exact scanning. A separate
stress session transferred 232 MiB over more than 100 seconds without a
disconnect.

## Scope

This report validates:

- payload upload and positive startup verification;
- HELLO negotiation and feature-level reporting;
- process discovery, metadata, foreground application, and maps;
- single and batch memory operations against the payload test process;
- exact, process-wide, AOB, pointer, and unknown-value scan commands;
- read-only maps, memory throughput, and exact scan against the game;
- the four-role connection model used by the frontend;
- repeated payload replacement on an occupied production port;
- sustained traffic beyond the 30-second idle threshold;
- closure of a genuinely idle connection;
- enforcement and recovery of the maximum-connection limit;
- host, PS4, PS5, frontend, locale, and protocol regression tests.

Process stop/continue, console reboot, and payload shutdown were deliberately
excluded from the functional probe because they are destructive and do not
measure the normal frontend workflow.

## Test Environment

| Item | Value |
|---|---|
| Console state | Fresh restart, game already running |
| Console address | `172.20.10.2` on a local network |
| Game process | `eboot.bin`, PID 95 |
| Game maps | 328 |
| Payload process | `payload.elf` |
| Payload version | `0.2.0-beta.2` |
| Protocol negotiation | feature level 2, wire version 1 |
| Native protocol | TCP 9020 |
| Loader | TCP 9021 |
| UDP logging | UDP 9023 |
| Connection roles | Control, Memory, Scan, Poll |
| Read benchmark | Non-destructive; game memory was never written |

The measured values include LAN transport, packet framing, Sony memory
primitives, daemon scheduling, optional compression, and frontend parsing.
They are end-to-end application figures rather than synthetic `memcpy`
bandwidth.

## Startup and Replacement

The initial production upload was accepted by the loader and verified by HELLO
on the first attempt. Two immediate replacements of the running payload were
then performed on the same endpoint; both returned a valid HELLO after two
connection attempts. A further replacement after the 20-connection capacity
test succeeded after three attempts.

| Operation | Result |
|---|---|
| Initial upload to 9020 | Verified on attempt 1 |
| Replacement 1 | Verified on attempt 2 |
| Replacement 2 | Verified on attempt 2 |
| Replacement after connection flood | Verified on attempt 3 |
| False upload success | Not observed; startup requires a valid HELLO |
| Port left unusable after replacement | Not observed |

This confirms that upload completion and payload startup are treated as
separate states and that a running instance can cooperatively release its
listeners before the replacement binds them.

## Functional Protocol Matrix

The protocol probe was run before and after repeated replacement.

| Result | Count |
|---|---:|
| Passed | 19 |
| Failed | 0 |
| Intentionally skipped | 4 |

Passed command paths:

- CONNECT, HELLO, and PING;
- PROCESS_LIST, PROCESS_INFO, PROCESS_MAPS, and FOREGROUND_APP;
- TELEMETRY;
- MEMORY_READ and reversible MEMORY_WRITE on the payload process;
- BATCH_READ and reversible BATCH_WRITE on the payload process;
- SCAN_EXACT and SCAN_PROCESS_EXACT;
- SCAN_AOB and SCAN_PROCESS_AOB;
- SCAN_POINTER;
- SCAN_UNKNOWN using the versioned v2 request ABI.

The probe advertised the complete capability set expected by the current PS5
payload, including process/memory access, batch operations, LZ4 maps,
debugger/tracer commands, kernel access, console UI, FPU/YMM registers, FS/GS
bases, and klog.

## Normal Performance Runs

Two complete read-only runs were captured: one after the initial injection and
one after two consecutive payload replacements.

### Process and Maps Latency

| Measurement | Initial run | Post-replacement run |
|---|---:|---:|
| PROCESS_LIST average, 10 requests | 10.305 ms | **9.540 ms** |
| PROCESS_LIST p50 | 9.392 ms | **8.557 ms** |
| PROCESS_LIST p95 | 12.573 ms | **10.598 ms** |
| PROCESS_MAPS first, 328 maps | 65.891 ms | **64.914 ms** |
| PROCESS_MAPS warm average, 20 requests | **8.934 ms** | 9.919 ms |
| PROCESS_MAPS warm p50 | **7.140 ms** | 7.348 ms |
| PROCESS_MAPS warm p95 | **13.199 ms** | 25.423 ms |
| Four-socket maps, average per socket | 11.581 ms | **9.708 ms** |
| Four-socket maps burst wall time | 12.311 ms | **11.515 ms** |

The first maps request includes the native VMMAP snapshot, validation, compact
conversion, cache population, optional compression, transport, and client
parsing. Warm requests are served from the bounded process-map cache. Four
simultaneous requests share a single-flight cache fill and then copy the compact
result independently.

### Memory and Scan Throughput

| Measurement | Initial run | Post-replacement run |
|---|---:|---:|
| MEMORY_READ, 4 KiB chunks | **0.38 MiB/s** | 0.34 MiB/s |
| MEMORY_READ, 64 KiB chunks | **4.01 MiB/s** | 3.16 MiB/s |
| MEMORY_READ, 1 MiB chunks | **8.11 MiB/s** | 7.96 MiB/s |
| Four-socket aggregate, 64 MiB | 7.24 MiB/s | **8.60 MiB/s** |
| SCAN_EXACT, 9.11 MiB range | 25.33 MiB/s | **25.55 MiB/s** |
| Payload scan time | 354.516 ms | **351.015 ms** |

Small reads are dominated by one protocol round trip and one Sony mdbg call per
request. Larger chunks amortize both costs. The four sockets provide concurrent
transport and scheduling, while access to the non-reentrant Sony mdbg primitive
is deliberately serialized to preserve correctness.

## Sustained Stress Run

The `--stress` mode keeps one logical session alive across a substantially
larger workload and reconnects idle role sockets before parallel reads. This
exercises active traffic beyond the default 30-second idle threshold.

| Stress measurement | Result |
|---|---:|
| PROCESS_LIST average | 10.808 ms |
| First maps request | 64.582 ms |
| Warm maps average | 10.068 ms |
| Four-socket maps burst | 15.069 ms |
| 4 KiB reads | 8 MiB in 22.52 s, 0.36 MiB/s |
| 64 KiB reads | 32 MiB in 16.05 s, 1.99 MiB/s |
| 1 MiB reads | 64 MiB in 15.06 s, 4.25 MiB/s |
| Four-socket aggregate | 128 MiB in 49.21 s, 2.60 MiB/s |
| Total transferred | **232 MiB** |
| Unexpected disconnects | **0** |
| Game memory writes | **0** |

The stress throughput is intentionally not presented as a peak number. It
captures sustained contention, queueing, and repeated access to the same Sony
kernel primitive. Its purpose is connection and protocol stability.

## Connection Lifecycle

### Idle Timeout

A separate client completed HELLO, remained completely idle for 32 seconds,
then attempted PING. The server had closed the connection as expected. Active
stress traffic continued well beyond 30 seconds without being classified as
idle.

### Maximum Connections

Twenty clients attempted HELLO while retaining their sockets:

| Outcome | Count |
|---|---:|
| Accepted | **16** |
| Rejected | **4** |
| Unaccounted errors | **0** |

After all clients closed, the payload was successfully replaced and HELLO was
verified again. The capacity limit therefore rejects excess work without
leaving the listener or instance lifecycle stuck.

## Relevant Hardening

The validated behavior depends on the following implementation choices:

- the listener polls non-blocking `accept` directly and survives transient
  console wait errors;
- accepted sockets use a real last-activity check rather than relying on Sony's
  cumulative receive-timeout behavior;
- the desktop owns exactly four role connections and plugins use a loopback
  broker instead of opening new console sessions;
- HELLO compatibility includes feature level, platform, capabilities, version,
  and payload identity;
- map queries use a bounded cache and single-flight miss handling;
- Sony process sysctl snapshots are serialized and tolerate size races;
- common responses up to 1 MiB are coalesced into one console write;
- the non-reentrant mdbg primitive is serialized without serializing the whole
  protocol;
- PS5 DMAP reads are used for blocked/auxiliary access, not as a fallback for
  an invalid user address;
- upload success is reported only after a valid payload HELLO;
- repeated injections cooperatively shut down the previous native or legacy
  endpoint before rebinding.

## Regression Validation

The same working tree was validated outside the console:

| Validation | Result |
|---|---|
| Host payload build | Passed |
| PS4 payload build | Passed |
| PS5 payload build | Passed |
| Full C/host `make test` suite | Passed |
| Debugger protocol assertions | 145 / 145 passed |
| Legacy process/memory E2E | 34 passed, 0 failed, 6 host skips |
| Action journal | 64 / 64 passed |
| Frontend parsing | 46 / 46 passed |
| Release/nightly comparison | 11 / 11 passed |
| Client pool and plugin broker | Passed |
| Frontend macOS build | Passed |
| Locale JSON/schema validation | Passed |
| Whitespace validation | Passed |

PS4 runtime debugger attach still requires a live PS4 validation pass. The PS4
payload compiles with the corrected Orbis auth IDs and shared protocol paths,
but this PS5 test does not substitute for console-specific PS4 evidence.

## Reproduction

Build the production payload and live probes:

```sh
make payload-ps5
cmake --build build/frontend -j4 \
  --target memdbg_payload_injection_probe memdbg_probe memdbg_performance_probe
```

Upload and require positive startup verification:

```sh
./build/frontend/bin/memdbg_payload_injection_probe \
  <console-ip> 9021 9020 build/ps5/MemDBG-ps5.elf
```

Run the functional matrix:

```sh
./build/frontend/bin/memdbg_probe <console-ip> 9020
```

Run the normal and sustained read-only benchmarks:

```sh
./build/frontend/bin/memdbg_performance_probe \
  <console-ip> 9020 eboot.bin

./build/frontend/bin/memdbg_performance_probe \
  <console-ip> 9020 eboot.bin --stress
```

For comparable numbers, restart the console first, launch the game, ensure no
old test payload ports remain open, and inject exactly one production payload.
The benchmark selects the lowest matching PID so a newly injected payload that
briefly inherits the loader's `eboot.bin` name cannot be mistaken for the game.

## Interpretation and Limits

- Results apply to this console, game state, network, and payload build.
- They should be compared using the same chunk sizes and clean-start method.
- No direct ps5debug payload benchmark was performed in this run, so this
  report does not claim a measured universal speed ratio against ps5debug.
- The architectural improvements are measurable in MemDBG's own before/after
  behavior, especially maps caching, connection reuse, replacement, and long
  session stability.
- Debugger attach, hardware breakpoints, and watchpoints should be benchmarked
  separately because they intentionally alter target execution state.

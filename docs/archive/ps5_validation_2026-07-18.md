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

The validation completed without a protocol failure or unexpected connection
loss. A safe game-memory write was performed while the process was stopped,
read back, restored byte-for-byte, verified again, and the process continued.

The final adaptive scanner averaged **175.79 MiB/s** over a 9.11 MiB contiguous
range and **152.63 MiB/s** over 16 tracked 12.28 MiB multi-map runs, with a
**171.68 MiB/s** multi-map peak. The process scanner is **14.88x faster** than
the original 64 KiB / one-worker 10.26 MiB/s baseline. It reports live bytes,
maps, matches and worker counts, merges one final result batch, and returns
partial results on Stop. A separate stress session transferred 232 MiB over
more than 100 seconds without a disconnect.

## Scope

This report validates:

- payload upload and positive startup verification;
- HELLO negotiation and feature-level reporting;
- process discovery, metadata, foreground application, and maps;
- single and batch memory operations against the payload test process;
- exact, process-wide, AOB, pointer, and unknown-value scan commands;
- maps, memory throughput, tracked exact scan, cancellation, and one reversible
  write/read-back/restore cycle against the game;
- the four-role connection model used by the frontend;
- repeated payload replacement on an occupied production port;
- sustained traffic beyond the 30-second idle threshold;
- closure of a genuinely idle connection;
- enforcement and recovery of the maximum-connection limit;
- host, PS4, PS5, frontend, locale, and protocol regression tests.

Console reboot was deliberately excluded. Process stop/continue and payload
shutdown were exercised only in controlled lifecycle tests.

## Test Environment

| Item | Value |
|---|---|
| Console state | Fresh restart, game already running |
| Console address | `172.20.10.2` on a local network |
| Game process | `eboot.bin`, PID 95 |
| Game maps | 334 in the final tuning session; 328 in the initial session |
| Payload process | `payload.elf` |
| Payload version | `0.2.0-beta.2` |
| Protocol negotiation | feature level 2, wire version 1 |
| Native protocol | TCP 9020 |
| Loader | TCP 9021 |
| UDP logging | UDP 9023 |
| Connection roles | Control, Memory, Scan, Poll |
| Write benchmark | 16 bytes at `0xd97000`; verified, restored, verified again |

The measured values include LAN transport, packet framing, Sony memory
primitives, daemon scheduling, optional compression, and frontend parsing.
They are end-to-end application figures rather than synthetic `memcpy`
bandwidth.

## Startup and Replacement

The initial production upload was accepted by the loader and verified by HELLO.
During tuning, each replacement first requested a cooperative shutdown, waited
until TCP 9020 was genuinely released, uploaded the new ELF, then required a
HELLO from the new instance. Depending on listener startup, verification took
two or three attempts.

| Operation | Result |
|---|---|
| Initial upload to 9020 | Verified on attempt 1 |
| Replacement 1 | Verified on attempt 2 |
| Replacement 2 | Verified on attempt 2 |
| Replacement after connection flood | Verified on attempt 3 |
| Old HELLO mistaken for new startup | Prevented by waiting for port release |
| False upload success | Not observed; startup requires a post-release HELLO |
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

## Final Scanner Tuning

### Root cause of the apparent 256 KiB reset

The earlier failure attributed to a 256 KiB scanner block happened during
`PROCESS_MAPS`, before any scan command reached the payload. Two independent
lifecycle faults reproduced the symptom:

1. the injection verifier could receive HELLO from the old daemon while that
   daemon was shutting down, then report the replacement as ready too early;
2. rapid clients opened four role sockets and closed them with TCP FIN only.
   Sony's socket wait path did not always reap those FINs promptly, so repeated
   probes accumulated to the 16-connection cap and later sockets reset.

The fixes are explicit and observable:

- replacement waits for the old debug port to be unavailable before upload;
- `GOODBYE` (`0x0003`) has a request/acknowledgement lifecycle and the client
  waits for the acknowledgement before closing;
- the handler also performs a periodic non-blocking peer-close probe as a
  fallback for old clients;
- all four frontend role sockets share one HELLO session identity, so they
  produce one console notification.

After these changes, eight consecutive 256 KiB scans and all larger-block
experiments completed without reset. Following cancel and write tests,
telemetry reported `active_connections=1`: only the telemetry probe itself.

### Chunk-size sweep

Console reads use a resilient algorithm. A failed large read is retried at
half-size repeatedly down to 4 KiB, so raising the fast-path size does not turn
a fragile page into a failed scan. Four map workers retain private buffers and
private result vectors; the payload merges them only after all workers finish.

| Configuration | Multi-map result | Read calls | Interpretation |
|---|---:|---:|---|
| 64 KiB, 1 worker | 10.26 MiB/s | 199 | Original baseline |
| 64 KiB, up to 4 workers | 16.98 MiB/s average | 199 | Parallel matching/read overlap |
| 128 KiB | 33.06 MiB/s | not retained | Stable intermediate point |
| 256 KiB | 48.44 MiB/s average, 50.90 peak | 54 | 8/8 rapid runs, no reset |
| 512 KiB | 71.63 MiB/s average, 88.97 peak | 30 | 8/8 rapid runs |
| 1 MiB | 95.74 MiB/s average, 99.55 peak | 18 | 8/8 rapid runs |
| 2 MiB | 12.28 MiB in 80.75 ms internal average | 12 | Faster core, old probe still had 50 ms join quantization |
| 4 MiB | **152.63 MiB/s average, 171.68 peak** | 10 | Final multi-map setting, 16-run aggregate |
| 8 MiB | 153.25 MiB/s average | 9 | No useful gain; more memory and slower cancellation |

The adjacent eight-run comparison used for the tuning decision was 157.25
MiB/s at 4 MiB versus 153.25 MiB/s at 8 MiB. The more conservative final
4 MiB figure above aggregates a second, noisier eight-run series as well.

The final policy is adaptive:

- **8 MiB** for a single contiguous exact range;
- **4 MiB per worker** for process/map scans, AOB, unknown and pointer paths;
- automatic retry down to **4 KiB** on a read error.

These are payload-internal buffers, not protocol frames. The maximum packet and
public `MEMORY_READ` request remain 1 MiB. With three active workers in the
measured partition, the normal parallel buffer cost is about 12 MiB; four
non-empty partitions would use about 16 MiB.

### Final repeated measurements

| Measurement | Result |
|---|---:|
| Exact contiguous range, 9.11 MiB, 8 runs | **175.79 MiB/s average, 189.49 peak** |
| Tracked process exact, 12.28 MiB / 8 maps, 16 runs | **152.63 MiB/s average, 171.68 peak** |
| Payload-internal multi-map time, 16 runs | **74.20 ms average** |
| Gain over 10.26 MiB/s baseline | **14.88x, +1,388%** |
| Rapid runs completed | **16 / 16** |
| Scan read errors | **0** |
| Unexpected disconnects/resets | **0** |

The progress monitor originally slept for a fixed 50 ms before joining, which
could add almost 50 ms after the result was already available. It now uses a
condition-variable wakeup: status remains sampled at 50 ms for a calm UI, but
completion wakes immediately. The benchmark separately records transport time
around the tracked scan request, so polling granularity no longer inflates the
throughput figure.

### Progress, cancellation, and write validation

The tracked job reports the sum of filtered partition bytes as its total. Each
worker atomically reports bytes read, completed maps, matches found, active and
total workers, and read errors through the Poll role connection. Results stay
thread-local during the scan and are emitted once as a merged final response.

The final live Stop test sent cancellation after about 20 ms:

| Cancellation field | Result |
|---|---:|
| Partial bytes returned | **5.77 MiB** |
| Completed maps returned | **5 of 8** |
| Partial matches returned | **1** |
| Active workers at cancel request | **3 of 3** |
| Response flag | **`cancelled=yes`** |

For the write test, remote allocation was correctly reported unsupported on
this platform. The probe selected a conservative zeroed run in a readable,
writable, non-executable map, stopped PID 95, reread the original 16 bytes,
wrote a test pattern, verified it, restored the original bytes, verified the
restore, and continued the process. The address was `0xd97000`; no test bytes
were left behind.

## Earlier Normal Performance Runs

The following tables preserve the pre-scanner-tuning measurements for
historical comparison.

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

### Progress Visibility and Copy Reduction

Selected-map scans now expose both a determinate progress bar and
`maps completed / maps total` on desktop and mobile layouts. Filtered map dumps
run outside the UI thread and expose completed maps, transferred bytes, planned
bytes, elapsed time, and cancellation. The planned total respects the active
filters and dump-size budget, so progress describes the work that will actually
be performed rather than every map in the process.

The wire limits were intentionally not raised. Larger packets did not address
the dominant costs and would increase peak memory pressure on both consoles.
Instead, compressed responses are constructed in one allocation and one final
frame, removing a redundant allocation and compressed-payload copy without
changing framing, LZ4 compatibility, or the 1 MiB single-read ceiling. A live
A/B retest was transport-limited and varied between runs, so this report does
not present the reduced CPU/memory work as an unsupported LAN throughput gain.

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

Current clients do not normally wait for that timeout. An idle disconnect sends
`GOODBYE`, waits for its empty success response, and only then closes TCP. If an
operation is blocked, disconnect still cancels the socket immediately. This
split preserves responsive cancellation without leaking ordinary role sockets.

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
- ordinary clients acknowledge `GOODBYE` before closing, with a periodic FIN
  probe retained for old clients and abnormal exits;
- the desktop owns exactly four role connections and gives them one shared,
  optional HELLO session identity, so the payload emits one connection
  notification for Control, Memory, Scan, and Poll together;
- raw TCP port probes do not emit connection notifications, while empty-body
  HELLO requests from older clients remain supported and are grouped by peer;
- plugins use a loopback broker instead of opening new console sessions;
- HELLO compatibility includes feature level, platform, capabilities, version,
  and payload identity;
- map queries use a bounded cache and single-flight miss handling;
- compressed framed responses avoid a second allocation and full compressed
  payload copy on both PS4 and PS5;
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

./build/frontend/bin/memdbg_performance_probe \
  <console-ip> 9020 eboot.bin --scan-only

./build/frontend/bin/memdbg_performance_probe \
  <console-ip> 9020 eboot.bin --cancel-scan
```

Run the reversible write/read-back/restore test only on a process you are
authorized to modify:

```sh
./build/frontend/bin/memdbg_performance_probe \
  <console-ip> 9020 eboot.bin --write-test
```

For comparable numbers, restart the console first, launch the game, ensure no
old test payload ports remain open, and inject exactly one production payload.
The benchmark selects the lowest matching PID so a newly injected payload that
briefly inherits the loader's `eboot.bin` name cannot be mistaken for the game.

## Interpretation and Limits

- Results apply to this console, game state, network, and payload build.
- They should be compared using the same chunk sizes and clean-start method.
- PS4 builds share the adaptive scanner and protocol lifecycle code and compile
  successfully, but the performance numbers in this document are PS5-only.
- No direct ps5debug payload benchmark was performed in this run, so this
  report does not claim a measured universal speed ratio against ps5debug.
- The architectural improvements are measurable in MemDBG's own before/after
  behavior, especially maps caching, connection reuse, replacement, and long
  session stability.
- Debugger attach, hardware breakpoints, and watchpoints should be benchmarked
  separately because they intentionally alter target execution state.

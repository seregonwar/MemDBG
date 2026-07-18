<div align="center">

<img src="assets/logo-nobg.png" width="520" alt="MemDBG" />

### Native memory debugging, scanning, and trainer tooling for PS4 / PS5 research.

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-black?style=flat-square)](LICENSE)
[![Version: 0.2.0](https://img.shields.io/badge/Version-0.2.0-blue?style=flat-square)](VERSION)
[![Platforms: PS4 / PS5 / Host](https://img.shields.io/badge/Platforms-PS4%20%2F%20PS5%20%2F%20Host-2f6feb?style=flat-square)](#platform-support)
[![Frontend: Desktop / Mobile](https://img.shields.io/badge/Frontend-Desktop%20%2F%20Mobile-8a63d2?style=flat-square)](#desktop-and-mobile-frontend)
[![Status: active development](https://img.shields.io/badge/Status-active%20development-f59e0b?style=flat-square)](#project-status)
[![Downloads](https://img.shields.io/github/downloads/seregonwar/memDBG/total?style=flat-square&color=brightgreen)](https://github.com/seregonwar/memDBG/releases)

</div>

---

**MemDBG** is a compact console payload plus a native frontend for memory
inspection, scanning, debugging, trainer building, and research workflows on
PlayStation 4, PlayStation 5, and host development machines.

It is designed for offline homebrew development, reverse-engineering education,
preservation, and authorized security research. It is not a tool for online
cheating, piracy, account abuse, or unauthorized access.

## Contents

- [Why MemDBG](#why-memdbg)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Desktop and Mobile Frontend](#desktop-and-mobile-frontend)
- [Build Targets](#build-targets)
- [Testing](#testing)
- [PS5 Live Validation](#ps5-live-validation)
- [Localization](#localization)
- [Plugins](#plugins)
- [Wire Protocol](#wire-protocol)
- [Platform Support](#platform-support)
- [Release Pipeline](#release-pipeline)
- [Documentation](#documentation)
- [Responsible Use](#responsible-use)
- [License](#license)

## Why MemDBG

MemDBG brings the workflows normally split across payloads, debugger clients,
cheat tooling, log viewers, and one-off scripts into one capability-aware
toolchain.

| Area | What MemDBG provides |
|---|---|
| Payload | C11 daemon for PS4, PS5, and host validation builds. |
| Frontend | Native C++17 Dear ImGui app for Linux, macOS, Windows, iOS, and Android. |
| Protocol | Compact binary `MDBG` protocol with versioning, feature bits, and optional LZ4 compression. |
| Scanning | Exact value, process-wide, AOB, pointer-chain, unknown-value, and heuristic Smart Auto-Search flows. |
| Debugging | Attach/detach, stop/continue/step, threads, registers, breakpoints, watchpoints, stack walk, and disassembly. |
| Trainers | `.cht` save/load, batchcode import, ON/OFF values, lock intervals, and patch-to-trainer export. |
| Research UX | Patch Studio, Analysis Notebook, process metadata, telemetry, logs, and plugin scripting. |
| CI confidence | Host payload, frontend tests, locale validation, and console payload/library rebuild targets. |

## Capabilities

### Payload Core

- Process enumeration, metadata, memory maps, protection changes, allocation,
  free, stop, continue, and kill primitives.
- Single and batch memory read/write, with batch operations capped for stable
  round-trip behavior.
- Server-side scanner paths for range and process-wide exact scans, AOB scans,
  pointer chains, and unknown initial value snapshots.
- Debugger session lifecycle with thread control, software breakpoints,
  hardware breakpoints/watchpoints, GPR/debug/FPU registers, stack walking, and
  compact disassembly support.
- PS4/PS5 kernel base/read/write and console notification/print commands,
  advertised only when the active payload supports them.
- ELF load and process hijack workflows with region matching by exact name,
  case sensitivity, regex, full path, wildcard, or substring fallback.
- PS5 remote allocation/free through the syscall bridge; remote calls execute
  through the debugger trampoline backend where supported.
- UDP telemetry, discovery, crash-resilient logging, and signal-safe flushes.

### Frontend Workflows

- Consoles: connect, disconnect, ping, shutdown, and UDP log listener control.
- Processes: PID/name/title/content metadata, maps, filters, dumps, ELF load,
  and hijack controls.
- Memory: hex read/write, patches, watchpoints, allocations, ROP gadget search,
  and heap-spray entropy analysis.
- Scanner: exact-value scans, process-wide scans, unknown/refine pipeline, and
  Smart Auto-Search presets for health, ammo, and resources.
- Pointer Scan and AOB Scan: dedicated workflows for stable addresses and
  wildcard byte signatures.
- Trainer: cheat entries, live OFF-value capture, lock intervals, batchcode
  import, high-performance GoldHEN JSON parsing, and `.cht` persistence.
- Debugger: registers, threads, stepping, breakpoints, watchpoints,
  disassembly, Patch Studio, and Analysis Notebook.
- Logs and Telemetry: live UDP feed, sender stats, dropped/evicted counters,
  throughput, scan-cache metrics, and runtime state.
- Plugins: Lua/Python desktop-side scripts with a JSON execution context.

## Architecture

```text
MemDBG
|-- src/                         C11 payload and host daemon
|   |-- core/daemon/             TCP protocol, dispatch, command handlers
|   |-- scanner/                 exact, AOB, pointer, unknown, SIMD helpers
|   |-- debug/                   attach, registers, breakpoints, stack walk
|   |-- privilege/               console privilege and syscall helpers
|   |-- telemetry/               UDP discovery and runtime logging
|   `-- pal/                     platform abstraction layer
|-- include/memdbg/              public protocol and PAL headers
|-- frontend/                    C++17 Dear ImGui desktop frontend
|   |-- src/app/                 shell, state, async UI dispatch
|   |-- src/core/client/         TCP protocol client
|   |-- src/screens/             product screens and tools
|   |-- src/trainer/             trainer and batchcode formats
|   |-- src/plugins/             plugin repository and runtime bridge
|   `-- src/locale/              embedded English plus repository locales
|-- mobile/                      iOS/iPadOS and Android shells
|-- docs/                        engineering and packaging documentation
|-- github-pages/                static user guide
`-- tests/                       host-side protocol, scanner, debugger, LZ4 tests
```

The console payload exposes a TCP debug endpoint, emits telemetry over UDP, and
announces capabilities during the `HELLO` handshake. The frontend uses those
capabilities to enable supported actions and hide unsupported ones, so partial
payloads and older builds fail gracefully instead of breaking the UI.

## Quick Start

### Host Development

The host build runs the same protocol locally, which makes it the fastest way
to test the frontend without a jailbroken console.

```sh
make host
make frontend

./build/MemDBG-host --bind=127.0.0.1 --debug-port=9020 \
  --udp-port=9023 --data-root=/tmp/MemDBG
```

Then launch the frontend:

```sh
# macOS
open build/frontend/bin/MemDBG.app

# Linux / non-bundle builds
./build/frontend/bin/memdbg_frontend
```

Connect to `127.0.0.1:9020` from the **Consoles** screen.

### PS5 Payload

```sh
make payload-ps5
make deploy-ps5 PS5_HOST=192.168.1.100 PS5_PORT=9021
```

After deployment, connect the frontend to the console IP on TCP port `9020`.
UDP logs use port `9023`; discovery uses UDP port `9022`.

### PS4 Payload

```sh
make payload-ps4
make deploy-ps4 PS4_HOST=192.168.1.100 PS4_PORT=9021
```

The PS4 and PS5 frontends share the same UI and protocol client. Feature
availability is controlled by the payload capability bitmap.

### One-command Host Shortcut

```sh
./tools/quick_start.sh
```

Useful options:

| Option | Purpose |
|---|---|
| `--no-build` | Launch using existing build artifacts. |
| `--host-only` | Start only the host payload. |
| `--help` | Show all supported options. |

## Desktop and Mobile Frontend

The desktop frontend is a native Dear ImGui application built with C++17,
OpenGL, and GLFW. It includes DPI-aware scaling, persistent settings, hotkeys,
toast notifications, a grouped sidebar, native app icons, and full Unicode font
fallback for the supported locale set.

| Platform | Artifact |
|---|---|
| macOS | `build/frontend/bin/MemDBG.app` |
| Linux | `build/frontend/bin/memdbg_frontend` plus `.desktop` metadata |
| Windows | `MemDBG.exe` release bundle |
| iOS / iPadOS | Metal shell, unsigned `.ipa` release artifact |
| Android | OpenGL ES 3 shell, release `.apk` artifact |

Mobile shells live under [`mobile/`](mobile/) and reuse the shared frontend
touch layout plus the embedded Lua 5.4 plugin runtime. See
[`docs/mobile_architecture.md`](docs/mobile_architecture.md) for the contract.

## Build Targets

### Requirements

| Component | Requirement |
|---|---|
| C payload | C11 compiler (`cc`, `clang`, or `gcc`) |
| Frontend | C++17, CMake 3.24+, OpenGL-capable desktop toolchain |
| PS5 payload | Bundled SDK in `external/ps5-payload-sdk/` or `PS5_PAYLOAD_SDK=` override |
| PS4 payload | Bundled SDK in `external/ps4-payload-sdk/` or `PS4_PAYLOAD_SDK=` override |
| Mobile | Xcode for iOS, Gradle/NDK for Android |

### Common Targets

```sh
make host              # build host daemon
make frontend          # build desktop frontend
make payload-ps5       # build PS5 payload ELF
make payload-ps4       # build PS4 payload ELF
make payload-ps5-lib   # build PS5 libmemdbg.a
make payload-ps4-lib   # build PS4 libmemdbg.a
make verify            # host + PS4 + PS5 rebuild matrix
```

The static library targets omit the standalone payload entry point and are
intended for embedding MemDBG functionality into a custom payload shell.

## Testing

```sh
make test                  # full host-side C test suite
make test-lz4              # internal LZ4 codec tests
make test-debugger         # mocked debugger backend tests
make test-debugger-e2e     # live host debugger protocol smoke test
make test-process-aob-e2e  # live host AOB protocol path
make check-locales         # validate locale completeness and manifest hashes
make check-headers         # verify header/source correspondence
git diff --check           # reject whitespace errors
```

Live console probes are built with the frontend tools:

```sh
# Functional MDBG command matrix
./build/frontend/bin/memdbg_probe <console-ip> 9020

# Read-only maps, memory, scan, and four-connection benchmark
./build/frontend/bin/memdbg_performance_probe <console-ip> 9020 eboot.bin

# Extended session/timeout stability workload
./build/frontend/bin/memdbg_performance_probe <console-ip> 9020 eboot.bin --stress
```

Frontend CMake also builds focused test binaries, including:

| Test binary | Coverage |
|---|---|
| `memdbg_app_state_parsing_test` | App-state parsing and persistence helpers |
| `memdbg_auto_search_test` | Smart Auto-Search heuristic engine |
| `memdbg_trainer_formats_test` | Trainer and batchcode parsing |
| `memdbg_locale_manager_test` | Locale loading, validation, and fallback |
| `memdbg_structure_compare_test` | Structure comparison helpers |
| `memdbg_plugin_manager_test` | Plugin manifest and repository behavior |

## PS5 Live Validation

The current payload and protocol feature level were validated on a freshly
restarted PS5 with a live `eboot.bin` target on **2026-07-18**. The test used
the production ports (`9020` native protocol, `744` legacy compatibility) and
four independent native role connections.

| Check | Result |
|---|---:|
| Functional protocol matrix | **19 passed, 0 failed, 4 intentionally skipped** |
| Process list latency (10 requests) | **9.54 ms average** |
| First maps enumeration (328 maps) | **64.91 ms** |
| Warm maps latency (20 requests) | **9.92 ms average** |
| Four-socket maps burst | **11.52 ms wall time** |
| Memory read, 1 MiB chunks | **7.96 MiB/s** |
| Four-socket aggregate read | **8.60 MiB/s** |
| Server-side exact scan | **25.55 MiB/s** |
| Sustained read-only stress workload | **232 MiB transferred; no disconnect** |
| Connection cap | **16 accepted, 4 rejected out of 20** |
| Idle timeout | **inactive connection closed after 30 seconds** |
| Repeated payload replacement | **verified by HELLO after every injection** |

These are end-to-end LAN measurements, including protocol framing, console
memory primitives, serialization, compression decisions, and client parsing.
They are not synthetic memory-copy figures. Full methodology, both normal
runs, stress results, protocol coverage, limitations, and reproduction steps
are in
[`docs/ps5_validation_2026-07-18.md`](docs/ps5_validation_2026-07-18.md).

## Localization

English is embedded in the frontend. Additional languages are stored in
[`frontend/locales/`](frontend/locales/), listed in
[`frontend/locales/manifest.json`](frontend/locales/manifest.json), validated by
hash and schema, downloaded when needed, and cached in the app data directory.

| Code | Language |
|---|---|
| `en` | English |
| `de` | Deutsch |
| `es` | Español |
| `fr` | Français |
| `it` | Italiano |
| `ja` | 日本語 |
| `ko` | 한국어 |
| `pt` | Português |
| `ru` | Русский |

When adding or updating translations:

```sh
python3 tools/generate_locale_manifest.py
make check-locales
```

## Plugins

The frontend can install and run desktop-side Lua/Python plugins from repository
manifests. The default public source is
[`seregonwar/MemDBG-Plugin`](https://github.com/seregonwar/MemDBG-Plugin), and
this checkout includes a bundled fallback under
[`plugin-repository/`](plugin-repository/).

Plugins receive a JSON context with the active console, selected PID, process
name, dump and trainer paths, map count, scan hits, trainer entry count,
protocol version, and payload capabilities.

See [`docs/plugins.md`](docs/plugins.md) for the manifest format and runtime
contract.

## Wire Protocol

MemDBG uses a packed little-endian binary protocol identified by
`MEMDBG_PACKET_MAGIC = "MDBG"`. The stable packet framing remains **wire
version 1**, while the current append-only command and HELLO contract is
**feature level 2**. Payloads advertise the negotiated feature level and
capabilities during `HELLO`, and clients gate UI and requests accordingly.

The normative technical specification is
[`docs/protocol.md`](docs/protocol.md). It documents the frame layout,
request/response lifecycle, compression sub-frame, status codes, command
registry, capability bits, and extension rules for keeping MDBG compatible as it
becomes a stable internal standard.

For older trainer/debugger clients, MemDBG can also expose a separate
ps5debug-compatible listener on TCP port `744`. That bridge is intentionally
isolated from the native protocol; see
[`docs/ps5debug_compat.md`](docs/ps5debug_compat.md) for the compatibility
contract, supported legacy commands, and extension plan.

| Limit | Value |
|---|---|
| Maximum packet size | 1 MiB |
| Maximum process-map response | 8 MiB |
| Maximum `MEMORY_READ` size | 1 MiB |
| `BATCH_READ` / `BATCH_WRITE` items | 64 per request |
| Maximum scan value payload | 16 bytes |
| Extended register blob | 1024 bytes |
| Optional compression | LZ4 via `MEMDBG_CAP_LZ4` |

Primary command families:

| Family | Examples |
|---|---|
| Session | `HELLO`, `PING`, `DISCOVERY`, `SHUTDOWN` |
| Process | list, info, maps, stop, continue, protect, alloc, free, stack, call, ELF load, hijack |
| Memory | single read/write, batch read/write |
| Scanner | exact, process exact, AOB, process AOB, pointer, unknown |
| Debugger | attach, detach, stop, continue, step, registers, events, breakpoints, watchpoints |
| Kernel | base discovery, kernel read, kernel write |
| Console | notification, kernel-console print, reboot |

Public protocol structures are in [`include/memdbg/core/`](include/memdbg/core/).
The protocol header remains the ABI source of truth; the specification explains
how that ABI is serialized and extended.

## Platform Support

| Target | Status | Notes |
|---|---|---|
| PlayStation 5 | Supported | `make payload-ps5`, kernel and debugger features are capability-gated. |
| PlayStation 4 | Supported | `make payload-ps4`, platform-specific debugger features are gated. |
| Linux host | Supported | Best environment for CI, ptrace tests, and local protocol validation. |
| macOS host | Supported | Some debugger actions may require SIP/codesign changes. |
| Windows frontend | Supported | Distributed as release bundle. |
| iOS / iPadOS | Supported | Metal shell, unsigned release artifact. |
| Android | Supported | OpenGL ES 3 shell, release APK. |

Host builds bind to loopback by default. Bind to `0.0.0.0` only when remote
machines must connect, and prefer `--allow=<frontend-ip>` for LAN sessions.

## Release Pipeline

GitHub Actions release jobs build desktop, payload, library, and mobile
artifacts for tags matching `v*`, manual dispatches, and the daily nightly
candidate.

| Job | Artifact |
|---|---|
| `host-linux` | `MemDBG-host-linux` |
| `host-macos` | `MemDBG-host-macos` |
| `frontend-linux` | `MemDBG-frontend-linux` |
| `frontend-macos` | `MemDBG-frontend-macos.app.zip` and DMG |
| `frontend-windows` | `MemDBG-frontend-windows.zip` |
| `payload-ps4` | `MemDBG-ps4.elf`, `libmemdbg-ps4.a` |
| `payload-ps5` | `MemDBG-ps5.elf`, `libmemdbg-ps5.a` |
| `mobile-ios` | `MemDBG-mobile-ios.ipa` |
| `mobile-android` | `MemDBG-mobile-android.apk` |

At 22:00 Europe/Rome each day, the workflow creates an immutable release tagged
`nightly-YYYYMMDD-gSHA`, where the date is local to Rome and `SHA` is the
lowercase seven-character commit ID (automatically lengthened by Git only to
avoid an abbreviation collision). Its title is
`nightly [YYYY-MM-DD-gSHA]`. Manual nightlies use the same identity rules, and a
rerun for an existing date and commit only verifies identical metadata and
assets; it never overwrites the release.

A newly published nightly becomes GitHub Latest. A newer stable official release
then takes the Latest badge, while prerelease official builds do not. The next
successfully published nightly becomes Latest again. All historical nightly and
official tags and assets remain accessible snapshots.

`VERSION` records the current official repository version for local builds. A
single resolver derives tagged/manual release versions and independent nightly
versions, then writes the resolved value before every desktop, payload, iOS,
and Android build. Release artifacts include `SHA256SUMS.txt`.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/showcase.md`](docs/showcase.md) | Product walkthrough and feature showcase. |
| [`docs/protocol.md`](docs/protocol.md) | Internal MDBG wire protocol specification and extension rules. |
| [`docs/ps5debug_compat.md`](docs/ps5debug_compat.md) | ps5debug compatibility layer for older trainer/debugger clients. |
| [`docs/ps5_validation_2026-07-18.md`](docs/ps5_validation_2026-07-18.md) | Reproducible PS5 protocol, stability, and performance validation report. |
| [`docs/feature_research.md`](docs/feature_research.md) | Planned work and technical research notes. |
| [`docs/plugins.md`](docs/plugins.md) | Plugin manifest and runtime contract. |
| [`docs/mobile_architecture.md`](docs/mobile_architecture.md) | iOS/Android shell architecture. |
| [`docs/release_packaging.md`](docs/release_packaging.md) | Release artifact and packaging details. |
| [`github-pages/`](github-pages/) | Static end-user guide for setup, scanning, trainer flow, and troubleshooting. |

## Project Status

MemDBG is in active pre-release development. Wire version `1` and feature level
`2` are stable for current tooling; new append-only commands and capability
bits may be added before the first public milestone.

Completed areas include process/memory primitives, all current scanner paths,
native desktop frontend, repository-backed localization, debugger lifecycle,
breakpoints/watchpoints, Patch Studio, Analysis Notebook, ELF load/hijack,
mobile shells, and release packaging.

Tracked follow-up work includes additional SIMD scan paths, alias compare
acceleration, assembler integration, and a dedicated klog forwarder.

## Contributing

Contributions are welcome around:

- payload and scanner hardening;
- frontend usability, accessibility, and layout refinement;
- debugger and disassembly workflows;
- translations under [`frontend/locales/`](frontend/locales/);
- plugin examples and documentation;
- reproducible bug reports with target, command, and log evidence.

For translations, update the locale JSON file, regenerate the manifest, and run
`make check-locales` before opening a pull request.

## Credits

MemDBG includes a compatibility layer for the **ps5debug** protocol created by
[SiSTR0](https://github.com/SiSTR0) / ctn and maintained in
[ps5debug-NG](https://github.com/OpenSourcereR-dev/ps5debug-NG) by
[OpenSourcereR-dev](https://github.com/OpenSourcereR-dev).
This bridge allows legacy trainers and debugger tools to connect without
modifications, while keeping the native MemDBG protocol clean and versioned.
See [`docs/ps5debug_compat.md`](docs/ps5debug_compat.md) for details.

## Responsible Use

MemDBG is built for legitimate debugging, security research, education,
preservation, and homebrew development on systems you own or are authorized to
analyze.

The maintainers do not support:

- online cheating or multiplayer advantage;
- piracy or circumvention of paid content;
- unauthorized access to systems, accounts, or third-party services;
- disruptive behavior against online services or other players.

This project is provided as-is. The authors and contributors are not
responsible for misuse, hardware or software damage, account action, legal
consequences, or violations of third-party terms.

## License

MemDBG is released under **GPL-3.0-or-later**. See [LICENSE](LICENSE).

---

<div align="center">

**MemDBG** - memory debugging for PS4 / PS5 research environments.

</div>

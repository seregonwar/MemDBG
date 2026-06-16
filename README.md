<div align="center">

<br/>

<img src="assets/logo-nobg.png" width="650" height="650" alt="MemDBG" />

<br/>
<br/>

**Memory debugging and inspection suite for PS4 / PS5 research environments.**

<br/>

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-black?style=flat-square)](LICENSE)
[![Platform: PS4 / PS5](https://img.shields.io/badge/Platform-PS4%20%2F%20PS5-black?style=flat-square)](#supported-platforms)
[![Status: Pre-release](https://img.shields.io/badge/Status-Pre--release-black?style=flat-square)](#repository-status)
[![Language: C11 / C++17](https://img.shields.io/badge/Language-C11%20%2F%20C%2B%2B17-black?style=flat-square)](#building)

<br/>

</div>

---

MemDBG is a high-performance memory debugging suite designed for PlayStation 4 and PlayStation 5 homebrew research. It pairs a tight, capability-aware wire protocol running on the console with a native Dear ImGui frontend, providing a unified interface for process inspection, memory analysis, scanning, and runtime cheating workflows.

Built for developers, security researchers, and advanced users who need low-level visibility into console memory — without compromising on speed or ergonomics.

> Intended for educational, research, preservation, and offline homebrew development purposes only.

<br/>

## Table of Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Features](#features)
- [Wire Protocol](#wire-protocol)
- [Supported Platforms](#supported-platforms)
- [Localization](#localization)
- [Building](#building)
- [Testing](#testing)
- [Workflow](#workflow)
- [Configuration](#configuration)
- [Release Pipeline](#release-pipeline)
- [Contributing](#contributing)
- [Ethical Use](#ethical-use)
- [Disclaimer](#disclaimer)
- [License](#license)

<br/>

## Highlights

- **Single-binary payload** for PS4 (Orbis) and PS5 (Prospero), plus a Linux/macOS host build for offline development.
- **Native desktop frontend** in C++17 with Dear ImGui, OpenGL, GLFW — packaged as `.app` on macOS, `.exe` on Windows, and a `.desktop` entry on Linux.
- **Capability-aware protocol** so the frontend can adapt to older or partial payloads without crashing.
- **First-class scanners**: exact value, process-wide exact, process-wide AOB, pointer chain, unknown initial value, plus a heuristic **Smart Auto-Search** engine for common game values (health, ammo, resources).
- **Non-blocking UI**: connect, scan, and telemetry requests run on worker threads and stream results back via `std::future` polling.
- **Multi-language** out of the box (8 languages, ships with a CI check that enforces locale completeness).
- **Library targets** (`libmemdbg.a`) for embedding the payload core into other tools.
- **Cross-platform discovery**: payloads respond to UDP broadcasts so the frontend can auto-populate without knowing the debug port.

<br/>

## Architecture

```
MemDBG
├── payload/                  C11 homebrew daemon (PS4, PS5, host)
│   ├── core/                 Engine, instance lifecycle, logging
│   ├── scanner/              Exact, AOB, pointer, unknown + process-wide variants
│   ├── debug/                Process / memory primitives shared by the scanner
│   ├── privilege/            Sandbox escape + per-process elevation
│   ├── telemetry/            UDP broadcast logger + discovery responder
│   └── pal/                  Platform abstraction (network, memory, fileio, notify, lz4)
├── libmemdbg.a               Static library target (PS4 / PS5) for embedded use
├── memdbg-host               Host validation build (same C sources, host toolchain)
└── frontend/                 C++17 + Dear ImGui desktop app
    ├── app/                  Window, sidebar, top bar, status bar, async dispatch
    ├── core/                 TCP client, UDP listener, GitHub profile loader
    ├── screens/              One file per screen (Home, Consoles, Processes, …)
    ├── scanner/              Auto-Search heuristic engine (mirrors backend semantics)
    ├── trainer/              .cht load/save, batchcode parser
    ├── locale/               JSON-driven i18n manager with translation files
    ├── ui/                   Reusable widgets, theme, fonts, icon font, file picker
    └── proto/                Standalone protocol probe CLI
```

The payload binds a TCP debug port, exposes process enumeration, map inspection, and memory primitives, and streams logs over UDP. The frontend connects to that TCP endpoint, listens for telemetry, and offers the full interactive interface. Older payloads advertise a smaller capability bitmap so the frontend can gracefully hide unsupported features instead of failing.

<br/>

## Features

### Scanner engine (payload-side)

- **Exact value scan** with type selection (`u8`, `u16`, `u32`, `u64`, `f32`, `f64`, raw bytes, pointer).
- **Process-wide exact scan** with protection mask and start/end range filtering.
- **Process-wide AOB scan** with wildcard bytes (`??`), tailored for cheat-engine-style signatures.
- **Range AOB scan** for targeted searches.
- **Pointer scan** with configurable max depth, alignment, and alignment-aware dereference.
- **Unknown initial value scan** — saves every aligned value as a baseline for later refinement.
- **Resilient I/O**: scans continue past faulting pages, count `read_errors`, and carry pending bytes across chunk boundaries so matches crossing 1 MiB chunks are still found.

### Frontend screens

| Screen | What it does |
|---|---|
| **Home (Command Center)** | Dashboard tiles for every workflow, live session + UDP status, recent map/hit/cheat chips. |
| **Consoles** | Direct payload session: Connect / Disconnect / Ping Payload / Shutdown Payload; start, restart, and stop the UDP log listener from one place. |
| **Processes** | Refresh processes (PID/name/title id/content id/path), refresh the memory maps of the selected PID, filter maps by read/write/exec, hide system maps, set min-size and dump-cap, dump selected or filtered maps to disk, and run a basic process analysis. |
| **Memory** | Address-range read/write with a hex view, byte-patch input, watchpoints (polling) with overlay marks, allocation tracking with importable event streams and free-double-free detection, plus an **Exploit Lab** with ROP gadget finder and a heap-spray entropy analyzer. |
| **Scanner** | Exact-value scan, process-wide scan, unknown initial value scan, refinement pipeline (Changed / Unchanged / Increased / Decreased), and **Smart Auto-Search** with target presets (Health / Ammo / Resources) and a scored candidate list. |
| **Pointer Scan** | Trace pointer chains back from a target address with adjustable depth and alignment. |
| **AOB Scan** | `48 8B ?? ??`-style pattern search, with wildcards, process-wide or range mode, and per-map protection filtering. |
| **Trainer** | Cheat builder (name, address, type, ON/OFF/lock), batchcode import (`offset`, `value`, `size`, AOB tokens), OFF-value capture from runtime memory, per-entry ON/OFF/Lock, periodic lock write, copy-all-addresses, save / load `.cht`-style trainer files. |
| **Logs** | Live UDP telemetry feed with start / stop / clear / copy, sender endpoint, bind-retry counter, received/dropped/evicted stats. |
| **Telemetry** | Payload runtime metrics when the payload advertises `PERF_TELEMETRY`: uptime, active connections, thread pool size, total read/write bytes and call counts, throughput, scan-map LRU cache hit / miss, and last-poll age. |
| **Settings** | Persistent connection defaults (host, debug TCP port, UDP log port, dump directory), 8-language picker, saved to the per-platform app config dir. |
| **Credits** | Creator info, GitHub profile (avatar + handle loaded at runtime), license, donation and GitHub links. |

### Frontend ergonomics

- Global hotkeys: **F1** Home, **F5** Connect / Disconnect, **F6** Processes, **F7** Scanner, **F8** Memory, **F9** Trainer, **F10** Logs.
- Toast notifications with auto fade-out and manual dismiss.
- Sidebar grouped into **Main / Tools / Observe / System** sections.
- Top bar with dynamic chips for session, maps, scan hits, and active cheats.
- Status bar with FPS, session state, target PID, and UDP listener stats.
- File picker integration for dump directory and trainer file save/load.
- Embedded logo, native window icon (`.icns` on macOS, `.ico` on Windows, `.desktop` on Linux), and `ResizeToFit`-friendly layout that also handles live window resize.

<br/>

## Wire Protocol

A compact binary protocol (`MEMDBG_PACKET_MAGIC = "MDBG"`, little-endian, version 1). All multi-byte fields are packed; payloads declare capabilities via the `HELLO` response bitmap so the frontend stays forward-compatible with older or PS-specific payloads.

### Protocol limits

- Max packet size: **1 MiB**
- Max read size: **1 MiB**
- `BATCH_READ` / `BATCH_WRITE` items per call: **64**
- Max scan value payload: **16 bytes** (auto-search pattern fits comfortably)
- Optional LZ4 compression on result payloads (advertised via `MEMDBG_CAP_LZ4`).

### Commands

| Code | Command | Purpose |
|---|---|---|
| `0x0001` | `HELLO` | Capability bitmap, platform id, version, debug/UDP ports. |
| `0x0002` | `PING` | Liveness probe. |
| `0x0100` | `PROCESS_LIST` | Enumerate PIDs. |
| `0x0101` | `PROCESS_MAPS` | Memory map list for a PID. |
| `0x0102` | `PROCESS_INFO` | Name, executable path, Title ID, Content ID. |
| `0x0103` | `FOREGROUND_APP` | Currently focused app metadata. |
| `0x0104` / `0x0105` | `PROCESS_STOP` / `PROCESS_CONTINUE` | Suspend / resume a target. |
| `0x0200` / `0x0201` | `MEMORY_READ` / `MEMORY_WRITE` | Single-address I/O. |
| `0x0202` / `0x0203` | `BATCH_READ` / `BATCH_WRITE` | Multi-address I/O in one round-trip (used by Auto-Search and trainer lock writes). |
| `0x0300` / `0x0301` | `SCAN_EXACT` / `SCAN_PROCESS_EXACT` | Value scan, range or process-wide. |
| `0x0302` / `0x0305` | `SCAN_AOB` / `SCAN_PROCESS_AOB` | Byte-pattern scan, range or process-wide. |
| `0x0303` | `SCAN_POINTER` | Pointer-chain search. |
| `0x0304` | `SCAN_UNKNOWN` | Baseline every aligned value for later refinement. |
| `0x0400` | `TELEMETRY` | Runtime performance metrics. |
| `0x0500` | `DISCOVERY` | UDP broadcast ping / pong for auto-detection. |
| `0x7f00` | `SHUTDOWN` | Clean payload termination. |

Every `SCAN_*` response includes a `memdbg_scan_response_prefix_t` with the hit count, truncated flag, bytes scanned, elapsed time, and read / region / error counts. This is the same prefix the frontend surfaces on screen.

<br/>

## Supported Platforms

| Platform | Status |
|---|---|
| PlayStation 5 | In development (`make payload-ps5`) |
| PlayStation 4 | In development (`make payload-ps4`) |
| Linux (host) | Supported |
| macOS (host) | Supported |
| Windows (host + frontend) | Supported |
| Frontend Linux | Supported |
| Frontend macOS | Supported (universal `.app` bundle) |
| Frontend Windows | Supported (with `.exe` and `.ico` icon) |

The frontend talks to the payload over TCP (`9020` by default); telemetry and discovery are UDP (`9023` / `9022` respectively). On the host build, all three ports must be free at start time.

<br/>

## Localization

The UI is fully driven by JSON locale files in [`frontend/locales/`](frontend/locales). The frontend automatically selects a language on first run based on the OS locale and persists the choice in its config. New languages are added by dropping a `<code>.json` file and opening a PR.

Shipped languages:

| Code | Language | File |
|---|---|---|
| `en` | English | [`en.json`](frontend/locales/en.json) |
| `es` | Español | [`es.json`](frontend/locales/es.json) |
| `it` | Italiano | [`it.json`](frontend/locales/it.json) |
| `fr` | Français | [`fr.json`](frontend/locales/fr.json) |
| `pt` | Português | [`pt.json`](frontend/locales/pt.json) |
| `de` | Deutsch | [`de.json`](frontend/locales/de.json) |
| `ja` | 日本語 | [`ja.json`](frontend/locales/ja.json) |
| `ru` | Русский | [`ru.json`](frontend/locales/ru.json) |

Locale consistency is enforced in CI:

```sh
make check-locales
```

The checker fails the build if any locale is missing a key that exists in `en.json`, ensuring contributors can't ship half-translated UIs.

<br/>

## Building

### Prerequisites

| Component | Requirement |
|---|---|
| C toolchain | C11-compatible (`cc` / `clang` / `gcc`) |
| C++ toolchain | C++17 with CMake 3.24+, Ninja recommended |
| PS5 build | [`external/ps5-payload-sdk/`](external/ps5-payload-sdk) (override with `PS5_PAYLOAD_SDK=`) |
| PS4 build | [`external/ps4-payload-sdk/`](external/ps4-payload-sdk) (override with `PS4_PAYLOAD_SDK=`) |
| Frontend | OpenGL, GLFW (pulled in via `FetchContent`), ImGui, nlohmann/json, stb (all pulled in via CMake) |

Both payload SDKs ship with the repository; you don't need to clone anything extra.

### Payload — PS5

```sh
make payload-ps5
make deploy-ps5 PS5_HOST=192.168.1.100 PS5_PORT=9021
```

### Payload — PS4

```sh
make payload-ps4
make deploy-ps4 PS4_HOST=192.168.1.100 PS4_PORT=9021
```

### Static library (embeddable)

```sh
make payload-ps5-lib    # build/ps5/libmemdbg.a
make payload-ps4-lib    # build/ps4/libmemdbg.a
```

Both archives ship the scanner, debug, telemetry, PAL, and privilege modules — minus the `main.c` entry point — so they can be linked into a custom payload shell.

### Host validation build

```sh
make host
./build/MemDBG-host --bind=0.0.0.0 --debug-port=9020 \
                    --udp-port=9023 --data-root=/tmp/MemDBG
```

The host build runs on Linux/macOS, opens real TCP/UDP sockets, and serves the same protocol as the console payload — perfect for unit tests, hardware bring-up, and frontend development without a console.

### Frontend

```sh
make frontend
./build/frontend/memdbg_frontend
```

On macOS this produces a `MemDBG.app` bundle (with `Resources/locales/`, `Resources/assets/app-icon.png`, and a custom `.icns` icon). On Linux you'll also get a `MemDBG.desktop` file alongside the binary.

### Standalone protocol probe

The CMake build also produces a `memdbg_probe` CLI for testing a payload without the GUI:

```sh
./build/frontend/memdbg_probe
```

### Full verification matrix

```sh
make clean
make verify    # = host + payload-ps4 + payload-ps5
```

<br/>

## Testing

Two test programs ship with the repo:

```sh
make test-aob-boundary     # 17-case AOB pattern boundary test
make test-process-aob-e2e  # End-to-end AOB scan over a running host payload
make test                  # Both of the above
```

- **`test_aob_boundary`** mocks the memory backend and the map table to verify the scanner carries pending bytes across the 1 MiB chunk boundary, handles wildcards, applies the good-suffix shift, and still finds matches after faulting pages.
- **`test_process_aob_e2e`** spawns a real `MemDBG-host` on a temp data root and walks it through `PROCESS_LIST → PROCESS_MAPS → SCAN_PROCESS_AOB`. The test is self-contained and cleans up after itself.

The frontend also builds an **auto-search unit test** (`memdbg_auto_search_test`) via CMake.

<br/>

## Workflow

A typical MemDBG session:

1. Build and deploy the compatible payload to a supported console (`make deploy-ps5` or `make deploy-ps4`).
2. Launch the frontend on your dev machine (`make frontend && ./build/frontend/memdbg_frontend`).
3. In **Consoles**, set the IP and ports (matching the payload) and press **Connect**.
4. In **Processes**, refresh the list and pick a target — title ID, content ID, and executable path are all surfaced.
5. **Memory**: read/write raw bytes; drop watchpoints to detect value changes; import allocation events if you want to track heap lifetime.
6. **Scanner**: run an exact-value scan for a known value; change that value in-game; refine (changed / unchanged / increased / decreased) until few results remain; or pick **Smart Auto-Search → Health / Ammo / Resources** for a heuristic walk.
7. **AOB Scan** or **Pointer Scan** to get stable addresses that survive ASLR.
8. **Trainer**: build a cheat list — name, address, type, ON/OFF values, lock interval — then save as a `.cht` trainer file or import a `batchcode` string.
9. **Telemetry**: keep an eye on throughput and scan cache hit rate to know if you're reading too aggressively or scanning too wide.
10. **Logs** (`F10`): scroll through the live UDP feed for any console-side errors.

<br/>

## Configuration

The frontend persists a small `frontend.conf` file under the per-platform app-config directory:

| OS | Path |
|---|---|
| Linux | `~/.config/MemDBG/frontend.conf` |
| macOS | `~/Library/Application Support/MemDBG/frontend.conf` |
| Windows | `%APPDATA%\MemDBG\frontend.conf` |

Settings stored:

```ini
host=192.168.1.100
debug_port=9020
udp_port=9023
dump_path=dumps
language=en
```

A static user-facing guide is published via **GitHub Pages** from [`github-pages/`](github-pages). Deploy that directory as the Pages root to get a full HTML/CSS walkthrough of the workflow (default ports, connection, scanner, trainer, troubleshooting).

Supported payload CLI flags (host build):

| Flag | Purpose |
|---|---|
| `--bind=0.0.0.0` | TCP bind address. |
| `--debug-port=9020` | TCP port the frontend connects to. |
| `--udp-port=9023` | UDP port for telemetry + discovery. |
| `--data-root=/tmp/MemDBG` | Working directory for log files and dumps. |
| `--no-udp-log` | Disable UDP log delivery (still replies to DISCOVERY). |
| `--no-replace-existing` | Refuse to overwrite an already-running payload instance. |

<br/>

## Release Pipeline

The release workflow at [`.github/workflows/release.yml`](.github/workflows/release.yml) builds a matrix of seven artifacts on every tag (`v*`) or `workflow_dispatch`:

| Job | Artifact |
|---|---|
| `host-linux` | `MemDBG-host-linux` |
| `host-macos` | `MemDBG-host-macos` |
| `frontend-linux` | `MemDBG-frontend-linux` |
| `frontend-macos` | `MemDBG-frontend-macos.app.zip` |
| `frontend-windows` | `MemDBG-frontend-windows` |
| `payload-ps4` | `MemDBG-ps4.elf` + `libmemdbg-ps4.a` |
| `payload-ps5` | `MemDBG-ps5.elf` + `libmemdbg-ps5.a` |

`make check-locales` and the AOB + E2E tests are part of the host-Linux job, so a release can only ship when the locales are complete and the scanner passes its tests. Artifacts are uploaded to the matching GitHub Release alongside a `SHA256SUMS.txt`.

<br/>

## Repository Status

This repository is **pre-release / active development**. The wire protocol version is `1` and bumps are discussed before breaking changes. Concrete progress targets:

- ✅ Console process / map / memory primitives, all scan types, batch I/O, telemetry, discovery.
- ✅ Native desktop frontend on Linux, macOS, Windows, with full i18n.
- 🛠 Pointer chain tooling and trainer formats beyond base `.cht` (relative / pointer trainers, GoldHEN JSON) are staged in [`docs/feature_research.md`](docs/feature_research.md).
- 🛠 Native debugger tooling (attach / detach, breakpoints, disassembler) is tracked in the same document.

<br/>

## Contributing

Contributions are welcome once the project reaches its first public development milestone.

Open contribution areas:

- **UI development** — Dear ImGui panels, layout, theming, accessibility.
- **Scanner optimization** — SIMD, parallelism, additional filtering modes.
- **Backend integration** — new payload protocols or platform ports.
- **Documentation and translations** — drop a new `<code>.json` under `frontend/locales/` and open a PR; `make check-locales` will guide you.
- **Bug reports and feature proposals** via GitHub Issues.

Please review the project goals and ethical guidelines before opening a pull request.

<br/>

## Ethical Use

MemDBG is built for legitimate debugging, security research, education, and homebrew development.

It is **not** intended for:

- Online cheating or multiplayer advantage.
- Piracy or circumventing paid content.
- Accessing systems or software without authorization.
- Attacking third-party services or disrupting online play.

The maintainers do not support and will not assist with any of the above.

<br/>

## Disclaimer

This project is provided for educational and research purposes only. The authors and contributors accept no responsibility for misuse, hardware or software damage, account actions, legal consequences, or violations of third-party terms of service.

Use at your own risk, on hardware and software you own or are authorized to analyze.

<br/>

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).

<br/>

---

<div align="center">

**MemDBG** — `mem` + `DBG` — memory debugging for PS4 / PS5 research.

</div>

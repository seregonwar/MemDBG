<div align="center">

<br/>

<img src="assets/logo-nobg.png" width="550" height="550" alt="MemDBG" />

<br/>
<br/>

**Memory debugging and inspection suite for PS4 / PS5 research environments.**

<br/>

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-black?style=flat-square)](LICENSE)
[![Platform: PS4 / PS5](https://img.shields.io/badge/Platform-PS4%20%2F%20PS5-black?style=flat-square)](#supported-platforms)
[![Status: Early Development](https://img.shields.io/badge/Status-Early%20Development-black?style=flat-square)](#repository-status)
[![Language: C11 / C++](https://img.shields.io/badge/Language-C11%20%2F%20C%2B%2B-black?style=flat-square)](#building)

<br/>

</div>

---

MemDBG is a high-performance memory debugging suite designed for PlayStation 4 and PlayStation 5 homebrew research. It combines a precise memory scanning engine with a remote debugging frontend, providing a unified interface for process inspection, memory analysis, and runtime debugging workflows.

Built for developers, security researchers, and advanced users who need low-level visibility into console memory — without compromising on speed or ergonomics.

> Intended for educational, research, preservation, and offline homebrew development purposes only.

<br/>

## Architecture

```
MemDBG
├── Payload Daemon          C11 — TCP wire protocol, process & memory backend
├── Core Scanner            High-performance scan engine, value comparison, filtering
├── Platform Abstraction    PS4 / PS5 backend isolation layer
├── UDP Telemetry           Diagnostic mirror → /data/MemDBG/MemDBG.log
├── Frontend UI             C++ / Dear ImGui — scanner, editor, trainer, watchlist
└── Plugin / Scripting      Planned extensibility layer
```

The payload daemon exposes process enumeration, memory map inspection, and read/write primitives over a compact TCP protocol. The frontend connects to the payload port, listens for UDP telemetry, and provides the full interactive interface.

<br/>

## Features

**Core**
- Memory read / write interface
- Remote process inspection and listing
- Memory region and map enumeration
- Hex viewer and live memory editor
- Exact-value memory scan with type selection
- Scan refinement (increased / decreased / unchanged / changed)
- Pointer and address tracking
- Session and project management

**Frontend**
- Dear ImGui — responsive, keyboard-navigable interface
- Runtime trainer list with ON / OFF capture and value lock / freeze
- Base cheat table load and save (`.cht`)
- Memory map dump for selected regions
- UDP log viewer with live telemetry feed

**Planned**
- Unknown initial value scan
- Multi-stage scan refinement pipeline
- Watchlist system
- Symbol and module viewer
- Thread information and register / context view
- Breakpoint management (where platform supports)
- Pointer scanner
- Memory region visualization
- Import / export profiles
- Plugin API and scripting support
- Automation interface
- Performance profiling tools

<br/>

## Supported Platforms

| Platform       | Status              |
|:---------------|:--------------------|
| PlayStation 5  | In development      |
| PlayStation 4  | In development      |
| Windows (host) | Planned             |
| Linux (host)   | Planned             |
| macOS (host)   | Planned             |

Platform support depends on the availability of compatible homebrew payloads and firmware-level debugging environments.

<br/>

## Building

### Prerequisites

- PS5 payload SDK at `external/ps5-payload-sdk/` (override with `PS5_PAYLOAD_SDK`)
- C11-compatible compiler for the payload target
- C++ toolchain with Dear ImGui for the frontend

### Payload — PS5

```sh
make payload-ps5
```

Override variables as needed:

```sh
make payload-ps5 PS5_PAYLOAD_SDK=/path/to/sdk PS5_HOST=192.168.1.100 PS5_PORT=9020
```

### Host Validation Build

```sh
make clean && make
./build/MemDBG-host --bind=127.0.0.1 --udp-host=127.0.0.1 --data-root=/tmp/MemDBG
```

### Frontend

```sh
make frontend
./build/frontend/MemDBG_frontend
```

<br/>

## Workflow

A typical MemDBG session:

1. Deploy the compatible debugging payload to a supported console.
2. Connect the frontend to the payload TCP endpoint.
3. Select a target process from the process list.
4. Run an exact-value scan for a known value.
5. After the value changes in-game, refine the scan.
6. Add candidate addresses to the watchlist.
7. Inspect or modify values at runtime.
8. Save the session for later analysis or sharing.

<br/>

## Configuration

A future configuration file will allow persistent settings:

```json
{
  "defaultHost": "192.168.1.100",
  "defaultPort": 9020,
  "platform": "auto",
  "scanThreads": 8,
  "sessionAutosave": true
}
```

Options are subject to change before the first stable release.

<br/>

## Contributing

Contributions are welcome once the project reaches its first public development milestone.

Open contribution areas:

- UI development (Dear ImGui panels, layout, UX)
- Scanner optimization (SIMD, parallelism, filtering)
- Backend integration (new payload protocols)
- Documentation and testing
- Bug reports and feature proposals

Please review the project goals and ethical guidelines before submitting a pull request.

<br/>

## Ethical Use

MemDBG is built for legitimate debugging, security research, education, and homebrew development.

It is **not** intended for:

- Online cheating or multiplayer advantage
- Piracy or circumventing paid content
- Accessing systems or software without authorization
- Attacking third-party services or disrupting online play

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

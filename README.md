# MemDBG

**MemDBG** is a high-performance memory debugging and inspection suite designed for PlayStation 4 and PlayStation 5 homebrew research environments.

The goal of the project is to provide a clean, fast, and extensible interface for memory scanning, process inspection, debugging workflows, and runtime analysis across supported console platforms.

> MemDBG is intended for educational, research, preservation, and offline homebrew development purposes only.

---

## Overview

MemDBG combines the flexibility of a memory scanner with the power of a remote debugging frontend.

It is designed to work with compatible debugging payloads and homebrew environments on PS4 and PS5, offering a unified interface for developers, researchers, and advanced users who need to inspect memory, analyze processes, and build custom debugging workflows.

---

## Key Features

* Cross-platform support for **PS4** and **PS5**
* High-performance memory scanning engine
* Remote process inspection
* Memory read/write interface
* Address search and filtering
* Hex viewer and memory editor
* Pointer and address tracking
* Debugger-oriented workflow
* Modular backend support
* Clean and responsive UI
* Project/session management
* Extensible architecture for future plugins

---

## Planned Features

* Advanced value scanner
* Multi-stage scan refinement
* Cheat table support
* Symbol and module viewer
* Breakpoint management
* Watchlist system
* Pointer scanner
* Memory region visualization
* Import/export profiles
* Plugin API
* Scripting support
* Trainer-style runtime controls
* Performance profiling tools

---

## Supported Platforms

| Platform         | Status                   |
| ---------------- | ------------------------ |
| PlayStation 4    | Planned / In development |
| PlayStation 5    | Planned / In development |
| Windows frontend | Planned                  |
| Linux frontend   | Planned                  |
| macOS frontend   | Planned                  |

Support depends on the availability of compatible payloads, firmware support, and homebrew/debugging environments.

---

## Project Goals

MemDBG aims to be:

* **Fast** — optimized scanning and memory operations
* **Clean** — simple interface, readable codebase, minimal clutter
* **Modular** — backend support can evolve independently
* **Cross-generation** — one tool for both PS4 and PS5 workflows
* **Research-focused** — useful for debugging, analysis, and homebrew development
* **Extensible** — designed with future plugins and automation in mind

---

## Non-Goals

MemDBG is **not** intended for:

* Online cheating
* Multiplayer advantage
* Piracy
* Circumventing paid content
* Attacking third-party systems
* Bypassing platform security for unauthorized purposes
* Disrupting online services or other users

The project should be used only on hardware, software, and data you own or are authorized to analyze.

---

## Architecture

MemDBG is designed around a modular architecture:

```text
MemDBG
├── Payload Daemon
├── Wire Protocol
├── Core Scanner
├── Process / Memory Backend
├── Platform Abstraction Layer
├── UDP Telemetry
├── Frontend UI
└── Plugin / Scripting Layer
```

### Payload Daemon

The C11 payload daemon exposes process listing, memory map inspection, memory read/write, and exact-value scanning through a compact TCP protocol.

### Frontend

The frontend provides the main user interface for process selection, memory scanning, editing, watchlists, and debugging controls.

### Core Scanner

The scanner handles high-performance memory search operations, value comparison, filtering, and scan refinement.

### Platform Backends

Platform backends communicate with compatible PS4 or PS5 debugging payloads and expose a common interface to the rest of the application.

### UDP Telemetry

The payload mirrors diagnostic output to UDP while still writing persistent logs to `/data/MemDBG/MemDBG.log`.

---

## Example Workflow

A typical MemDBG workflow may look like this:

1. Connect to a supported console running a compatible debugging environment.
2. Select a target process.
3. Scan memory for a known value.
4. Refine the scan after the value changes.
5. Add relevant addresses to the watchlist.
6. Inspect or edit values during runtime.
7. Save the session for later analysis.

---

## Repository Status

This project is currently in early development.

APIs, file formats, UI layout, and backend behavior may change frequently before the first stable release.

---

## Installation

Installation instructions will be added once the first public build is available.

```bash
# Placeholder
git clone https://github.com/your-username/MemDBG.git
cd MemDBG
```

---

## Building

The payload side is C11.

Host validation build:

```bash
make clean
make
./build/MemDBG-host --bind=127.0.0.1 --udp-host=127.0.0.1 --data-root=/tmp/MemDBG
```

PS5 payload build:

```bash
make payload-ps5
```

The PS5 target uses `external/ps5-payload-sdk/` by default. Override `PS5_PAYLOAD_SDK`, `PS5_HOST`, or `PS5_PORT` when needed.

Frontend build:

```bash
make frontend
./build/frontend/MemDBG_frontend
```

The frontend is a C++/Dear ImGui desktop app. It can connect to the payload TCP port, listen for UDP logs, list processes and maps, show process metadata when available, read/write memory, run exact scans, refine scan results, dump selected memory maps, and build a small runtime trainer list with ON/OFF capture, lock/freeze support, and base `.cht` load/save.

Feature research and the implementation roadmap are tracked in `docs/feature_research.md`.

---

## Configuration

A future configuration file may include:

```json
{
  "defaultHost": "192.168.1.100",
  "defaultPort": 9020,
  "platform": "auto",
  "scanThreads": 8,
  "sessionAutosave": true
}
```

Configuration options are subject to change.

---

## Roadmap

### Phase 1 — Core Foundation

* Basic project structure
* PS4/PS5 backend abstraction
* Remote connection manager
* Process list
* Memory region listing
* Basic memory read/write

### Phase 2 — Scanner

* Exact value scan
* Unknown initial value scan
* Increased/decreased value filtering
* Data type support
* Result table
* Watchlist

### Phase 3 — Debugging Tools

* Module viewer
* Thread information
* Register/context view
* Breakpoint support where available
* Runtime memory tools

### Phase 4 — Usability

* Session save/load
* Cheat table format
* Import/export
* UI polish
* Error reporting
* Performance improvements

### Phase 5 — Extensibility

* Plugin system
* Scripting support
* Automation API
* Custom backend modules

---

## Contributing

Contributions are welcome once the project reaches a public development stage.

Possible contribution areas:

* UI development
* Scanner optimization
* Backend integration
* Documentation
* Testing
* Bug reports
* Feature proposals

Before submitting a pull request, please make sure your contribution follows the goals and ethical guidelines of the project.

---

## Ethical Use

MemDBG is built for legitimate debugging, research, education, and homebrew development.

Do not use this project to gain unfair advantages in online games, interfere with services, violate terms of service, or access systems and software without permission.

The maintainers do not support piracy, online cheating, or malicious use.

---

## Disclaimer

This project is provided for educational and research purposes only.

The authors and contributors are not responsible for misuse, damage, account bans, hardware issues, software issues, legal consequences, or violations of third-party terms of service.

Use at your own risk.

---

## License

MemDBG is licensed under GPL-3.0-or-later. See [LICENSE](LICENSE).

---

## Credits

MemDBG is inspired by existing homebrew debugging and memory inspection tools from the console research community.

Special thanks to developers and researchers who contribute to open-source homebrew tooling, debugging payloads, and memory analysis projects.

---

## Name

**MemDBG** stands for:

```text
mem  = memory
DBG  = debug
```

A short, technical name for a cross-generation memory debugging suite.

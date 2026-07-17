# Action Journal

Self-contained, reusable C++ module for recording structured user actions as a JSON-lines journal. Designed to survive frontend crashes and enable post-mortem diagnostics.

```cpp
#include "action_journal.hpp"
```

## Overview

The Action Journal records every user operation (connect, disconnect, scan, memory read, etc.) into a JSON-lines file. Each entry is flushed to disk immediately, so the last actions survive even a hard application crash. On restart, the journal can be inspected to:

- Detect unclean shutdowns (missing `clean_shutdown` marker)
- Offer to pre-fill a GitHub issue with the recorded actions
- Replay actions to reproduce a crash

Session boundaries are marked with `session_start` and `clean_shutdown` entries.

### File format

Each line is a standalone JSON object:

```json
{"ts":1712345678,"action":"scan_exact","detail":{"type":"u32","value":"42","pid":1234,"name":"eboot.bin"}}
```

Markers use empty detail objects:

```json
{"ts":1712345600,"action":"session_start","detail":{}}
{"ts":1712345999,"action":"clean_shutdown","detail":{}}
```

---

## API Reference

### `ActionJournalEntry`

```cpp
struct ActionJournalEntry {
    std::time_t timestamp;  // Unix epoch
    std::string action;     // Operation name
    std::string detail;     // JSON object with params
};
```

### `ActionJournal`

| Method | Description |
|--------|-------------|
| `ActionJournal()` | Constructor. Does not open a file. |
| `~ActionJournal()` | Destructor. Calls `close()`. |
| `bool open(const char *path)` | Opens the journal file (append mode). Writes `session_start`. Creates parent directories if needed. Returns `false` on failure. |
| `void close()` | Writes `clean_shutdown`, flushes, and closes. Call at shutdown. |
| `void record(const char *action, const char *detail)` | Thread-safe. Writes and flushes an entry immediately. `detail` must be a valid JSON object string (e.g. `{"key":"value"}`). If either is null/empty, defaults are used. |
| `void record_marker(const char *marker)` | Shortcut for `record(marker, "{}")`. |
| `void set_enabled(bool)` | Enable/disable at runtime. Disabled calls are silently ignored. |
| `bool enabled()` | Returns current state. |
| `bool is_open()` | True when the file is open and writable. |

### Static methods

| Method | Description |
|--------|-------------|
| `static bool load_recent(path, entries, max, *clean)` | Parses a journal file, returns the last `max` entries (default 200). Sets `*clean` to `true` if a `clean_shutdown` marker exists. Excludes markers from `entries`. |
| `static std::string build_crash_report_url(actions, version, platform, anonymize, telemetry)` | Builds a GitHub issue URL for `console_crash.yml` pre-filled with reproduction steps, platform info, and build version. `anonymize` (default `true`) redacts IPs, PIDs, process names, and paths. `include_telemetry` (default `true`) includes detail fields in steps. |
| `static std::filesystem::path default_path()` | Returns `<app_data>/logs/memdbg_actions.log`. |
| `static std::string json_escape(const std::string &value)` | Escapes `"`, `\`, and control characters (U+0000–U+001F) for safe JSON string concatenation. **Always wrap user-controlled values** with this when building detail strings manually. |

---

## Integration

### CMake

```cmake
# Add the module to your target
target_sources(your_target PRIVATE
    path/to/action_journal/action_journal.cpp
)

target_include_directories(your_target PRIVATE
    path/to/action_journal   # for #include "action_journal.hpp"
    path/to/sjson            # sjson single-header dependency
)
```

### Dependencies

| Dependency | Required for |
|-----------|-------------|
| `sJson.c` (external) | JSON parsing and serialization |

Zero additional dependencies — only standard C++17 and sjson. The path
for `open()` is provided by the caller (e.g. `platform::app_data_dir() /
"logs" / "memdbg_actions.log"`).

### Startup / shutdown

```cpp
#include "action_journal.hpp"
#include "platform.hpp"  // for app_data_dir() — use your own path provider

memdbg::frontend::ActionJournal journal;

// At startup: caller provides the path
const auto path = platform::app_data_dir() / "logs" / "memdbg_actions.log";
if (!journal.open(path.c_str())) {
    // Log warning: journal unavailable
}
journal.set_enabled(true);

// At shutdown
journal.close();
```

### Recording actions

```cpp
// Simple action with no params
journal.record("connect", "{}");

// Action with JSON detail — always use json_escape for user input
std::string detail = "{\"pid\":" + std::to_string(pid)
    + ",\"name\":\"" + ActionJournal::json_escape(process_name) + "\""
    + ",\"host\":\"" + ActionJournal::json_escape(host) + "\"}";
journal.record("process_select", detail.c_str());
```

### Crash review (at startup)

```cpp
const auto path = platform::app_data_dir() / "logs" / "memdbg_actions.log";
std::vector<ActionJournalEntry> actions;
bool clean_shutdown = false;

if (ActionJournal::load_recent(path, actions, 200, &clean_shutdown)) {

    if (!clean_shutdown) {
        // Unclean exit detected
        std::string url = ActionJournal::build_crash_report_url(
            actions, "1.0.0", "macOS 14", true, true);
        // Show dialog: "MemDBG crashed last session. Report issue?"
        // On confirm: open url in browser
    }
}
```

---

## Thread safety

- `record()` and `record_marker()` acquire a mutex internally. Safe to call from any thread.
- `open()` and `close()` acquire the same mutex. Do not call concurrently with `record()`.
- `set_enabled()` / `enabled()` are lock-free atomics.
- `load_recent()` and `build_crash_report_url()` are static and thread-safe (no shared state).

---

## Anonymization

When `build_crash_report_url()` is called with `anonymize=true` (default):

| Key | Transformation |
|-----|---------------|
| `host` | IP octets beyond the first are replaced with `x` (e.g. `192.x.x.x`) |
| `pid` | Replaced with `[PID]` |
| `name` | Replaced with `[PROCESS]` |
| `path` | Only the last path component is kept (e.g. `[REDACTED]/eboot.bin`) |

All other detail fields are passed through unchanged.

---

## Exporting / reusing

This module is self-contained and can be copied into other projects:

1. Copy `action_journal.hpp` and `action_journal.cpp` to your project
2. Copy `sJson.c` from MemDBG's `external/sjson/` (or use any JSON library; replace the `extern "C" {}` block in the `.cpp`)
3. Add the sjson dependency and your own path provider
4. Add to your CMake target as shown above

The module has no dependency on ImGui, GLFW, `platform.hpp`, or any other
MemDBG frontend code.

---

## License

SPDX-License-Identifier: GPL-3.0-or-later

Copyright (C) 2026 SeregonWar

Part of the [MemDBG](https://github.com/seregonwar/MemDBG) project.

# AppState Substruct Pattern

MemDBG's frontend state was originally a monolithic `AppState` struct with
~240 members spanning processes, scanner, debugger, trainer, plugins,
connection lifecycle, and more.  An external audit identified this as a
"God Object" risk — the single largest architectural concern in the frontend.

The decomposition replaces inline member groups with dedicated substructs,
each declared **above** `AppState` and referenced as a named field.

## Before & After

```cpp
// BEFORE: 240+ members in one flat struct (1,100+ lines)
struct AppState {
  // ... connection state ...
  bool connect_pending = false;
  uint64_t connect_generation = 0;
  bool heartbeat_pending = false;
  // ... scanner state ...
  int scan_type = MEMDBG_VALUE_U32;
  char scan_value[128] = "0";
  // ... ELF load state ...
  char elf_load_path[512] = "";
  // ... another 230 members ...
};

// AFTER: substructs + ~60 root members (~600 lines)
struct ElfState { /* 32 members */ };
struct TracerState { /* 26 members */ };
struct TaskMgrState { /* 25 members */ };
struct PluginState { /* 40 members */ };
struct ScannerState { /* 62 members */ };
struct ConnectionState { /* 18 members */ };
struct MemoryState { /* 23 members */ };
struct KlogState { /* 11 members */ };

struct AppState {
  // ... root members (~60) ...
  ElfState elf;
  TracerState tracer;
  TaskMgrState taskmgr;
  PluginState plugin;
  ScannerState scan;
  ConnectionState conn;
  MemoryState mem;
  KlogState klog;
};
```

## Substructure Reference

| Struct | Field | Members | Commit | Description |
|--------|-------|---------|--------|-------------|
| `ElfState` | `state.elf` | 32 | `431a063` | ELF drag-drop, segment metadata, load/hijack async |
| `TracerState` | `state.tracer` | 26 | `431a063` | Syscall tracer attach/detach, status, events, crash detection |
| `TaskMgrState` | `state.taskmgr` | 25 | `f5867bb` | Process resource table, fmem samples, batch prefetch |
| `PluginState` | `state.plugin` | 40 | `0417129` | Plugin sources, cheat repos, trainer cheats, GUI bridge state |
| `ScannerState` | `state.scan` | 62 | `e256987` | Core scan config, value editor, AOB/pointer scanners, async scan, auto-search |
| `ConnectionState` | `state.conn` | 18 | `e42502f` | Connect/heartbeat lifecycle, debugger attach, reconnect state machine |
| `MemoryState` | `state.mem` | 23 | `e42502f` | Read/write/dump buffers, allocation tracking, memory overlay |
| `KlogState` | `state.klog` | 11 | `e42502f` | Kernel log streaming, line buffer, auto-scroll, search |

## Rename Convention

The bulk rename converts dot-notation naturally:

| Before | After |
|--------|-------|
| `state.scan_type` | `state.scan.type` |
| `state.scan_async_pending` | `state.scan.async_pending` |
| `state.aob_pattern` | `state.scan.aob_pattern` |
| `state.connect_pending` | `state.conn.connect_pending` |
| `state.klog_connected` | `state.klog.connected` |
| `state.elf_load_path` | `state.elf.load_path` |
| `state.tracer_pending` | `state.tracer.pending` |
| `state.taskmgr_selected_row` | `state.taskmgr.selected_row` |
| `state.plugin_gui_active_id` | `state.plugin.gui_active_id` |

**Regex order matters**: more specific patterns must run before generic ones
(e.g., rename `state.scan_async_*` before `state.scan_*` to avoid partial
matches).

## What Stays at the Root

Not everything belongs in a substruct.  These remain at `AppState` root:

- **Core subsystem objects** with complex lifecycles: `plugin_manager`,
  `cheat_repository`, `lua_engine`, `theme_manager`, `payload_fetcher`,
  `release_check`, `github_profile`
- **Shared references**: `Client &client = pool.control()` (reference to
  `ClientPool`)
- **Cross-cutting state**: `screen`, `status`, `notifications`,
  `processes`, `maps`, `selected_pid`, `selected_map_row`
- **Payload injection**: `payload_inject_pending`, `payload_port`,
  `payload_platform` (system-level, not connection transport)
- **UI helpers**: `sidebar_width`, `map_filter_*`, `settings_active_section`
- **Mutexes and atomics** that coordinate across subsystems

The rule: **extract when a group of 10+ members shares a clear purpose,
are always accessed together, and don't need complex inter-struct
synchronization.**

## Adding a New Substruct

1. **Count your members** — aim for 10+ related fields with a clear boundary.

2. **Define the struct above `AppState`** in `app_state.hpp`:
   ```cpp
   struct MyNewState {
     int foo = 0;
     char bar[64] = "";
     std::vector<Baz> items;
     // ... all related members ...
   };
   ```

3. **Replace inline members** in `AppState` with a single field:
   ```cpp
   MyNewState my;
   ```

4. **Bulk rename** across the codebase. Use a Python script that applies
   regexes in specific-to-generic order:
   ```python
   renames = [
       (r'\bstate\.my_specific_(\w+)', r'state.my.specific_\1'),
       (r'\bstate\.my_(\w+)',         r'state.my.\1'),
   ]
   for pattern, replacement in renames:
       content = re.sub(pattern, replacement, content)
   ```
   Run the script on every `.cpp` and `.hpp` file under `frontend/src/`.

5. **Build and fix**: `cmake --build build/frontend -j4`. Fix any missed
   references manually.

6. **Update `client_async_busy()`** and `connect_sequence_pending()` inline
   helpers if the extracted members are listed there.

7. **Build all targets** (including tests):
   ```bash
   cmake --build build/frontend --target all -j4
   ```

8. **Commit** with a descriptive message following the convention:
   ```
   refactor(frontend): extract MyNewState from AppState
   ```

## Performance Notes

- Substructs add no runtime overhead — the memory layout is identical
  (all fields are still contiguous within `AppState`).
- `std::mutex` and `std::atomic` members inside substructs make the
  parent `AppState` non-copyable, which **it already was**.
- Compile times improved slightly (~5%) because fewer translation units
  need to re-parse the full member list when only one substruct changes.

## History

The decomposition was driven by an external audit recommendation (~2026-07)
that identified `app_state.hpp` (1,109 lines, 1,004 lines of code) as the
primary God Object risk.  Eight substructs were extracted across six commits,
reducing `AppState` by ~70% and eliminating the largest architectural concern
flagged by the audit.

See also: [codecave.md](codecave.md), [plugins.md](plugins.md),
[protocol.md](protocol.md).

# Reconnect System (Rest-Mode Resilience)

MemDBG's reconnect system enables the frontend to survive console rest-mode cycles — the
connection is temporarily lost, the console enters low-power sleep, and when it wakes the
frontend automatically reconnects **without destroying the user's work** (scan results,
trainer definitions, UI state).

## Overview

When a PlayStation 4 or 5 enters rest mode, the payload daemon may be:
1. **Terminated** — the payload process dies and must be re-injected.
2. **Suspended** — the process survives but loses its network sockets.
3. **Suspended with stale sockets** — the process and socket FDs survive, but the
   console's network stack is temporarily unavailable.

The reconnect system handles all three cases through a layered design:

| Layer | File(s) | Responsibility |
|-------|---------|---------------|
| **State machine** | `app_state.hpp` (enums, structs), `session.cpp` (transitions) | Detects transport loss, tracks reconnect phase, preserves UI state |
| **Connection lifecycle** | `connection.cpp` (`quiesce_transport`, `reset_remote_session`, `connect_console`) | Separates non-destructive quiesce from full session teardown |
| **Epoch protocol** | `app_state.hpp`, `scanner_async.cpp`, `screen_processes.cpp` | Prevents stale async results from old connections |
| **Session restoration** | `session.cpp` (`poll_restore_session`, `TargetIdentity`) | Rematches the target process after reconnect using logical identity |
| **Daemon identity** | `memdbg_protocol.h` (HELLO v2), `response.c` | `daemon_instance_id` detects payload restart vs survival |

---

## State Machine

### ConnectionPhase Enum

```cpp
enum class ConnectionPhase {
  Disconnected,      // No active session (initial state or manual disconnect)
  Connecting,        // Async connect in progress (manual → spinner modal shown)
  Online,            // Fully connected, remote operations allowed
  ConnectionLost,    // Transport detected dead (heartbeat failed)
  WaitingForWake,    // Backoff timer counting down before next retry
  Reconnecting,      // Async reconnect attempt in progress (no modal)
  Restoring,         // Reconnected — refreshing process list & rematching target
};
```

### Phase Transition Diagram

```
  Disconnected
       │
       ▼ (user clicks Connect, or payload auto-inject completes)
  Connecting ──────────────► Online
       │                        │
       │ (failure / cancel)     │ (heartbeat ×2 fails)
       ▼                        ▼
  Disconnected           ConnectionLost
                               │
                               ▼
                         WaitingForWake ── (user cancels) ──► Disconnected
                               │
                               │ (backoff timer expires)
                               ▼
                         Reconnecting ── (user cancels) ──► Disconnected
                               │
                               ▼ (HELLO succeeds)
                          Restoring
                               │ (process list refreshed, target rematched)
                               ▼
                             Online
```

### ReconnectState

```cpp
struct ReconnectState {
  bool enabled = true;              // Can be disabled via settings
  bool manual_disconnect = false;   // User explicitly disconnected → no auto-reconnect
  bool stale = false;               // Remote state (PID, maps, debugger) is suspect
  ConnectionPhase phase{Disconnected};
  uint32_t attempt = 0;             // Consecutive retry count
  uint64_t epoch = 0;               // Bumped on every disconnect cycle
  steady_clock::time_point next_attempt_at{};
  steady_clock::time_point started_at{};
  std::string reason;
  TargetIdentity target_identity;   // Saved before disconnect for rematch
};
```

Key design decisions:
- **`std::chrono::steady_clock`** (not `ImGui::GetTime()`): immune to computer sleep.
  If the frontend machine itself suspends, the backoff timer doesn't drift.
- **`manual_disconnect` gate**: user-initiated disconnects are permanent. Only
  transport-level failures trigger auto-reconnect.
- **`stale` flag**: set `true` on disconnect, cleared to `false` only after
  completed `Restoring` phase. While `stale`, `remote_ready()` returns `false`.

### Heartbeat Threshold

The frontend detects transport loss through **two consecutive heartbeat failures**
(`heartbeat_failures >= 2`). A single timeout is ignored — it may be caused by
a heavy scan, network congestion, or a temporary kernel stall.

Heartbeats are suspended during long-running operations (scans, dumps) to avoid
false positives. The `heartbeat_pending` flag gates the health check.

### Backoff Schedule

```
Attempt 0:   500 ms
Attempt 1:  1000 ms
Attempt 2:  2000 ms
Attempt 3:  4000 ms
Attempt 4:  8000 ms
Attempt 5+: 10000 ms (repeats indefinitely)
```

Defined in `connection.cpp`:

```cpp
static constexpr std::array<milliseconds, 6> kBackoff{
  milliseconds(500),  milliseconds(1000), milliseconds(2000),
  milliseconds(4000), milliseconds(8000), milliseconds(10000)};
```

---

## Key Functions

### `begin_reconnect()` — `session.cpp`

Called when transport loss is detected (heartbeat failure ×2 or socket error).

1. Saves `TargetIdentity` from the currently selected process.
2. Cancels all pending I/O, disconnects control socket, invalidates role sockets.
3. Bumps `reconnect.epoch` — all in-flight async operations from the old epoch
   are now stale.
4. Sets `phase = WaitingForWake`, initializes backoff timer.

```cpp
void begin_reconnect(AppState &state, const std::string &reason);
```

### `poll_session_health()` — `session.cpp`

Called every frame by `draw_app()`. Checks for transport-level failure:

```cpp
if (state.has_hello && !state.client.connected() &&
    !state.conn.connect_pending &&
    state.conn.reconnect.phase == ConnectionPhase::Online) {
  begin_reconnect(state, ...);
}
```

**Critical guard**: the `phase == Online` check prevents re-triggering
`begin_reconnect` every frame after the first failure (which would reset
the backoff timer infinitely).

### `poll_reconnect()` — `session.cpp`

Called every frame, immediately after `poll_session_health()`. Advances the
state machine when the backoff timer expires:

```cpp
if (phase != WaitingForWake && phase != Reconnecting) return;
if (now < next_attempt_at) return;
phase = Reconnecting;
connect_console(state, ConnectIntent::AutomaticReconnect);
```

### `poll_connect()` — `connection.cpp`

Collects the result of the async `connect_console()` future:

- **Success on reconnect path**: enters `Restoring` phase. Debugger and tracer
  state are invalidated (attachments tied to old PID). Daemon instance ID is
  checked for rotation.
- **Success on manual connect**: enters `Online` directly (fresh session).
- **Failure on reconnect**: calls `schedule_reconnect_retry()` which updates
  the status bar with current attempt and retry seconds.
- **Cancelled**: stops the reconnect state machine (`manual_disconnect = true`,
  `phase = Disconnected`).

### `cancel_connect()` — `connection.cpp`

Cancels any in-flight connection attempt. If the reconnect state machine is
active (`WaitingForWake` or `Reconnecting`), this permanently stops it:

```cpp
void cancel_connect(AppState &state) {
  state.conn.reconnect.manual_disconnect = true;
  state.conn.reconnect.phase = ConnectionPhase::Disconnected;
  state.conn.reconnect.reason.clear();
  state.conn.reconnect.attempt = 0;
  state.conn.connect_cancel_requested = true;
  ++state.conn.connect_generation;
}
```

Once `manual_disconnect` is `true`, `begin_reconnect()` and `poll_reconnect()`
are both gated — the state machine will not restart until the user manually
connects again.

### `quiesce_transport()` vs `reset_remote_session()` — `connection.cpp`

| Operation | `quiesce_transport()` | `reset_remote_session()` |
|-----------|----------------------|--------------------------|
| Cancel pending I/O | ✅ | ✅ |
| Disconnect sockets | ✅ | ✅ |
| Clear process list | ❌ | ✅ |
| Clear maps | ❌ | ✅ |
| Reset scanner results | ❌ | ✅ |
| Reset debugger state | ❌ | ✅ |
| Preserve trainer definitions | ✅ | ❌ |
| Preserve scan results | ✅ | ❌ |
| Preserve UI state | ✅ | ❌ |
| Called on | transport loss (reconnect) | manual disconnect, shutdown |

### `poll_restore_session()` — `session.cpp`

Called every frame while `phase == Restoring`. Does **not** independently
request a process list — it polls `taskmgr.prefetch_future`, which was already
launched by `poll_connect()` falling through to `start_taskmgr_prefetch()`
after setting `phase = Restoring`.

```
poll_connect()                connection.cpp
  success on reconnect path
  → phase = Restoring
  → falls through to start_taskmgr_prefetch()  ← spawns async process list

poll_restore_session()        session.cpp
  polls taskmgr.prefetch_future                 ← collects the result
```

**`restore_list_requested` flag**: A bool in `AppState` that gates the forced
process list refresh. Set to `true` on the first `Restoring` frame (the flag
is initially `false`, so the first call triggers the refresh). Cleared to
`false` when the phase leaves `Restoring`. This prevents re-requesting the
list every frame.

Rematching logic:
1. Rematches the target process by `TargetIdentity`:
   - **Primary**: `title_id` match via `taskmgr.resources` (requires process info).
   - **Fallback**: `name` match against the process list.
2. On match: refreshes memory maps, sets `phase = Online`, clears `stale`.
3. On no match: sets `phase = Online` but leaves `stale = true` — the user must
   manually re-select the target process on the new daemon instance.

---

## TargetIdentity

PIDs are ephemeral across rest-mode cycles (the game process gets a new PID on
wake). `TargetIdentity` stores the logical identity of the target so the
frontend can rematch it:

```cpp
struct TargetIdentity {
  std::string name;              // "eboot.bin", "SceShellCore"
  std::string title_id;          // "CUSA12345"
  std::string content_id;        // "IV0001-CUSA12345_00-MEMDBG0000000000"
  std::string executable_path;   // "/app0/eboot.bin"
  std::string selected_module_name;
  uint64_t selected_module_offset = 0;

  bool valid() const { return !name.empty() || !title_id.empty(); }
};
```

Captured in `begin_reconnect()` before the socket is closed, used in
`poll_restore_session()` for rematching.

---

## Epoch Protocol

Every disconnect cycle bumps `reconnect.epoch`. Async operations capture the
epoch at launch and reject their results if the epoch has changed by the time
they complete.

### Operations with Epoch Protection

| Operation | Epoch field | File |
|-----------|------------|------|
| Telemetry | `telemetry_epoch` | `connection.cpp` |
| Map refresh | `map_refresh_epoch` | `connection.cpp` |
| TaskMgr prefetch | `taskmgr.prefetch_epoch` | `connection.cpp` |
| Scanner (all 4 variants) | `scan.async_epoch` | `scanner_async.cpp` |
| Map dump | `map_dump_epoch` | `screen_processes.cpp` |

### Epoch Check Pattern

```cpp
// Launch: capture epoch
state.scan.async_epoch = state.conn.reconnect.epoch;

// Poll: reject if stale
const uint64_t captured_epoch = state.scan.async_epoch;
state.scan.async_pending = false;
if (captured_epoch != state.conn.reconnect.epoch) {
  // Clear temp storage and consume the future, do NOT apply results
  state.scan.async_future.get();
  state.scan.async_temp_result = ScanResult{};
  state.scan.async_temp_snapshot.clear();
  return;
}
// Apply results...
```

### `remote_ready()` Gate

New remote operations should check `remote_ready()` before launching:

```cpp
inline bool remote_ready(const AppState &state) {
  return state.client.connected() &&
         state.conn.reconnect.phase == ConnectionPhase::Online &&
         !state.conn.reconnect.stale;
}
```

This is defined in `app_state.hpp` and blocks operations while: disconnected,
reconnecting, restoring, or when remote state is stale.

---

## Daemon Instance Identity (Protocol v2)

The HELLO response includes a `daemon_instance_id` (random uint64 generated at
daemon startup) and `daemon_start_monotonic_ns`. These allow the frontend to
distinguish:

| Scenario | `daemon_instance_id` | Action |
|----------|---------------------|--------|
| Payload survived rest mode | Same | Preserve state, revalidate processes/maps |
| Payload was terminated & re-injected | Different | Clear processes, maps, invalidate all remote handles |
| Pre-v2 payload | Zero | Degrade gracefully (skip rotation check) |

The `daemon_instance_id` is checked in `poll_connect()` after a successful
reconnect HELLO.

---

## Main Loop Integration

In `draw_app()` (`shell/memdbg_app.cpp`), the poll functions are called in
a specific order:

```cpp
poll_connect(state);           // Collect async connect result
poll_payload_lifecycle(state); // Payload inject → auto-connect flow

poll_session_health(state);    // Detect transport loss → begin_reconnect
poll_reconnect(state);         // Advance backoff timer → connect_console(Auto)

poll_restore_session(state);   // Rematch target process during Restoring phase

// Remaining periodic tasks (only launch when remote_ready)
poll_taskmgr_prefetch(state);
poll_telemetry(state);
poll_map_refresh(state);
poll_tracer(state);
poll_plugin_tasks(state);
poll_cheat_tasks(state);
```

**Key ordering**: `poll_session_health` must run before `poll_reconnect` —
the first detects the loss, the second advances the backoff state machine.

---

## What Is Preserved vs Invalidated

### Preserved Across Reconnect Cycles

- Current screen and UI state
- Console IP/port settings
- Trainer and cheat definitions
- Scan results (marked as unverified — `stale = true`)
- Scanner history and snapshots
- Target process name, title ID, content ID
- Selected module name and offset

### Invalidated on Every Reconnect

- PID (numeric) — always re-resolved
- Debugger attachment, breakpoints, watchpoints
- Tracer state
- Thread IDs
- Remote allocation handles
- Server-side scan jobs
- Memory maps (refreshed from daemon)
- Absolute addresses (recalculated from module base + offset)

### Suspended Until Verified

- Trainer lock writes and periodic writes
- Breakpoint re-enable
- Watchpoint re-enable
- Tracer re-attach

> **Note**: Trainer write suspension is implemented (PR 3 — `apply_locked_cheats()`
> checks `remote_ready()`). Automatic byte-verification before re-enabling
> breakpoints/watchpoints/tracer is **planned for PR 4**.

---

## Tests

| Test | File | What it validates |
|------|------|-------------------|
| Reconnect E2E | `tests/test_reconnect_e2e.c` | Daemon restart, HELLO v2, instance_id rotation, double cycle |
| State machine E2E | `tests/test_reconnect_state_machine.c` | Full phase transition cycle: Online → ConnectionLost → WaitingForWake → Reconnecting → Restoring → Online, heartbeat ×2, second cycle stress |
| Frontend state machine | `frontend/tests/test_app_reconnect.cpp` | 116 unit tests: ConnectionPhase transitions, TargetIdentity, remote_ready, epoch stale rejection, backoff timing, trainer suspension |

Run with:
```sh
make test-reconnect-e2e
make test-reconnect-state-machine
cd frontend && cmake --build build --target memdbg_app_reconnect_test && ./build/bin/memdbg_app_reconnect_test
```

---

## Future Work (PR 4–5)

- **PR 4**: Payload network supervisor — indefinite retry with backoff (currently
  gives up after 15 seconds). Listener-liveness probe for the case where socket
  FDs survive rest mode but the network stack is down.
- **PR 5**: Additional integration tests — `test_server_restart_same_instance`,
  `test_stale_future_rejection`, `test_listener_recreation`, `test_reconnect_fd_leaks`.
- Hardware validation: 50 cycles PS5 rest → wake, 20 cycles PS4 rest → wake.

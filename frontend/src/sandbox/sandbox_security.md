# MemDBG Sandbox — Security Documentation

## Threat Model

**Adversary:** A remote or local attacker who can submit arbitrary Lua or Python
code via plugin repositories or the built-in Lua Console REPL.

**Assets:**
- User's filesystem (read/write access to arbitrary files)
- User's network (outbound connections)
- User's processes (fork/exec arbitrary binaries)
- User's system (resource exhaustion → DoS)
- Connected consoles (arbitrary memory read/write via memdbg API)

**Trust Boundary:** The sandbox is a hard boundary. No code that enters the
sandbox can escape without exploiting a sandbox vulnerability.

---

## Vulnerability Audit Log

### V1 — Found & Fixed: pcall() Timeout/Instruction Limit Bypass
- **Severity:** HIGH (Host process hang)
- **Attack:** `pcall(function() while true do end end)` catches `luaL_error` from the count hook. The hook sets `s_timeout_active = false` on first violation, allowing the script to continue indefinitely via `pcall`.
- **Fix:** Added `s_aborted` — a persistent flag that survives `pcall` longjmps. Once any limit is hit, every subsequent hook invocation re-throws the error, making pcall-bypass impossible.
- **Test:** `test_advanced_escapes` → "pcall cannot catch timeout", "pcall cannot bypass instruction limit"

### V2 — Found & Fixed: Direct Searcher Invocation Bypass
- **Severity:** HIGH (Arbitrary code execution)
- **Attack:** `package.searchers[2]("malicious")` with modified `package.path` loads files directly, bypassing the guarded `require()`.
- **Fix:** Nil out ALL `package.searchers` indices (1-4). Only the guarded `require()` can load modules.
- **Test:** `test_advanced_escapes` → "all searchers nil'd"

### V3 — Found & Fixed: Native Code via All-in-One C Loader (searchers[4])
- **Severity:** HIGH (Privilege escalation / native code execution)
- **Attack:** `package.searchers[4]("lfs")` with modified `package.cpath` loads system-installed `.so` modules, bypassing the native code ban (only `searchers[3]` was nil'd).
- **Fix:** Nil `package.searchers[4]` in addition to `searchers[3]` (now all indices 1-4 are nil'd).
- **Test:** Covered by "all searchers nil'd" test

### V4 — Found & Fixed: Error String Output Limit Bypass
- **Severity:** LOW (Output flooding / memory pressure)
- **Attack:** `error(string.rep('X', 10*1024*1024))` produces a 10 MiB error message stored directly in `r.error`, bypassing `max_output_bytes`.
- **Fix:** Truncate `lua_tostring` output to `max_output_bytes` in both `exec()` and `exec_file()`.
- **Test:** `test_advanced_escapes` → "error strings truncated"

### V5 — Found & Fixed: Case-Insensitive Module Blocklist Bypass
- **Severity:** MEDIUM (Blocklist evasion)
- **Attack:** `require('IO')` or `require('Io')` would bypass the case-sensitive `strcmp` blocklist check. If a file named `IO.lua` existed, it would load.
- **Fix:** Module blocklist now uses case-insensitive comparison (`tolower`).
- **Test:** `test_advanced_escapes` → "require uppercase IO blocked"

---

## Lua Sandbox — Attack Surface & Mitigations

| Attack Vector | Mitigation | Verified By |
|---|---|---|
| `io.open("/etc/passwd")` | `io` library never loaded | Escape Tests |
| `os.execute("rm -rf /")` | `os` library never loaded (unless policy allows) | Escape Tests |
| `dofile("malicious.lua")` | Global set to `nil` | Escape Tests |
| `loadfile("malicious.lua")` | Global set to `nil` | Escape Tests |
| `load(code)` / `loadstring(code)` | Globals set to `nil` | Escape Tests |
| `package.loadlib("libc.so", "system")` | `package.loadlib` nil, `package.cpath` empty | Escape Tests |
| `package.searchers[n]` direct invocation | ALL searchers (1-4) set to `nil` | Advanced Escape Tests |
| `require("io")` | `require` guarded — blocks `io`, `os`, `ffi`, `socket`, `http`, `cjson`, `debug` | Escape Tests |
| `require("IO")` / `require("Io")` | Case-insensitive blocklist comparison | Advanced Escape Tests |
| `require("socket.http")` (dotted prefix) | Guard checks prefixed names (splits on `.`) | Escape Tests |
| `pcall(require, "io")` | Guard uses `luaL_error` — propagates through pcall | Advanced Escape Tests |
| `pcall(infinite_loop)` | `s_aborted` persistent flag survives pcall longjmps | Advanced Escape Tests |
| `pcall(instruction_bomb)` | `s_aborted` re-throws on every hook invocation | Advanced Escape Tests |
| `rawget(_G, "dofile")` | Returns `nil` (original was explicitly nil'd) | Escape Tests |
| `debug.getregistry()` | `debug` library never loaded; `require("debug")` blocked | Escape Tests |
| Path traversal (`../../etc/passwd`) | `is_safe_path()` rejects `..` and absolute paths | Path Traversal Tests |
| Symlink escape from plugin root | Canonical containment plus bounded buffer load | Path Traversal Tests |
| Capability bleed through `io` / `os` libraries | Dangerous mixed-capability functions removed after loading | Policy Tests |
| Memory exhaustion (10 GB table) | Custom allocator hook with 16 MiB hard cap | Memory Limit Tests |
| CPU exhaustion (`while true do end`) | Count-hook checks wall-clock every 5k VM instructions | Timeout Tests |
| Stack overflow (deep recursion) | Count-hook checks `lua_getstack` depth | Stack Depth Tests |
| Output flooding (100 MB print) | `print()` capturer truncates at 256 KiB | Output Limit Tests |
| Error string flooding (`error(10MB_string)`) | Error strings truncated to `max_output_bytes` | Advanced Escape Tests |
| Integer overflow (Lua number → C int) | `safe_to_u32()`/`safe_to_u64()` guard with NaN/Inf checks | Integer Overflow Tests |
| Embedded null bytes in strings | `luaL_tolstring` returns correct length | String Tests |
| Embedded NUL in source code | Source rejected before `luaL_loadstring` | Boundary Tests |
| Format string attacks | Not applicable (no C format functions exposed) | String Tests |
| `_ENV` manipulation | `load`/`loadstring` nil'd; `setfenv` removed in Lua 5.2+ | Escape Tests |
| `__gc` / `__close` uninterruptible finalizer | `setmetatable` and `getmetatable` removed | PoC Tests |
| Cross-execution global poisoning | Fresh Lua state for every `exec` / `exec_file` | PoC Tests |
| `table.move` C-loop timeout bypass | `table.move` removed | Advanced Escape Tests |
| Lua-pattern C matcher CPU DoS | `string.find/match/gmatch/gsub` removed | Advanced Escape Tests |
| Instruction-limit undercount / delayed check | Hook interval added to counter; checked every callback | Limit Tests |
| `collectgarbage(nil)` full-GC bypass | Strict `count`/`isrunning` allowlist | Advanced Escape Tests |
| `coroutine.wrap` / `coroutine.close` hidden C execution | Both functions removed | Advanced Escape Tests |
| Module-static accounting across instances | Second live instance fails closed | Advanced Escape Tests |
| Concurrent `exec` / `shutdown` state race | Shared recursive lifecycle lock | Advanced Escape Tests |

## Hardware Limits (Default)

| Resource | Limit | Configurable |
|---|---|---|
| Wall-clock time | 5 000 ms | `SandboxLimits::max_time_ms` |
| Lua VM instructions | 20 000 000 | `SandboxLimits::max_instructions` |
| Memory (total allocated) | 16 MiB | `SandboxLimits::max_memory_bytes` |
| Output buffer | 256 KiB | `SandboxLimits::max_output_bytes` |
| Source code size | 512 KiB | `SandboxLimits::max_code_bytes` |
| Call stack depth | 200 frames | `SandboxLimits::max_call_depth` |

---

## Python Execution — Supervised OS Sandbox

CPython import hooks and resource limits are not a security boundary. Python
code can recover dangerous objects through the runtime object graph, so MemDBG
does not rely on an import blocklist.

Therefore:

- Python always runs in a separately supervised process without shell command
  construction on POSIX systems.
- The supervisor enforces source size, wall-clock, CPU, address-space, process,
  file-descriptor, and captured-output limits and kills the complete child
  process group on timeout.
- macOS restrictive execution uses a Seatbelt profile. Plugin files and the
  generated context are readable, while other user data, subprocess creation,
  and network access are denied unless the corresponding policy allows them.
- Platforms without a reviewed OS isolation backend still fail closed for any
  restrictive policy. Explicit unrestricted execution remains available only
  for trusted code.

The next parity step is a reviewed Linux namespace/seccomp backend and a Windows
restricted-token/AppContainer backend. Until then those platforms must not
silently downgrade a restrictive Python policy.

---

## Test Suite

| Test File | Category | Test Count |
|---|---|---|
| `test_sandbox_lua.cpp` | Escape vectors (10 tests) | ✓ |
| `test_sandbox_lua.cpp` | Advanced escapes (6 tests) — pcall, searchers, truncation | ✓ |
| `test_sandbox_lua.cpp` | Resource exhaustion (4 tests) | ✓ |
| `test_sandbox_lua.cpp` | Boundary attacks (3 tests) | ✓ |
| `test_sandbox_lua.cpp` | Integer overflow (2 tests) | ✓ |
| `test_sandbox_lua.cpp` | String attacks (2 tests) | ✓ |
| `test_sandbox_lua.cpp` | Path traversal (2 tests) | ✓ |
| **Total Lua security tests** | **49** | ✓ |
| `test_sandbox_fuzz.cpp` | Safe patterns (26 patterns) | ✓ |
| `test_sandbox_fuzz.cpp` | Dangerous patterns (8 patterns) | ✓ |
| `test_sandbox_fuzz.cpp` | Random strings (200 runs) | ✓ |
| `test_sandbox_fuzz.cpp` | Random loops (100 runs) | ✓ |
| `test_sandbox_limits.cpp` | Limit enforcement (6 tests) | ✓ |
| `test_sandbox_python.cpp` | Python OS isolation and supervision (12 tests on macOS) | ✓ |

Run all tests:
```bash
cd build
cmake --build . --target memdbg_sandbox_lua_test memdbg_sandbox_fuzz_test memdbg_sandbox_limits_test
./bin/memdbg_sandbox_lua_test
./bin/memdbg_sandbox_fuzz_test
./bin/memdbg_sandbox_limits_test
```

## Architecture

```
frontend/src/sandbox/
├── sandbox.hpp              # Aggregator header
├── sandbox_policy.hpp       # Immutable security policy (builder pattern)
├── sandbox_limits.hpp       # Resource limits with safe defaults
├── sandbox_result.hpp       # Bounded, validated result types
├── sandbox_engine.hpp       # Abstract base class + factory functions
├── sandbox_lua.cpp          # Hardened Lua 5.4 sandbox implementation
├── sandbox_python.cpp       # OS-isolated, supervised Python subprocess
├── sandbox_common.cpp       # Shared method implementations
└── sandbox_security.md      # This document

frontend/tests/sandbox/
├── test_sandbox_lua.cpp     # Security test suite (7 categories, 49 tests)
├── test_sandbox_fuzz.cpp    # Fuzzing / stress test suite
└── test_sandbox_limits.cpp  # Resource limit enforcement tests
```

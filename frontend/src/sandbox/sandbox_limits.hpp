/*
 * MemDBG Sandbox — Hardware resource limits enforced during script execution.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * All limits are zero-initialised (meaning "no limit / use default") unless
 * explicitly set. The defaults are safe for untrusted scripts:
 *   time:    5 000 ms
 *   memory:  16 MiB
 *   output:  256 KiB
 *   code:    512 KiB
 *   stack:   200 call-frames
 */

#ifndef MEMDBG_SANDBOX_LIMITS_HPP
#define MEMDBG_SANDBOX_LIMITS_HPP

#include <cstdint>
#include <cstddef>

namespace memdbg::sandbox {

struct SandboxLimits {
  // ── Time ────────────────────────────────────────────────────────────
  int32_t  max_time_ms      = 5000;    ///< wall-clock execution timeout (0 = none)
  int32_t  max_cpu_ms       = 0;       ///< CPU-time timeout (0 = none, not on all platforms)
  int64_t  max_instructions = 20000000;///< Lua VM instructions (0 = none)

  // ── Memory ──────────────────────────────────────────────────────────
  size_t max_memory_bytes = 16U * 1024U * 1024U; ///< Lua allocator hard cap
  size_t max_output_bytes = 256U * 1024U;        ///< captured stdout/stderr cap
  size_t max_code_bytes   = 512U * 1024U;        ///< max source code size accepted

  // ── Stack ───────────────────────────────────────────────────────────
  int max_call_depth = 200;  ///< max nested function calls (0 = none)

  // ── Coroutine ───────────────────────────────────────────────────────
  int64_t max_coroutine_resumes = 100000; ///< max coroutine.resume calls

  // ── Python subprocess (only meaningful for Python sandbox) ─────────
  int32_t python_timeout_sec = 30;    ///< SIGALRM / subprocess timeout
  int32_t python_max_mb      = 64;    ///< RLIMIT_AS / virtual memory limit in MiB
  int32_t python_max_procs   = 1;     ///< RLIMIT_NPROC
  int32_t python_max_files   = 0;     ///< RLIMIT_NOFILE (0 = no file descriptors allowed)

  /// Return the strictest of *this and `other` (min of every field).
  SandboxLimits clamp(const SandboxLimits &other) const;

  /// Production-safe defaults for untrusted Lua scripts.
  static SandboxLimits lua_defaults() { return SandboxLimits{}; }

  /// Production-safe defaults for untrusted Python subprocess.
  static SandboxLimits python_defaults() {
    SandboxLimits l;
    l.max_time_ms = 30000;
    l.python_timeout_sec = 30;
    l.python_max_mb = 64;
    l.python_max_procs = 1;
    l.python_max_files = 0;
    return l;
  }

  bool is_valid() const {
    return max_time_ms >= 0 && max_memory_bytes > 0 &&
           max_output_bytes > 0 && max_code_bytes > 0;
  }
};

} // namespace memdbg::sandbox

#endif /* MEMDBG_SANDBOX_LIMITS_HPP */

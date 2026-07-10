/*
 * MemDBG Sandbox — Safe, bounds-checked result types.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * All result strings are bounded to max_output_bytes and never exceed
 * the configured limit. Error messages are truncated safely.
 */

#ifndef MEMDBG_SANDBOX_RESULT_HPP
#define MEMDBG_SANDBOX_RESULT_HPP

#include "sandbox_limits.hpp"

#include <cstdint>
#include <string>

namespace memdbg::sandbox {

enum class SandboxExitReason : uint8_t {
  kCompleted  = 0,  ///< script finished normally
  kTimeout    = 1,  ///< wall-clock or CPU timeout exceeded
  kMemory     = 2,  ///< memory limit exceeded
  kStackDepth = 3,  ///< max call depth exceeded
  kOutput     = 4,  ///< output buffer limit reached
  kCodeSize   = 5,  ///< source code too large
  kPolicy     = 6,  ///< script attempted a blocked operation
  kError      = 7,  ///< runtime error (syntax, logic, etc.)
  kInternal   = 8,  ///< sandbox internal error (bug)
};

const char *exit_reason_string(SandboxExitReason r);

/// Safe result from a sandbox execution.
struct SandboxResult {
  bool ok = false;
  SandboxExitReason exit_reason = SandboxExitReason::kInternal;
  std::string output;   ///< captured stdout (bounded to limits.max_output_bytes)
  std::string error;    ///< error message (truncated to 1024 bytes)
  int32_t exit_code = -1;
  int64_t instructions_used = 0;  ///< Lua VM instructions consumed
  int32_t elapsed_ms = 0;         ///< wall-clock time spent

  /// Truncate output to `limit` bytes, appending a truncation notice.
  void enforce_output_limit(size_t limit);
};

} // namespace memdbg::sandbox

#endif /* MEMDBG_SANDBOX_RESULT_HPP */

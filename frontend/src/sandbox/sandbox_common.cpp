/*
 * MemDBG Sandbox — Shared implementations (policy, limits, result, factory).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sandbox.hpp"

#include <algorithm>
#include <sstream>

namespace memdbg::sandbox {

// ── SandboxPolicy::describe ──────────────────────────────────────────────

std::string SandboxPolicy::describe() const {
  std::ostringstream oss;
  oss << "SandboxPolicy{fs=" << (allow_filesystem ? "yes" : "no")
      << " subprocess=" << (allow_subprocess ? "yes" : "no")
      << " net=" << (allow_network ? "yes" : "no")
      << " native=" << (allow_native_modules ? "yes" : "no")
      << " ffi=" << (allow_ffi ? "yes" : "no")
      << " safe=" << (is_safe() ? "yes" : "NO")
      << "}";
  return oss.str();
}

// ── SandboxLimits::clamp ─────────────────────────────────────────────────

// Helper: min treating 0 as "unbounded" (infinity)
static inline int32_t safe_min32(int32_t a, int32_t b) {
  if (a == 0) return b;
  if (b == 0) return a;
  return a < b ? a : b;
}
static inline int64_t safe_min64(int64_t a, int64_t b) {
  if (a == 0) return b;
  if (b == 0) return a;
  return a < b ? a : b;
}
static inline size_t s_min(size_t a, size_t b) {
  if (a == 0) return b;
  if (b == 0) return a;
  return a < b ? a : b;
}
static inline int safe_min_int(int a, int b) {
  if (a == 0) return b;
  if (b == 0) return a;
  return a < b ? a : b;
}

SandboxLimits SandboxLimits::clamp(const SandboxLimits &other) const {
  SandboxLimits result;
  result.max_time_ms = safe_min32(max_time_ms, other.max_time_ms);
  result.max_cpu_ms = safe_min32(max_cpu_ms, other.max_cpu_ms);
  result.max_instructions = safe_min64(max_instructions, other.max_instructions);
  result.max_memory_bytes = s_min(max_memory_bytes, other.max_memory_bytes);
  result.max_output_bytes = s_min(max_output_bytes, other.max_output_bytes);
  result.max_code_bytes = s_min(max_code_bytes, other.max_code_bytes);
  result.max_call_depth = safe_min_int(max_call_depth, other.max_call_depth);
  result.max_coroutine_resumes = safe_min64(max_coroutine_resumes, other.max_coroutine_resumes);
  result.python_timeout_sec = safe_min32(python_timeout_sec, other.python_timeout_sec);
  result.python_max_mb = safe_min32(python_max_mb, other.python_max_mb);
  result.python_max_procs = safe_min32(python_max_procs, other.python_max_procs);
  result.python_max_files = safe_min32(python_max_files, other.python_max_files);
  return result;
}

// ── exit_reason_string ───────────────────────────────────────────────────

const char *exit_reason_string(SandboxExitReason r) {
  switch (r) {
  case SandboxExitReason::kCompleted:  return "completed";
  case SandboxExitReason::kTimeout:    return "timeout";
  case SandboxExitReason::kMemory:     return "memory_limit";
  case SandboxExitReason::kStackDepth: return "stack_depth";
  case SandboxExitReason::kOutput:     return "output_limit";
  case SandboxExitReason::kCodeSize:   return "code_size";
  case SandboxExitReason::kPolicy:     return "policy_violation";
  case SandboxExitReason::kError:      return "runtime_error";
  case SandboxExitReason::kInternal:   return "internal_error";
  }
  return "unknown";
}

// ── SandboxResult::enforce_output_limit ──────────────────────────────────

void SandboxResult::enforce_output_limit(size_t limit) {
  if (output.size() > limit) {
    output.resize(limit);
    output += "\n[Sandbox] Output truncated.\n";
    exit_reason = SandboxExitReason::kOutput;
  }
}

} // namespace memdbg::sandbox

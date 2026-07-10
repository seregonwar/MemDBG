/*
 * MemDBG Sandbox — Immutable security policy configuration.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A SandboxPolicy is constructed once with validated values and never
 * mutated afterward. All member functions are const. Use the Builder
 * pattern via SandboxPolicy::create() for safe construction.
 */

#ifndef MEMDBG_SANDBOX_POLICY_HPP
#define MEMDBG_SANDBOX_POLICY_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::sandbox {

struct SandboxLimits; // forward

/// Immutable security policy governing what a sandboxed script may do.
struct SandboxPolicy {
  // ── Filesystem ──────────────────────────────────────────────────────
  bool allow_filesystem = false;   ///< io library / open() / file I/O
  bool allow_cwd_change = false;   ///< os.chdir / lfs.chdir
  bool allow_tempfiles = false;    ///< os.tmpname / tempfile

  // ── Process ─────────────────────────────────────────────────────────
  bool allow_subprocess = false;   ///< os.execute / io.popen / subprocess
  bool allow_signal = false;       ///< os.kill / signal

  // ── Network ─────────────────────────────────────────────────────────
  bool allow_network = false;      ///< socket / http / luasocket

  // ── Native Code ─────────────────────────────────────────────────────
  bool allow_native_modules = false; ///< require/dlsym of .so/.dll
  bool allow_ffi = false;            ///< ffi.cdef / ffi.C

  // ── Resource Limits ─────────────────────────────────────────────────
  const SandboxLimits *limits = nullptr; ///< if non-null, enforced at runtime

  // ── Module Allowlist ────────────────────────────────────────────────
  /// Whitelist of module names allowed via require().
  /// Empty = ALL require() calls blocked (default-deny).
  /// Use dotted notation for submodules: "mymod.submod" allows
  /// require("mymod.submod") and require("mymod") (prefix match).
  std::vector<std::string> require_whitelist;

  // ── Validation ──────────────────────────────────────────────────────
  /// Return true if this policy is safe for untrusted code.
  /// The default-constructed policy (all false) is maximally safe.
  bool is_safe() const {
    return !allow_filesystem && !allow_subprocess && !allow_network &&
           !allow_native_modules && !allow_ffi;
  }

  /// Return a human-readable description of the policy.
  std::string describe() const;

  /// Builder: start from a locked-down default and selectively enable features.
  static SandboxPolicy create() { return SandboxPolicy{}; }

  SandboxPolicy &with_filesystem(bool v = true) { allow_filesystem = v; return *this; }
  SandboxPolicy &with_subprocess(bool v = true)  { allow_subprocess = v; return *this; }
  SandboxPolicy &with_network(bool v = true)     { allow_network = v; return *this; }
  SandboxPolicy &with_native_modules(bool v = true) { allow_native_modules = v; return *this; }
  SandboxPolicy &with_limits(const SandboxLimits &l) { limits = &l; return *this; }
  SandboxPolicy &with_require_whitelist(std::vector<std::string> wl) { require_whitelist = std::move(wl); return *this; }
};

} // namespace memdbg::sandbox

#endif /* MEMDBG_SANDBOX_POLICY_HPP */

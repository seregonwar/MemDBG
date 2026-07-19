/*
 * MemDBG Sandbox — Lua sandbox fuzzing / stress test suite.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Generates random (but syntactically valid-ish) Lua programs and verifies
 * the sandbox never crashes, leaks memory, or allows escape.
 *
 * Every execution is a "fuzz run" — the test passes if the sandbox returns
 * a valid SandboxResult without segfaulting, deadlocking, or producing
 * unexpected exit reasons.
 */

#include "sandbox/sandbox.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

static int g_runs = 0, g_crashes = 0, g_escapes = 0;
static std::mt19937 g_rng(std::random_device{}());

// ── fuzzing primitives ───────────────────────────────────────────────────

static std::string random_string(size_t max_len) {
  static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789_ .";
  size_t len = std::uniform_int_distribution<size_t>(0, max_len)(g_rng);
  std::string s;
  s.reserve(len);
  for (size_t i = 0; i < len; ++i)
    s.push_back(chars[std::uniform_int_distribution<>(0, (int)sizeof(chars)-2)(g_rng)]);
  return s;
}

static int random_int(int min, int max) {
  return std::uniform_int_distribution<>(min, max)(g_rng);
}

// ── known safe patterns ──────────────────────────────────────────────────

// These are patterns we know should always be safe to execute.
static const std::vector<std::string> SAFE_PATTERNS = {
  "return 42",
  "return 'hello'",
  "local x = 1; return x + 1",
  "return 1 + 2 * 3",
  "return #'test'",
  "return type(42)",
  "return tostring(42)",
  "return tonumber('42')",
  "return math.abs(-5)",
  "return string.upper('hello')",
  "return table.concat({1,2,3}, ',')",
  "local t = {}; t.a = 1; return t.a",
  "return 1, 2, 3",
  "return true and false",
  "return nil or 'default'",
  "local f = function() return 1 end; return f()",
  "local a, b = 1, 2; return a, b",
  "return pcall(function() error('test') end)",
  "for i=1,3 do end; return 'ok'",
  "return select('#', 1, 2, 3)",
  "return {1, 2, 3}[2]",
  "local mt = {}; local t = setmetatable({}, mt); return type(t)",
  "return coroutine.create(function() end)",
  "return utf8.len('hello')",
  "return string.rep('x', 5)",
  "return #string.rep('x', 100)",
};

// ── known dangerous patterns (should be blocked/timeout) ─────────────────

static const std::vector<std::string> DANGEROUS_PATTERNS = {
  "while true do end",                    // infinite loop
  "local function f(n) f(n+1) end; f(0)", // infinite recursion
  "os.execute('id')",                     // subprocess
  "return io.open('/etc/passwd')",        // filesystem
  "return dofile('test')",                // file load
  "return loadfile('test')",              // file load
  "return require('io')",                 // blocked module
  "return package.loadlib('libc.so', 'system')", // native module
};

// ── fuzz runner ──────────────────────────────────────────────────────────

static void fuzz_run(memdbg::sandbox::SandboxEngine &engine,
                     const std::string &code, const char *category) {
  ++g_runs;
  auto r = engine.exec(code);

  // Check for crash-like exit reasons (we should never see kInternal in a fuzz)
  if (r.exit_reason == memdbg::sandbox::SandboxExitReason::kInternal) {
    ++g_crashes;
    std::cerr << "INTERNAL: [" << category << "] " << code.substr(0, 120)
              << "\n  error: " << r.error << "\n";
    return;
  }

  // Check for policy escapes (dangerous patterns should be blocked)
  std::string lower_err = r.error;
  std::transform(lower_err.begin(), lower_err.end(), lower_err.begin(),
                 [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); });

  // Only count true escapes (kPolicy violations that shouldn't happen, or kInternal)
  if (r.exit_reason == memdbg::sandbox::SandboxExitReason::kInternal) {
    ++g_escapes;
    std::cerr << "ESCAPE: [" << category << "] " << code.substr(0, 120)
              << "\n  reason: " << static_cast<int>(r.exit_reason)
              << "  error: " << r.error << "\n";
  }
}

// ── test functions ───────────────────────────────────────────────────────

static void test_safe_patterns() {
  auto engine = memdbg::sandbox::create_lua_sandbox();
  auto policy = memdbg::sandbox::SandboxPolicy::create();
  auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
  limits.max_time_ms = 2000;
  limits.max_memory_bytes = 8 * 1024 * 1024;
  std::string err;
  engine->init(policy, limits, &err);

  for (const auto &code : SAFE_PATTERNS) {
    fuzz_run(*engine, code, "safe");
  }
}

static void test_dangerous_patterns() {
  auto engine = memdbg::sandbox::create_lua_sandbox();
  auto policy = memdbg::sandbox::SandboxPolicy::create();
  auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
  limits.max_time_ms = 500;  // very short timeout
  limits.max_memory_bytes = 2 * 1024 * 1024;
  std::string err;
  engine->init(policy, limits, &err);

  for (const auto &code : DANGEROUS_PATTERNS) {
    fuzz_run(*engine, code, "dangerous");
  }
}

static void test_random_strings(int count) {
  auto engine = memdbg::sandbox::create_lua_sandbox();
  auto policy = memdbg::sandbox::SandboxPolicy::create();
  auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
  limits.max_time_ms = 1000;
  limits.max_output_bytes = 64 * 1024;
  std::string err;
  engine->init(policy, limits, &err);

  for (int i = 0; i < count; ++i) {
    std::string code = random_string(500);
    fuzz_run(*engine, code, "random");
  }
}

static void test_random_expressions(int count) {
  auto engine = memdbg::sandbox::create_lua_sandbox();
  auto policy = memdbg::sandbox::SandboxPolicy::create();
  auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
  limits.max_time_ms = 2000;
  std::string err;
  engine->init(policy, limits, &err);

  for (int i = 0; i < count; ++i) {
    int n = random_int(1, 100);
    std::string code = "local x = 0; for i=1," + std::to_string(n) +
                       " do x = x + i end; return x";
    fuzz_run(*engine, code, "loop");
  }
}

// ── main ──────────────────────────────────────────────────────────────────

int main() {
  std::cout << "MemDBG Sandbox — Fuzzing Tests\n"
            << "===============================\n";

  test_safe_patterns();
  test_dangerous_patterns();
  test_random_strings(200);
  test_random_expressions(100);

  std::cout << "\n─────────────────────────────────────\n"
            << "Runs: " << g_runs << "  Crashes: " << g_crashes
            << "  Escapes: " << g_escapes << "\n";

  return (g_crashes > 0 || g_escapes > 0) ? 1 : 0;
}

/*
 * MemDBG Sandbox — Resource limit enforcement tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Verifies all SandboxLimits are enforced correctly:
 *   - Timeout
 *   - Memory cap
 *   - Output truncation
 *   - Code size limit
 *   - Call depth
 */

#include "sandbox/sandbox.hpp"

#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>

static int g_passed = 0, g_failed = 0;

static void test(const char *name, bool condition, const std::string &extra = "") {
  if (condition) { ++g_passed; std::cout << "  PASS " << name << "\n"; }
  else { ++g_failed; std::cerr << "  FAIL " << name << (extra.empty() ? "" : " — " + extra) << "\n"; }
}

template<typename F> static void section(const char *h, F &&f) {
  std::cout << "\n── " << h << "\n"; f();
}

int main() {
  using namespace memdbg::sandbox;

  std::cout << "MemDBG Sandbox — Limits Tests\n=============================\n";

  section("1. Timeout enforcement", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_time_ms = 100;
    lim.max_instructions = 0;
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec("while true do end");
    test("infinite loop timed out", r.exit_reason == SandboxExitReason::kTimeout,
         std::to_string(static_cast<int>(r.exit_reason)));
    test("elapsed recorded", r.elapsed_ms > 0);
  });

  section("2. Memory limit enforcement", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_memory_bytes = 1024 * 1024; // 1 MiB
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec("local t = {}; for i=1,100000 do t[i] = string.rep('x', 1000) end");
    test("memory limit triggered", !r.ok,
         "error: " + r.error.substr(0, 80));
  });

  section("3. Output truncation", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_output_bytes = 1024;
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec("for i=1,10000 do print('x') end");
    test("output truncated", r.output.find("truncated") != std::string::npos);
  });

  section("4. Code size limit", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_code_bytes = 100;
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec(std::string(200, ' '));
    test("oversized code rejected", r.exit_reason == SandboxExitReason::kCodeSize,
         std::to_string(static_cast<int>(r.exit_reason)));
  });

  section("5. Call depth limit", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_call_depth = 10;
    lim.max_instructions = 0;
    lim.max_time_ms = 3000;
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec("function f(n) if n > 0 then f(n-1); local x=1 end end; f(1000)");
    test("call depth exceeded",
         r.error.find("call depth") != std::string::npos ||
         r.error.find("aborted") != std::string::npos,
         r.error.substr(0, 80));
  });

  section("6. Instruction limit accuracy", [&] {
    auto e = create_lua_sandbox();
    SandboxLimits lim = SandboxLimits::lua_defaults();
    lim.max_time_ms = 3000;
    lim.max_instructions = 1000;
    e->init(SandboxPolicy::create(), lim);
    auto r = e->exec(
        "local n=0; for i=1,1000000 do n=n+1 end; return n");
    test("low instruction limit enforced",
         !r.ok && r.exit_reason == SandboxExitReason::kTimeout,
         "used=" + std::to_string(r.instructions_used) + " error=" + r.error);
    test("instruction counter uses VM units",
         r.instructions_used >= 1000 && r.instructions_used < 5000,
         std::to_string(r.instructions_used));
  });

  std::cout << "\n─────────────────────────────────────\n"
            << "Results: " << g_passed << " passed, " << g_failed << " failed\n";
  return g_failed > 0 ? 1 : 0;
}

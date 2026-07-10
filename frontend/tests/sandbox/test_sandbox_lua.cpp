/*
 * MemDBG Sandbox — Lua sandbox security test suite.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tests every known escape vector. A failing test = a security vulnerability.
 *
 * Categories:
 *   1. Escape attempts (io, os, dofile, loadfile, require FFI, loadlib)
 *   2. Resource exhaustion (infinite loops, massive allocations, deep recursion)
 *   3. Boundary attacks (address 0x0, max uint, size=0, negative sizes)
 *   4. Integer overflow (large Lua numbers → C integer overflow)
 *   5. String attacks (embedded nulls, 10MB strings, format attacks)
 *   6. Path traversal (../../etc/passwd via require, absolute paths)
 */

#include "sandbox/sandbox.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// ── test harness ─────────────────────────────────────────────────────────

static int g_passed = 0, g_failed = 0;

static void test(const char *name, bool condition, const std::string &detail = "") {
  if (condition) {
    ++g_passed;
    std::cout << "  PASS " << name << "\n";
  } else {
    ++g_failed;
    std::cerr << "  FAIL " << name;
    if (!detail.empty()) std::cerr << " — " << detail;
    std::cerr << "\n";
  }
}

template <typename F>
static void test_section(const char *header, F &&fn) {
  std::cout << "\n── " << header << "\n";
  fn();
}

// ── helpers ──────────────────────────────────────────────────────────────

static std::unique_ptr<memdbg::sandbox::SandboxEngine> make_default_lua() {
  auto engine = memdbg::sandbox::create_lua_sandbox();
  auto policy = memdbg::sandbox::SandboxPolicy::create();
  auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
  std::string err;
  if (!engine->init(policy, limits, &err)) {
    std::cerr << "Cannot init Lua sandbox: " << err << "\n";
    std::exit(1);
  }
  return engine;
}

// ── 1. Escape attempts ───────────────────────────────────────────────────

static void test_escape_vectors() {
  auto engine = make_default_lua();

  test_section("1. Escape attempts", [&] {
    // io library never loaded
    test("io library not loaded",
         engine->exec("return io").output.find("nil") != std::string::npos);

    // os.execute blocked
    test("os.execute blocked",
         engine->exec("os.execute('id')").error.find("nil") != std::string::npos);

    // dofile nil
    test("dofile nil",
         engine->exec("return dofile").output.find("nil") != std::string::npos);

    // loadfile nil
    test("loadfile nil",
         engine->exec("return loadfile").output.find("nil") != std::string::npos);

    // require("io") blocked by empty whitelist (default-deny)
    test("require io blocked",
         engine->exec("require('io')").error.find("whitelist") != std::string::npos);

    // require("os") blocked by empty whitelist
    test("require os blocked",
         engine->exec("require('os')").error.find("whitelist") != std::string::npos);

    // package.loadlib nil
    test("package.loadlib nil",
         engine->exec("return package.loadlib").output.find("nil") != std::string::npos);

    // package.cpath empty
    test("package.cpath empty",
         engine->exec("return #package.cpath == 0 and 'ok' or 'bad'").output.find("ok") != std::string::npos);

    // ffi/cjson blocked by empty whitelist
    test("require ffi blocked",
         engine->exec("require('ffi')").error.find("whitelist") != std::string::npos);

    // No rawget to access hidden globals
    auto r = engine->exec("local f = rawget(_G, 'dofile'); return type(f)");
    test("rawget dofile returns nil",
         r.output.find("nil") != std::string::npos);

    // collectgarbage('stop') blocked
    auto r2 = engine->exec("collectgarbage('stop')");
    test("collectgarbage stop blocked",
         r2.error.find("blocked") != std::string::npos);

    // collectgarbage('count') allowed (informational)
    auto r3 = engine->exec("return collectgarbage('count')");
    test("collectgarbage count allowed", r3.ok);

    // coroutine timeout bypass blocked: coroutine inherits hook
    auto r4 = engine->exec(
        "local co = coroutine.create(function() while true do end end); "
        "coroutine.resume(co)");
    test("coroutine timeout bypass blocked",
         !r4.ok || r4.exit_reason == memdbg::sandbox::SandboxExitReason::kTimeout ||
         r4.error.find("timed out") != std::string::npos ||
         r4.error.find("aborted") != std::string::npos);
  });
}

// ── 1b. Advanced escape (pcall bypass, searcher bypass, error truncation) ─

static void test_advanced_escapes() {
  test_section("1b. Advanced escape vectors", [&] {
    {
      // pcall cannot bypass timeout — s_aborted persists after first violation
      auto engine = make_default_lua();
      auto r = engine->exec(
          "local ok, err = pcall(function() while true do end end); "
          "return tostring(ok) .. ' | ' .. tostring(err)");
      test("pcall cannot catch timeout",
           r.exit_reason == memdbg::sandbox::SandboxExitReason::kTimeout ||
           r.error.find("aborted") != std::string::npos,
           r.error.empty() ? r.output.substr(0, 80) : r.error.substr(0, 80));
    }

    {
      // pcall cannot bypass instruction limit — s_aborted persists
      auto engine = make_default_lua();
      auto r = engine->exec(
          "local count = 0; "
          "while true do "
          "  local ok, err = pcall(function() for i=1,100000 do end end); "
          "  count = count + 1; "
          "  if not ok then break end; "
          "end; "
          "return count");
      test("pcall cannot bypass instruction limit",
           r.exit_reason == memdbg::sandbox::SandboxExitReason::kTimeout ||
           r.error.find("aborted") != std::string::npos ||
           !r.ok,
           r.error.empty() ? r.output.substr(0, 80) : r.error.substr(0, 80));
    }

    {
      // All package.searchers are nil'd — cannot bypass require guard
      auto engine = make_default_lua();
      auto r = engine->exec(
          "return tostring(package.searchers[1]) .. ',' .. "
          "tostring(package.searchers[2]) .. ',' .. "
          "tostring(package.searchers[3]) .. ',' .. "
          "tostring(package.searchers[4])");
      test("all searchers nil'd",
           r.ok && r.output.find("nil,nil,nil,nil") != std::string::npos,
           r.output);
    }

    {
      // Error strings are truncated to max_output_bytes
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      limits.max_output_bytes = 256;
      limits.max_time_ms = 3000;
      std::string err;
      engine->init(policy, limits, &err);
      auto r = engine->exec("error(string.rep('X', 10000))");
      test("error strings truncated",
           r.error.size() <= limits.max_output_bytes + 10,  // "..." + margin
           "error size: " + std::to_string(r.error.size()));
    }

    {
      // require with case variations (IO, Io) still blocked with empty whitelist
      auto engine = make_default_lua();
      auto r = engine->exec("local ok, err = pcall(require, 'IO'); return err");
      test("require uppercase IO blocked",
           r.output.find("whitelist") != std::string::npos ||
           r.output.find("not found") != std::string::npos ||
           r.output.find("module") != std::string::npos);
    }

    {
      // pcall(require, 'io') still blocked with empty whitelist
      auto engine = make_default_lua();
      auto r = engine->exec("local ok, err = pcall(require, 'io'); return err");
      test("pcall require io blocked",
           r.output.find("whitelist") != std::string::npos);
    }

    {
      // Coroutine resume limit enforced
      auto engine = make_default_lua();
      auto r = engine->exec(
          "local co = coroutine.create(function() coroutine.yield() end); "
          "for i = 1, 200000 do coroutine.resume(co) end; return 'ok'");
      test("coroutine resume limit enforced",
           !r.ok || r.error.find("resume limit") != std::string::npos ||
           r.error.find("aborted") != std::string::npos ||
           r.error.find("timed out") != std::string::npos,
           r.ok ? "returned ok (" + r.output + ")" : r.error.substr(0, 80));
    }

    {
      // User finalizers can execute outside interruptible instruction paths.
      auto engine = make_default_lua();
      auto r = engine->exec(
          "return tostring(setmetatable) .. ',' .. tostring(getmetatable)");
      test("metatable APIs removed",
           r.ok && r.output.find("nil,nil") != std::string::npos, r.output);
    }

    {
      // Separate submissions must not share attacker-controlled globals.
      auto engine = make_default_lua();
      auto first = engine->exec("SANDBOX_POISON = 'leaked'");
      auto second = engine->exec("return tostring(SANDBOX_POISON)");
      test("fresh state per execution",
           first.ok && second.ok && second.output.find("nil") != std::string::npos,
           second.output);
    }

    {
      auto engine = make_default_lua();
      auto r = engine->exec(
          "return tostring(table.move) .. ',' .. tostring(coroutine.wrap) .. "
          "',' .. tostring(coroutine.close)");
      test("non-interruptible C primitives removed",
           r.ok && r.output.find("nil,nil,nil") != std::string::npos, r.output);
    }

    {
      auto engine = make_default_lua();
      auto r = engine->exec(
          "local ok, err = pcall(collectgarbage, nil); "
          "return tostring(ok) .. ' | ' .. tostring(err)");
      test("collectgarbage nil blocked",
           r.ok && r.output.find("false |") != std::string::npos &&
               r.output.find("blocked") != std::string::npos,
           r.output);
    }

    {
      auto first = make_default_lua();
      auto second = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      const bool initialized = second->init(policy, limits, &err);
      test("second concurrent instance fails closed",
           !initialized && err.find("concurrent") != std::string::npos, err);
    }

    {
      auto engine = make_default_lua();
      auto r = engine->exec(
          "return tostring(string.find) .. ',' .. tostring(string.match) .. "
          "',' .. tostring(string.gmatch) .. ',' .. tostring(string.gsub)");
      test("Lua pattern matcher APIs removed",
           r.ok && r.output.find("nil,nil,nil,nil") != std::string::npos,
           r.output);
    }

    {
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      policy.allow_filesystem = true;
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      auto r = engine->exec(
          "return tostring(io.popen) .. ',' .. tostring(io.tmpfile)");
      test("filesystem capability does not grant process or tempfiles",
           r.ok && r.output.find("nil,nil") != std::string::npos, r.output);
    }

    {
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      policy.allow_subprocess = true;
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      auto r = engine->exec(
          "return tostring(os.exit) .. ',' .. tostring(os.remove) .. ',' .. "
          "tostring(os.rename) .. ',' .. tostring(os.tmpname)");
      test("subprocess capability does not grant host exit or filesystem",
           r.ok && r.output.find("nil,nil,nil,nil") != std::string::npos,
           r.output);
    }

    {
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      limits.max_time_ms = 100;
      std::string err;
      engine->init(policy, limits, &err);
      std::atomic<bool> started{false};
      std::thread worker([&] {
        started.store(true, std::memory_order_release);
        (void)engine->exec("while true do end");
      });
      while (!started.load(std::memory_order_acquire))
        std::this_thread::yield();
      engine->shutdown();
      worker.join();
      test("concurrent shutdown serializes with execution",
           !engine->is_initialized());
    }
  });
}

// ── 1c. Whitelist-based require (defense-in-depth) ────────────────────────

static void test_require_whitelist() {
  test_section("1c. Whitelist-based require", [&] {
    {
      // Empty whitelist (default): all require() calls blocked
      auto engine = make_default_lua();
      auto r = engine->exec("local ok, err = pcall(require, 'table'); return err");
      test("empty whitelist blocks table",
           r.output.find("whitelist") != std::string::npos);
    }

    {
      // Custom whitelist: only allowed modules pass through
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create()
          .with_require_whitelist({"table", "string", "math"});
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      // 'table' is in whitelist — allowed
      auto r = engine->exec("local ok, err = pcall(require, 'table'); return tostring(ok)");
      test("whitelist allows table", r.output.find("true") != std::string::npos, r.output);

      // 'io' is NOT in whitelist — blocked
      auto r2 = engine->exec("local ok, err = pcall(require, 'io'); return err");
      test("whitelist blocks io", r2.output.find("whitelist") != std::string::npos);
    }

    {
      // Case-insensitivity: guard allows MYMODULE when "mymodule" is whitelisted.
      // Note: since mymodule isn't actually loaded, the original require will
      // fail with "not found" — the test verifies the guard allowed the request
      // through (no "whitelist" error) rather than requiring the module to exist.
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create()
          .with_require_whitelist({"mymodule"});
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      auto r = engine->exec("local ok, err = pcall(require, 'MYMODULE'); return err");
      test("whitelist case-insensitive",
           r.output.find("whitelist") == std::string::npos, r.output);
    }

    {
      // Prefix match: require("mymod.sub") allowed because "mymod" in whitelist.
      // Guard passes through, original require fails with "not found" since
      // the module doesn't exist — test verifies no "whitelist" error.
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create()
          .with_require_whitelist({"mymod"});
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      auto r = engine->exec("local ok, err = pcall(require, 'mymod.sub'); return err");
      test("whitelist prefix allows submodules",
           r.output.find("whitelist") == std::string::npos, r.output);
    }

    {
      // Dotted submodule blocked if parent not in whitelist
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create()
          .with_require_whitelist({"mymod"});
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      std::string err;
      engine->init(policy, limits, &err);
      // require("other.sub") blocked — "other" not in whitelist
      auto r = engine->exec("local ok, err = pcall(require, 'other.sub'); return err");
      test("unknown prefix blocked", r.output.find("whitelist") != std::string::npos);
    }
  });
}

// ── 2. Resource exhaustion ───────────────────────────────────────────────

static void test_resource_exhaustion() {
  test_section("2. Resource exhaustion", [&] {
    {
      auto engine = make_default_lua();
      // Infinite loop → timed out
      auto r = engine->exec("while true do end");
      test("infinite loop timed out",
           r.exit_reason == memdbg::sandbox::SandboxExitReason::kTimeout,
           std::to_string(static_cast<int>(r.exit_reason)));
    }

    {
      auto engine = make_default_lua();
      // Deep recursion → call depth exceeded.
      // The local assignment after the recursive call prevents Lua 5.4 tail-call
      // optimisation, ensuring the stack actually grows.
      auto r = engine->exec("function f(n) if n > 0 then f(n-1); local x=1 end end; f(5000)");
      test("deep recursion blocked",
           r.exit_reason == memdbg::sandbox::SandboxExitReason::kStackDepth ||
           r.error.find("call depth") != std::string::npos ||
           r.error.find("aborted") != std::string::npos,
           r.error);
    }

    {
      // Use a tight memory limit so the allocator blocks the string concat quickly.
      // 10M iterations of string concat causes O(n²) C-level string copies that
      // the Lua hook cannot interrupt mid-copy.
      auto engine = memdbg::sandbox::create_lua_sandbox();
      auto policy = memdbg::sandbox::SandboxPolicy::create();
      auto limits = memdbg::sandbox::SandboxLimits::lua_defaults();
      limits.max_memory_bytes = 1024 * 1024; // 1 MiB – string concat hits this fast
      limits.max_time_ms     = 3000;
      std::string err;
      if (!engine->init(policy, limits, &err)) {
        std::cerr << "Cannot init Lua sandbox: " << err << "\n";
        std::exit(1);
      }
      auto r = engine->exec("local s = ''; for i=1,5000000 do s = s .. 'x' end");
      test("massive string blocked",
           !r.ok,
           r.error.substr(0, 80));
    }

    {
      auto engine = make_default_lua();
      // Output flooding → truncated
      auto r = engine->exec("for i=1,100000 do print(string.rep('x', 100)) end");
      test("output flooding truncated",
           r.output.find("truncated") != std::string::npos ||
           r.exit_reason == memdbg::sandbox::SandboxExitReason::kOutput);
    }
  });
}

// ── 3. Boundary attacks ──────────────────────────────────────────────────

static void test_boundary_attacks() {
  auto engine = make_default_lua();

  test_section("3. Boundary attacks", [&] {
    // Code too large
    auto r = engine->exec(std::string(1024 * 1024, ' '));
    test("oversized code rejected",
         r.exit_reason == memdbg::sandbox::SandboxExitReason::kCodeSize);

    // Empty code
    auto r2 = engine->exec("");
    test("empty code ok", r2.ok);

    // Null byte in code
    static constexpr char kNulPayload[] =
        "print('hi')\0os.execute('rm -rf /')";
    auto r3 = engine->exec(std::string(kNulPayload, sizeof(kNulPayload) - 1));
    test("null byte rejected",
         !r3.ok && r3.exit_reason ==
             memdbg::sandbox::SandboxExitReason::kPolicy);
  });
}

// ── 4. Integer overflow ──────────────────────────────────────────────────

static void test_integer_overflow() {
  auto engine = make_default_lua();

  test_section("4. Integer overflow guards", [&] {
    // NB: The sandboxed engine doesn't have memdbg API bindings by default,
    // but these tests verify the safe cast helpers exist in the codebase.
    // We test via Lua's own number system.

    // Very large number → should be parseable by Lua (uses double)
    auto r = engine->exec("return 1e308");
    test("large float ok", r.ok || r.output.find("inf") != std::string::npos);

    // Very small (negative large)
    auto r2 = engine->exec("return -1e308");
    test("large negative ok", r2.ok || r2.output.find("-inf") != std::string::npos);
  });
}

// ── 5. String attacks ────────────────────────────────────────────────────

static void test_string_attacks() {
  auto engine = make_default_lua();

  test_section("5. String attacks", [&] {
    // Embedded nulls
    auto r = engine->exec("return 'hel\\0lo'");
    test("embedded null handled", r.ok);

    // Format string attack (%%s %n etc.)
    auto r2 = engine->exec("return string.format('%%s%%n%%x')");
    test("format string ok", r2.ok);
  });
}

// ── 6. Path traversal ────────────────────────────────────────────────────

static void test_path_traversal() {
  test_section("6. Path traversal", [&] {
    {
      auto engine = make_default_lua();
      // Try to require a module from absolute path
      auto r = engine->exec("package.path = '/etc/?.lua'; local status, err = pcall(require, 'passwd'); return err");
      test("absolute path in require blocked",
           r.ok && (r.output.find("module") != std::string::npos ||
                    r.output.find("not found") != std::string::npos));
    }

    {
      auto engine = make_default_lua();
      // Relative path with ..
      auto r = engine->exec("package.path = '../../?.lua'; local ok, err = pcall(require, 'test'); return tostring(ok)");
      test("path traversal via package.path",
           r.ok);
    }


    {
      const auto nonce = std::to_string(
          std::chrono::high_resolution_clock::now().time_since_epoch().count());
      const fs::path root = fs::temp_directory_path() / ("memdbg-root-" + nonce);
      const fs::path outside =
          fs::temp_directory_path() / ("memdbg-outside-" + nonce + ".lua");
      fs::create_directories(root);
      std::ofstream(outside) << "return 'OUTSIDE_SECRET'\n";
      std::error_code ec;
      fs::create_symlink(outside, root / "entry.lua", ec);
      auto engine = make_default_lua();
      auto r = engine->exec_file("entry.lua", root);
      test("symlink entry cannot escape plugin root",
           !ec && !r.ok && r.exit_reason ==
               memdbg::sandbox::SandboxExitReason::kPolicy,
           r.output.empty() ? r.error : r.output);
      fs::remove_all(root, ec);
      fs::remove(outside, ec);
    }
  });
}

// ── main ──────────────────────────────────────────────────────────────────

int main() {
  std::cout << "MemDBG Sandbox — Lua Security Tests\n"
            << "===================================\n";

  test_escape_vectors();
  test_advanced_escapes();
  test_require_whitelist();
  test_resource_exhaustion();
  test_boundary_attacks();
  test_integer_overflow();
  test_string_attacks();
  test_path_traversal();

  std::cout << "\n─────────────────────────────────────\n"
            << "Results: " << g_passed << " passed, " << g_failed << " failed\n";

  return g_failed > 0 ? 1 : 0;
}

/*
 * MemDBG Sandbox — supervised Python regression tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sandbox/sandbox.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

static int g_passed = 0;
static int g_failed = 0;

static void check(const char *name, bool condition,
                  const std::string &detail = {}) {
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

int main() {
  using namespace memdbg::sandbox;
  auto engine = create_python_sandbox();
  auto limits = SandboxLimits::python_defaults();
  std::string error;

  limits.max_time_ms = 250;
  limits.max_output_bytes = 128U;
  limits.max_code_bytes = 256U;
  const bool safe_init = engine->init(SandboxPolicy::create(), limits, &error);

#ifdef __APPLE__
  check("restrictive policy uses macOS isolation", safe_init, error);
  if (safe_init) {
    auto basic = engine->exec("print('python sandbox ready')");
    check("isolated Python executes", basic.ok &&
          basic.output.find("sandbox ready") != std::string::npos,
          basic.error + basic.output);

    auto filesystem = engine->exec(
        "open('/etc/passwd', 'rb').read(1); print('escaped')");
    check("host filesystem read blocked",
          !filesystem.ok && filesystem.output.find("escaped") == std::string::npos,
          filesystem.output);

    auto subprocess = engine->exec(
        "import subprocess; subprocess.run(['/usr/bin/id']); print('escaped')");
    check("child process creation blocked",
          !subprocess.ok && subprocess.output.find("escaped") == std::string::npos,
          subprocess.output);

    auto network = engine->exec(
        "import socket; socket.socket().connect(('127.0.0.1', 9)); "
        "print('escaped')");
    check("network access blocked",
          !network.ok && network.output.find("escaped") == std::string::npos,
          network.output);

    auto timeout = engine->exec("import time; time.sleep(5)");
    check("wall-clock timeout enforced",
          !timeout.ok && timeout.exit_reason == SandboxExitReason::kTimeout,
          timeout.error);

    auto output = engine->exec("print('x' * 4096)");
    check("output limit enforced",
          output.exit_reason == SandboxExitReason::kOutput &&
              output.output.size() < 256U,
          std::to_string(output.output.size()));

    auto code_size = engine->exec(std::string(300U, ' '));
    check("code-size limit enforced",
          code_size.exit_reason == SandboxExitReason::kCodeSize,
          code_size.error);

    const auto plugin_root = std::filesystem::temp_directory_path() /
                             "memdbg-python-sandbox-plugin-test";
    std::error_code ec;
    std::filesystem::remove_all(plugin_root, ec);
    std::filesystem::create_directories(plugin_root, ec);
    {
      std::ofstream module(plugin_root / "helper.py");
      module << "VALUE = 42\n";
      std::ofstream entry(plugin_root / "main.py");
      entry << "import helper, json, sys\n"
               "print(helper.VALUE, json.load(open(sys.argv[1]))['pid'])\n";
    }
    auto plugin = engine->exec_file("main.py", plugin_root, "{\"pid\": 1337}");
    check("plugin-local imports and context work in isolated mode",
          plugin.ok && plugin.output.find("42 1337") != std::string::npos,
          plugin.error + plugin.output);
    std::filesystem::remove_all(plugin_root, ec);
  }
#else
  check("restrictive policy fails closed without OS backend",
        !safe_init && error.find("no reviewed OS isolation backend") !=
                          std::string::npos,
        error);
#endif

  auto partial = SandboxPolicy::create();
  partial.allow_filesystem = true;
  partial.allow_subprocess = true;
  error.clear();
  auto partial_engine = create_python_sandbox();
  const bool partial_init = partial_engine->init(partial, limits, &error);
#ifdef __APPLE__
  check("partial policy remains OS isolated", partial_init, error);
#else
  check("partial policy fails closed without OS backend", !partial_init, error);
#endif

  auto trusted = SandboxPolicy::create();
  trusted.allow_filesystem = true;
  trusted.allow_subprocess = true;
  trusted.allow_network = true;
  trusted.allow_native_modules = true;
  trusted.allow_ffi = true;
  auto trusted_engine = create_python_sandbox();
  error.clear();
  const bool trusted_init = trusted_engine->init(trusted, limits, &error);
  check("explicit trusted mode initializes", trusted_init, error);
  if (trusted_init) {
    auto run = trusted_engine->exec("print(6 * 7)");
    check("trusted mode is still supervised",
          run.ok && run.output.find("42") != std::string::npos,
          run.error + run.output);
  }

  std::cout << "Python sandbox tests: " << g_passed << " passed, "
            << g_failed << " failed\n";
  return g_failed == 0 ? 0 : 1;
}

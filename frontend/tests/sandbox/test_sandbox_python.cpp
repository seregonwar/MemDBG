/*
 * MemDBG Sandbox — Python fail-closed regression tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sandbox/sandbox.hpp"

#include <iostream>
#include <string>

int main() {
  using namespace memdbg::sandbox;
  auto engine = create_python_sandbox();
  auto limits = SandboxLimits::python_defaults();
  std::string error;

  const bool safe_init = engine->init(SandboxPolicy::create(), limits, &error);
  if (safe_init || error.find("untrusted Python execution is disabled") ==
                       std::string::npos) {
    std::cerr << "FAIL restrictive Python policy did not fail closed: "
              << error << "\n";
    return 1;
  }

  auto partial = SandboxPolicy::create();
  partial.allow_filesystem = true;
  partial.allow_subprocess = true;
  error.clear();
  if (engine->init(partial, limits, &error)) {
    std::cerr << "FAIL partially permissive Python policy was accepted\n";
    return 1;
  }

  std::cout << "Python sandbox fail-closed tests passed\n";
  return 0;
}

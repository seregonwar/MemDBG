/*
 * MemDBG Sandbox — mobile Python fail-closed backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sandbox_engine.hpp"

namespace memdbg::sandbox {

namespace {

class MobilePythonSandbox final : public SandboxEngine {
public:
  bool init(const SandboxPolicy &policy, const SandboxLimits &limits,
            std::string *error = nullptr) override {
    policy_ = policy;
    limits_ = limits;
    if (error != nullptr) {
      *error = "Python plugins are unavailable on mobile builds; use Lua";
    }
    return false;
  }

  void shutdown() override {}

  SandboxResult exec(const std::string &) override {
    return unavailable_result();
  }

  SandboxResult exec_file(const std::filesystem::path &,
                          const std::filesystem::path &,
                          const std::string & = "") override {
    return unavailable_result();
  }

  bool is_initialized() const override { return false; }
  const char *engine_name() const override { return "Python 3 (unavailable)"; }

private:
  static SandboxResult unavailable_result() {
    SandboxResult result;
    result.exit_reason = SandboxExitReason::kPolicy;
    result.error = "Python plugins are unavailable on mobile builds; use Lua";
    return result;
  }
};

} // namespace

std::unique_ptr<SandboxEngine> create_python_sandbox() {
  return std::make_unique<MobilePythonSandbox>();
}

} // namespace memdbg::sandbox

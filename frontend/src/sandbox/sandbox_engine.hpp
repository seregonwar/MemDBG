/*
 * MemDBG Sandbox — Abstract script execution engine.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_SANDBOX_ENGINE_HPP
#define MEMDBG_SANDBOX_ENGINE_HPP

#include "sandbox_policy.hpp"
#include "sandbox_limits.hpp"
#include "sandbox_result.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace memdbg::sandbox {

/// Abstract base for sandboxed script execution engines.
class SandboxEngine {
public:
  virtual ~SandboxEngine() = default;

  virtual bool init(const SandboxPolicy &policy, const SandboxLimits &limits,
                    std::string *error = nullptr) = 0;
  virtual void shutdown() = 0;
  virtual SandboxResult exec(const std::string &code) = 0;
  virtual SandboxResult exec_file(const std::filesystem::path &entry,
                                  const std::filesystem::path &root,
                                  const std::string &context_json = "") = 0;
  virtual bool is_initialized() const = 0;
  virtual const char *engine_name() const = 0;

  const SandboxPolicy &policy() const { return policy_; }
  const SandboxLimits &limits() const { return limits_; }

protected:
  SandboxPolicy policy_;
  SandboxLimits limits_;
};

// Factory functions
std::unique_ptr<SandboxEngine> create_lua_sandbox();
std::unique_ptr<SandboxEngine> create_python_sandbox();

} // namespace memdbg::sandbox

#endif /* MEMDBG_SANDBOX_ENGINE_HPP */

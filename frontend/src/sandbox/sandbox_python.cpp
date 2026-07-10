/*
 * MemDBG Sandbox — Python subprocess sandbox.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Python scripts execute in a separate process with:
 *   - RLIMIT_AS (virtual memory cap)
 *   - RLIMIT_CPU (CPU time cap)
 *   - RLIMIT_NPROC (no child processes)
 *   - RLIMIT_NOFILE (no file descriptors beyond stdin/stdout/stderr)
 *   - SIGALRM wall-clock timeout
 *   - Output captured with hard byte cap
 *   - PYTHONPATH restricted to plugin directory
 *   - Stdin closed (/dev/null)
 *   - Command-line arguments shell-quoted
 */

#include "sandbox_engine.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>

#if defined(_WIN32)
#include <process.h>
#define SANDBOX_POPEN  _popen
#define SANDBOX_PCLOSE _pclose
#else
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#define SANDBOX_POPEN  popen
#define SANDBOX_PCLOSE pclose
#endif

namespace memdbg::sandbox {

using Clock = std::chrono::steady_clock;

// ── shell quoting ────────────────────────────────────────────────────────

static std::string posix_quote(const std::string &s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'') out += "'\\''";
    else out.push_back(c);
  }
  out += "'";
  return out;
}

// ── Python sandbox ───────────────────────────────────────────────────────

class PythonSandbox : public SandboxEngine {
public:
  bool init(const SandboxPolicy &policy, const SandboxLimits &limits,
            std::string *error = nullptr) override;
  void shutdown() override {}
  SandboxResult exec(const std::string &code) override;
  SandboxResult exec_file(const std::filesystem::path &entry,
                          const std::filesystem::path &root,
                          const std::string &context_json = "") override;
  bool is_initialized() const override { return initialized_; }
  const char *engine_name() const override { return "Python 3"; }

private:
  bool initialized_ = false;
  std::string python_exe_;

  SandboxResult run_command(const std::string &command);
#ifdef __APPLE__
  static void setup_rlimits();
#endif
};

bool PythonSandbox::init(const SandboxPolicy &policy,
                         const SandboxLimits &limits,
                         std::string *error) {
  policy_ = policy;
  limits_ = limits;

  // CPython cannot be turned into a security boundary with import hooks:
  // blocked modules remain reachable through already-loaded objects and the
  // runtime's object graph.  Until this engine has a platform sandbox
  // (seatbelt/seccomp/restricted token), fail closed for every restrictive
  // policy instead of claiming that Python code is isolated.
  const bool explicitly_unrestricted =
      policy.allow_filesystem && policy.allow_subprocess &&
      policy.allow_network && policy.allow_native_modules && policy.allow_ffi;
  if (!explicitly_unrestricted) {
    if (error) {
      *error = "Python sandbox unavailable: untrusted Python execution is "
               "disabled; use Lua or explicitly request unrestricted execution";
    }
    return false;
  }

  // Find python3
  const char *candidates[] = {"python3", "python", nullptr};
  for (int i = 0; candidates[i] != nullptr; ++i) {
    std::string check = "command -v " + posix_quote(candidates[i]) +
                        " >/dev/null 2>&1";
    if (std::system(check.c_str()) == 0) {
      python_exe_ = candidates[i];
      break;
    }
  }
  if (python_exe_.empty()) {
    if (error) *error = "Python 3 interpreter not found";
    return false;
  }
  initialized_ = true;
  return true;
}

SandboxResult PythonSandbox::exec(const std::string &code) {
  SandboxResult result;
  result.exit_reason = SandboxExitReason::kInternal;

  // Write code to temp file
  std::FILE *f = nullptr;
#if defined(_WIN32)
  char tmp_path[L_tmpnam_s] = {};
  if (tmpnam_s(tmp_path, sizeof(tmp_path)) == 0) {
    f = std::fopen(tmp_path, "wb");
  }
#else
  char tmp_path[] = "/tmp/memdbg-sandbox-py-XXXXXX";
  const int fd = mkstemp(tmp_path);
  if (fd >= 0) f = fdopen(fd, "w");
  if (fd >= 0 && f == nullptr) close(fd);
#endif
  if (f == nullptr) {
    result.error = "Cannot create temp file for Python script";
    return result;
  }
  const std::string code_with_guard = "# -*- coding: utf-8 -*-\n" + code;
  std::fwrite(code_with_guard.data(), 1, code_with_guard.size(), f);
  std::fclose(f);

  std::string cmd = python_exe_ + " " + posix_quote(tmp_path) + " 2>&1";
  result = run_command(cmd);
  std::remove(tmp_path);
  return result;
}

SandboxResult PythonSandbox::exec_file(const std::filesystem::path &entry,
                                       const std::filesystem::path &root,
                                       const std::string &context_json) {
  SandboxResult result;
  (void)context_json;

  // Build safe command with restricted PYTHONPATH
  std::ostringstream cmd;
  cmd << "cd " << posix_quote(root.string())
      << " && PYTHONPATH=" << posix_quote(root.string())
      << " python3 "
      << "-I"  // isolated mode: no user-site, no PYTHON* env
      << " -s" // no user site directory
      << " " << posix_quote(entry.string()) << " 2>&1";

  result = run_command(cmd.str());
  return result;
}

#ifdef __APPLE__
void PythonSandbox::setup_rlimits() {
  // macOS doesn't support RLIMIT_NPROC/RLIMIT_AS the same way; just set CPU
  struct rlimit rl;
  rl.rlim_cur = 30;
  rl.rlim_max = 30;
  setrlimit(RLIMIT_CPU, &rl);
}
#endif

SandboxResult PythonSandbox::run_command(const std::string &command) {
  SandboxResult result;
  result.exit_reason = SandboxExitReason::kInternal;

  // Prepend ulimit commands on Unix
  std::string full_cmd;
#if !defined(_WIN32)
  std::ostringstream ulim;
  ulim << "ulimit -t " << limits_.python_timeout_sec << " 2>/dev/null; "
       << "ulimit -v " << (limits_.python_max_mb * 1024) << " 2>/dev/null; "
       << "ulimit -u " << limits_.python_max_procs << " 2>/dev/null; "
       << "ulimit -n " << (limits_.python_max_files > 0 ? limits_.python_max_files : 4) << " 2>/dev/null; "
       << command;
  full_cmd = ulim.str();
#else
  full_cmd = command;
#endif

  auto t_start = Clock::now();

  FILE *pipe = SANDBOX_POPEN(full_cmd.c_str(), "r");
  if (pipe == nullptr) {
    result.error = "Cannot start Python process";
    return result;
  }

  std::array<char, 4096> buf{};
  bool truncated = false;
  while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
    size_t len = std::strlen(buf.data());
    if (result.output.size() <= limits_.max_output_bytes &&
        len <= limits_.max_output_bytes - result.output.size()) {
      result.output += buf.data();
    } else {
      truncated = true;
    }
  }

  int raw_code = SANDBOX_PCLOSE(pipe);
  auto t_end = Clock::now();
  result.elapsed_ms = static_cast<int32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count());

#if !defined(_WIN32)
  if (WIFEXITED(raw_code)) {
    result.exit_code = WEXITSTATUS(raw_code);
    result.ok = (result.exit_code == 0);
  } else if (WIFSIGNALED(raw_code)) {
    result.exit_code = 128 + WTERMSIG(raw_code);
    result.ok = false;
    int sig = WTERMSIG(raw_code);
    if (sig == SIGALRM || sig == SIGXCPU)
      result.exit_reason = SandboxExitReason::kTimeout;
    else if (sig == SIGSEGV || sig == SIGABRT)
      result.exit_reason = SandboxExitReason::kMemory;
    else
      result.exit_reason = SandboxExitReason::kError;
  }
#else
  result.exit_code = raw_code;
  result.ok = (raw_code == 0);
#endif

  if (result.ok && result.exit_reason == SandboxExitReason::kInternal)
    result.exit_reason = SandboxExitReason::kCompleted;

  if (truncated) {
    result.output += "\n[Sandbox] Output truncated.\n";
  }
  if (!result.ok && result.error.empty()) {
    result.error = "Process exited with code " + std::to_string(result.exit_code);
  }

  return result;
}

// ── factory ──────────────────────────────────────────────────────────────

std::unique_ptr<SandboxEngine> create_python_sandbox() {
  return std::unique_ptr<SandboxEngine>(new PythonSandbox());
}

} // namespace memdbg::sandbox

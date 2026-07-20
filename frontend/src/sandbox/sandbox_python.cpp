/*
 * MemDBG Sandbox — supervised Python subprocess sandbox.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sandbox_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#define SANDBOX_POPEN _popen
#define SANDBOX_PCLOSE _pclose
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace memdbg::sandbox {

using Clock = std::chrono::steady_clock;

namespace {

std::string find_executable(const std::vector<std::string> &names) {
  const char *path_env = std::getenv("PATH");
  if (path_env == nullptr) return {};
#if defined(_WIN32)
  constexpr char separator = ';';
#else
  constexpr char separator = ':';
#endif
  std::stringstream paths(path_env);
  std::string directory;
  while (std::getline(paths, directory, separator)) {
    if (directory.empty()) directory = ".";
    for (const std::string &name : names) {
      std::filesystem::path candidate = std::filesystem::path(directory) / name;
      std::error_code ec;
      if (std::filesystem::is_regular_file(candidate, ec))
        return std::filesystem::absolute(candidate, ec).string();
#if defined(_WIN32)
      candidate += ".exe";
      if (std::filesystem::is_regular_file(candidate, ec))
        return std::filesystem::absolute(candidate, ec).string();
#endif
    }
  }
  return {};
}

bool path_is_within(const std::filesystem::path &child,
                    const std::filesystem::path &root) {
  const auto relative = child.lexically_relative(root);
  return !relative.empty() && !relative.is_absolute() &&
         *relative.begin() != "..";
}

std::filesystem::path make_private_temp_dir() {
#if defined(_WIN32)
  std::error_code ec;
  auto base = std::filesystem::temp_directory_path(ec);
  for (unsigned i = 0; i < 100U; ++i) {
    auto candidate = base / ("memdbg-python-" + std::to_string(std::rand()) +
                             "-" + std::to_string(i));
    if (std::filesystem::create_directory(candidate, ec)) return candidate;
  }
  return {};
#else
  std::string pattern =
      (std::filesystem::temp_directory_path() / "memdbg-python-XXXXXX").string();
  std::vector<char> writable(pattern.begin(), pattern.end());
  writable.push_back('\0');
  char *created = mkdtemp(writable.data());
  if (created == nullptr) return {};
  std::error_code ec;
  auto canonical = std::filesystem::canonical(created, ec);
  return ec ? std::filesystem::path(created) : canonical;
#endif
}

#ifdef __APPLE__
std::string seatbelt_quote(const std::string &value) {
  std::string out = "\"";
  for (char c : value) {
    if (c == '\\' || c == '"') out.push_back('\\');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}
#endif

#if defined(_WIN32)
std::string shell_quote(const std::string &value) {
  std::string out = "\"";
  for (char c : value) {
    if (c == '"') out += "\\\"";
    else out.push_back(c);
  }
  out.push_back('"');
  return out;
}
#endif

} // namespace

class PythonSandbox final : public SandboxEngine {
public:
  bool init(const SandboxPolicy &policy, const SandboxLimits &limits,
            std::string *error = nullptr) override;
  void shutdown() override { initialized_ = false; }
  SandboxResult exec(const std::string &code) override;
  SandboxResult exec_file(const std::filesystem::path &entry,
                          const std::filesystem::path &root,
                          const std::string &context_json = "") override;
  bool is_initialized() const override { return initialized_; }
  const char *engine_name() const override { return "Python 3"; }

private:
  SandboxResult run(const std::filesystem::path &entry,
                    const std::filesystem::path &root,
                    const std::filesystem::path &temp_dir,
                    const std::filesystem::path &context_path);
#ifdef __APPLE__
  std::string seatbelt_profile(const std::filesystem::path &root,
                               const std::filesystem::path &temp_dir) const;
#endif

  bool initialized_ = false;
  bool os_isolated_ = false;
  std::string python_exe_;
};

bool PythonSandbox::init(const SandboxPolicy &policy,
                         const SandboxLimits &limits,
                         std::string *error) {
  initialized_ = false;
  os_isolated_ = false;
  policy_ = policy;
  limits_ = limits;
  if (!limits.is_valid()) {
    if (error) *error = "Invalid Python sandbox limits";
    return false;
  }

#if defined(_WIN32)
  python_exe_ = find_executable({"python3", "python", "py"});
#else
  python_exe_ = find_executable({"python3", "python"});
#endif
  if (python_exe_.empty()) {
    if (error) *error = "Python 3 interpreter not found";
    return false;
  }

  const bool unrestricted =
      policy.allow_filesystem && policy.allow_subprocess &&
      policy.allow_network && policy.allow_native_modules && policy.allow_ffi;
#ifdef __APPLE__
  os_isolated_ = std::filesystem::is_regular_file("/usr/bin/sandbox-exec");
#endif
  if (!unrestricted && !os_isolated_) {
    if (error) {
      *error = "Python sandbox unavailable: this platform has no reviewed OS "
               "isolation backend; use Lua or explicitly request unrestricted "
               "execution for trusted code";
    }
    return false;
  }

  initialized_ = true;
  return true;
}

SandboxResult PythonSandbox::exec(const std::string &code) {
  SandboxResult result;
  result.exit_reason = SandboxExitReason::kInternal;
  if (!initialized_) {
    result.error = "Python sandbox is not initialized";
    return result;
  }
  if (code.size() > limits_.max_code_bytes) {
    result.exit_reason = SandboxExitReason::kCodeSize;
    result.error = "Python source exceeds the configured code-size limit";
    return result;
  }
  if (code.find('\0') != std::string::npos) {
    result.exit_reason = SandboxExitReason::kPolicy;
    result.error = "Python source contains an embedded NUL byte";
    return result;
  }

  const auto temp_dir = make_private_temp_dir();
  if (temp_dir.empty()) {
    result.error = "Cannot create private Python sandbox directory";
    return result;
  }
  const auto entry = temp_dir / "script.py";
  {
    std::ofstream out(entry, std::ios::binary | std::ios::trunc);
    if (!out) {
      std::filesystem::remove_all(temp_dir);
      result.error = "Cannot create Python script";
      return result;
    }
    out << "# -*- coding: utf-8 -*-\n" << code;
  }
  result = run(entry, temp_dir, temp_dir, {});
  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return result;
}

SandboxResult PythonSandbox::exec_file(const std::filesystem::path &entry,
                                       const std::filesystem::path &root,
                                       const std::string &context_json) {
  SandboxResult result;
  result.exit_reason = SandboxExitReason::kPolicy;
  if (!initialized_) {
    result.exit_reason = SandboxExitReason::kInternal;
    result.error = "Python sandbox is not initialized";
    return result;
  }

  std::error_code ec;
  const auto canonical_root = std::filesystem::canonical(root, ec);
  if (ec) {
    result.error = "Invalid Python plugin root";
    return result;
  }
  auto candidate = entry.is_absolute() ? entry : canonical_root / entry;
  const auto canonical_entry = std::filesystem::canonical(candidate, ec);
  if (ec || !std::filesystem::is_regular_file(canonical_entry, ec) ||
      !path_is_within(canonical_entry, canonical_root)) {
    result.error = "Python plugin entry escapes its root";
    return result;
  }
  const auto source_size = std::filesystem::file_size(canonical_entry, ec);
  if (ec || source_size > limits_.max_code_bytes) {
    result.exit_reason = SandboxExitReason::kCodeSize;
    result.error = "Python plugin exceeds the configured code-size limit";
    return result;
  }

  const auto temp_dir = make_private_temp_dir();
  if (temp_dir.empty()) {
    result.exit_reason = SandboxExitReason::kInternal;
    result.error = "Cannot create private Python sandbox directory";
    return result;
  }
  std::filesystem::path context_path;
  if (!context_json.empty()) {
    context_path = temp_dir / "context.json";
    std::ofstream out(context_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      std::filesystem::remove_all(temp_dir, ec);
      result.exit_reason = SandboxExitReason::kInternal;
      result.error = "Cannot create Python plugin context";
      return result;
    }
    out << context_json;
  }

  result = run(canonical_entry, canonical_root, temp_dir, context_path);
  std::filesystem::remove_all(temp_dir, ec);
  return result;
}

#ifdef __APPLE__
std::string PythonSandbox::seatbelt_profile(
    const std::filesystem::path &root,
    const std::filesystem::path &temp_dir) const {
  std::ostringstream profile;
  const std::string root_q = seatbelt_quote(root.string());
  const std::string temp_q = seatbelt_quote(temp_dir.string());
  const std::string python_root_q = seatbelt_quote(
      std::filesystem::path(python_exe_).parent_path().parent_path().string());
  profile << "(version 1)\n(deny default)\n"
          << "(allow process-exec)\n"
          /* CPython and dyld touch OS-version-specific runtime paths. Permit
             reads globally, then deny data reads from user-controlled and
             sensitive roots. More-specific plugin/interpreter rules below
             re-enable only the files required for execution. */
          << "(allow file-read*)\n"
          << "(deny file-read-data "
          << "(require-all (subpath \"/Users\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))) "
          << "(require-all (subpath \"/Volumes\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))) "
          << "(require-all (subpath \"/private/etc\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))) "
          << "(require-all (subpath \"/private/var\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))) "
          << "(require-all (subpath \"/opt\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))) "
          << "(require-all (subpath \"/usr/local\") (require-not (subpath "
          << root_q << ")) (require-not (subpath " << temp_q
          << ")) (require-not (subpath " << python_root_q << "))))\n"
          << "(allow file-read* (subpath " << root_q
          << ") (subpath " << temp_q << ") (subpath " << python_root_q
          << "))\n"
          << "(allow file-read-metadata)\n"
          << "(allow sysctl-read)\n"
          << "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n";
  if (policy_.allow_filesystem)
    profile << "(allow file-read*)\n(allow file-write*)\n";
  else if (policy_.allow_tempfiles)
    profile << "(allow file-write* (subpath "
            << seatbelt_quote(temp_dir.string()) << "))\n";
  if (policy_.allow_subprocess)
    profile << "(allow process-fork)\n";
  if (policy_.allow_network)
    profile << "(allow network*)\n";
  return profile.str();
}
#endif

SandboxResult PythonSandbox::run(const std::filesystem::path &entry,
                                 const std::filesystem::path &root,
                                 const std::filesystem::path &temp_dir,
                                 const std::filesystem::path &context_path) {
  SandboxResult result;
  result.exit_reason = SandboxExitReason::kInternal;
  const auto started = Clock::now();

#if defined(_WIN32)
  (void)temp_dir;
  std::string command = "cd /d " + shell_quote(root.string()) + " && " +
      shell_quote(python_exe_) + " -I -s -B " + shell_quote(entry.string());
  if (!context_path.empty()) command += " " + shell_quote(context_path.string());
  command += " 2>&1";
  FILE *pipe = SANDBOX_POPEN(command.c_str(), "r");
  if (pipe == nullptr) {
    result.error = "Cannot start Python process";
    return result;
  }
  std::array<char, 4096> buffer{};
  bool truncated = false;
  while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
    const size_t len = std::strlen(buffer.data());
    const size_t room = result.output.size() < limits_.max_output_bytes
        ? limits_.max_output_bytes - result.output.size() : 0U;
    result.output.append(buffer.data(), std::min(room, len));
    truncated = truncated || len > room;
  }
  result.exit_code = SANDBOX_PCLOSE(pipe);
  result.ok = result.exit_code == 0;
  result.exit_reason = result.ok ? SandboxExitReason::kCompleted
                                 : SandboxExitReason::kError;
#else
  int output_pipe[2] = {-1, -1};
  if (pipe(output_pipe) != 0) {
    result.error = "Cannot create Python output pipe";
    return result;
  }

  std::string profile;
#ifdef __APPLE__
  if (os_isolated_) profile = seatbelt_profile(root, temp_dir);
#endif
  pid_t child = fork();
  if (child < 0) {
    close(output_pipe[0]); close(output_pipe[1]);
    result.error = "Cannot fork Python sandbox process";
    return result;
  }
  if (child == 0) {
    (void)setpgid(0, 0);
    const int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) (void)dup2(null_fd, STDIN_FILENO);
    (void)dup2(output_pipe[1], STDOUT_FILENO);
    (void)dup2(output_pipe[1], STDERR_FILENO);
    close(output_pipe[0]); close(output_pipe[1]);
    if (null_fd > STDERR_FILENO) close(null_fd);

    struct rlimit limit{};
    const int cpu_seconds = std::max(1, limits_.python_timeout_sec);
    limit.rlim_cur = static_cast<rlim_t>(cpu_seconds);
    limit.rlim_max = static_cast<rlim_t>(cpu_seconds + 1);
    (void)setrlimit(RLIMIT_CPU, &limit);
#if !defined(__APPLE__)
    limit.rlim_cur = limit.rlim_max =
        static_cast<rlim_t>(limits_.python_max_mb) * 1024U * 1024U;
    (void)setrlimit(RLIMIT_AS, &limit);
#endif
#ifdef RLIMIT_NPROC
    limit.rlim_cur = limit.rlim_max =
        static_cast<rlim_t>(std::max(1, limits_.python_max_procs));
    (void)setrlimit(RLIMIT_NPROC, &limit);
#endif
    limit.rlim_cur = limit.rlim_max =
        static_cast<rlim_t>(std::max(16, limits_.python_max_files));
    (void)setrlimit(RLIMIT_NOFILE, &limit);
    (void)chdir(root.c_str());
    (void)setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    (void)setenv("PYTHONNOUSERSITE", "1", 1);
    (void)setenv("TMPDIR", temp_dir.c_str(), 1);
    (void)setenv("TMP", temp_dir.c_str(), 1);
    (void)setenv("TEMP", temp_dir.c_str(), 1);
    (void)setenv("MEMDBG_PLUGIN_DIR", root.c_str(), 1);
    if (!context_path.empty())
      (void)setenv("MEMDBG_CONTEXT", context_path.c_str(), 1);

    std::vector<std::string> arguments;
    static const char *kBootstrap =
        "import runpy,sys; root,entry,*rest=sys.argv[1:]; "
        "sys.path.insert(0,root); sys.argv=[entry]+rest; "
        "runpy.run_path(entry,run_name='__main__')";
#ifdef __APPLE__
    if (os_isolated_) {
      arguments = {"/usr/bin/sandbox-exec", "-p", profile, python_exe_,
                   "-I", "-s", "-B", "-c", kBootstrap, root.string(),
                   entry.string()};
    } else
#endif
    {
      arguments = {python_exe_, "-I", "-s", "-B", "-c", kBootstrap,
                   root.string(), entry.string()};
    }
    if (!context_path.empty()) arguments.push_back(context_path.string());
    std::vector<char *> argv;
    argv.reserve(arguments.size() + 1U);
    for (std::string &argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    execv(argv[0], argv.data());
    _exit(127);
  }

  close(output_pipe[1]);
  const int flags = fcntl(output_pipe[0], F_GETFL, 0);
  (void)fcntl(output_pipe[0], F_SETFL, flags | O_NONBLOCK);
  bool truncated = false;
  bool timed_out = false;
  int status = 0;
  bool exited = false;
  const auto deadline = started + std::chrono::milliseconds(
      limits_.max_time_ms > 0 ? limits_.max_time_ms
                              : limits_.python_timeout_sec * 1000);
  std::array<char, 4096> buffer{};
  while (!exited) {
    struct pollfd pfd{output_pipe[0], POLLIN, 0};
    (void)poll(&pfd, 1, 20);
    for (;;) {
      const ssize_t count = read(output_pipe[0], buffer.data(), buffer.size());
      if (count <= 0) break;
      const size_t len = static_cast<size_t>(count);
      const size_t room = result.output.size() < limits_.max_output_bytes
          ? limits_.max_output_bytes - result.output.size() : 0U;
      result.output.append(buffer.data(), std::min(room, len));
      truncated = truncated || len > room;
    }
    const pid_t waited = waitpid(child, &status, WNOHANG);
    exited = waited == child;
    if (!exited && limits_.max_time_ms > 0 && Clock::now() >= deadline) {
      timed_out = true;
      (void)kill(-child, SIGKILL);
      (void)kill(child, SIGKILL);
      (void)waitpid(child, &status, 0);
      exited = true;
    }
  }
  /* A permitted subprocess must never outlive its plugin invocation. */
  if (!timed_out) (void)kill(-child, SIGTERM);
  for (;;) {
    const ssize_t count = read(output_pipe[0], buffer.data(), buffer.size());
    if (count <= 0) break;
    const size_t len = static_cast<size_t>(count);
    const size_t room = result.output.size() < limits_.max_output_bytes
        ? limits_.max_output_bytes - result.output.size() : 0U;
    result.output.append(buffer.data(), std::min(room, len));
    truncated = truncated || len > room;
  }
  close(output_pipe[0]);

  if (timed_out) {
    result.exit_code = 128 + SIGKILL;
    result.exit_reason = SandboxExitReason::kTimeout;
  } else if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
    result.ok = result.exit_code == 0;
    result.exit_reason = result.ok ? SandboxExitReason::kCompleted
                                   : SandboxExitReason::kError;
  } else if (WIFSIGNALED(status)) {
    const int signal = WTERMSIG(status);
    result.exit_code = 128 + signal;
    result.exit_reason = signal == SIGXCPU ? SandboxExitReason::kTimeout
                                           : SandboxExitReason::kError;
  }
#endif

  result.elapsed_ms = static_cast<int32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          Clock::now() - started).count());
  if (truncated) {
    result.output += "\n[Sandbox] Output truncated.\n";
    result.exit_reason = SandboxExitReason::kOutput;
  }
  if (!result.ok && result.error.empty())
    result.error = result.exit_reason == SandboxExitReason::kTimeout
        ? "Python execution timed out"
        : "Python process exited with code " + std::to_string(result.exit_code);
  if (result.error.size() > 1024U) result.error.resize(1024U);
  return result;
}

std::unique_ptr<SandboxEngine> create_python_sandbox() {
  return std::make_unique<PythonSandbox>();
}

} // namespace memdbg::sandbox

/*
 * MemDBG - IDA GDB bridge subprocess runner.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gdb_bridge_runner.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <system_error>
#include <thread>

#if defined(MEMDBG_PLATFORM_IOS)
/* iOS does not support fork/exec; the runner is compiled out. */
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <mach-o/dyld.h>
#else
#include <limits.h>
#endif
#endif

#if defined(MEMDBG_PLATFORM_IOS)
namespace memdbg::frontend {

std::filesystem::path GdbBridgeRunner::locate_binary() { return {}; }
bool GdbBridgeRunner::start(const Config &, std::string &error) {
  error = "process spawning is unavailable on this platform";
  return false;
}
void GdbBridgeRunner::stop() {}
bool GdbBridgeRunner::running() const { return false; }
void GdbBridgeRunner::poll_output() {}
GdbBridgeRunner::~GdbBridgeRunner() = default;

} // namespace memdbg::frontend
#else
namespace memdbg::frontend {

namespace {

#if defined(_WIN32)
constexpr const char *kBridgeBinaryFile = "memdbg_gdb_bridge.exe";
#else
constexpr const char *kBridgeBinaryFile = "memdbg_gdb_bridge";
#endif
constexpr unsigned int kTerminateGraceMs = 3000U;

std::filesystem::path make_shutdown_file_path() {
  std::error_code ec;
  std::filesystem::path dir = std::filesystem::temp_directory_path(ec);
  if (ec) return {};
#if defined(_WIN32)
  const unsigned long pid = static_cast<unsigned long>(GetCurrentProcessId());
#else
  const unsigned long pid = static_cast<unsigned long>(::getpid());
#endif
  const auto stamp = static_cast<unsigned long long>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  return dir / ("memdbg-gdb-bridge-" + std::to_string(pid) + "-" +
                std::to_string(stamp) + ".shutdown");
}

bool create_shutdown_file(const std::filesystem::path &path) {
  if (path.empty()) return false;
  std::ofstream out(path, std::ios::out | std::ios::trunc);
  out << "shutdown\n";
  return static_cast<bool>(out);
}

void remove_shutdown_file(const std::filesystem::path &path) {
  if (path.empty()) return;
  std::error_code ec;
  (void)std::filesystem::remove(path, ec);
}

#if defined(_WIN32)
std::string quote_windows_arg(const std::string &arg) {
  std::string out;
  out.push_back('"');
  size_t backslashes = 0U;
  for (char c : arg) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2U + 1U, '\\');
      out.push_back('"');
      backslashes = 0U;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0U;
    out.push_back(c);
  }
  out.append(backslashes * 2U, '\\');
  out.push_back('"');
  return out;
}
#endif

} // namespace

GdbBridgeRunner::~GdbBridgeRunner() { stop(); }

std::filesystem::path GdbBridgeRunner::locate_binary() {
  namespace fs = std::filesystem;

  char exe_buf[4096];
  exe_buf[0] = '\0';
#if defined(_WIN32)
  wchar_t wide_buf[4096];
  const DWORD n = GetModuleFileNameW(nullptr, wide_buf, 4096);
  if (n > 0 && n < 4096) {
    (void)WideCharToMultiByte(CP_UTF8, 0, wide_buf, -1, exe_buf,
                              static_cast<int>(sizeof(exe_buf)), nullptr,
                              nullptr);
  }
#elif defined(__APPLE__)
  uint32_t size = sizeof(exe_buf);
  if (_NSGetExecutablePath(exe_buf, &size) != 0) exe_buf[0] = '\0';
#elif defined(__linux__)
  {
    const ssize_t n = ::readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
    if (n > 0) exe_buf[n] = '\0';
  }
#endif

  const fs::path exe_path(exe_buf[0] != '\0' ? exe_buf : "");
  if (!exe_path.empty()) {
    std::error_code ec;
    const fs::path candidate = exe_path.parent_path() / kBridgeBinaryFile;
    if (fs::is_regular_file(candidate, ec)) return candidate;
  }

  if (const char *path_env = std::getenv("PATH")) {
    std::error_code ec;
#if defined(_WIN32)
    const char sep_char = ';';
#else
    const char sep_char = ':';
#endif
    std::string path_str(path_env);
    size_t begin = 0;
    while (begin <= path_str.size()) {
      const size_t sep = path_str.find(sep_char, begin);
      const std::string dir = path_str.substr(
          begin, sep == std::string::npos ? std::string::npos : sep - begin);
      if (!dir.empty()) {
        const fs::path candidate = fs::path(dir) / kBridgeBinaryFile;
        if (fs::is_regular_file(candidate, ec)) return candidate;
      }
      if (sep == std::string::npos) break;
      begin = sep + 1U;
    }
  }
  return {};
}

bool GdbBridgeRunner::start(const Config &config, std::string &error) {
  stop();

  if (config.binary.empty()) {
    error = "memdbg_gdb_bridge binary not found";
    return false;
  }
  if (config.host.empty()) {
    error = "console host is required";
    return false;
  }

  shutdown_file_ = make_shutdown_file_path();
  remove_shutdown_file(shutdown_file_);

  std::vector<std::string> args;
  args.push_back("--host");
  args.push_back(config.host);
  args.push_back("--port");
  args.push_back(std::to_string(config.mdbg_port));
  if (!config.listen.empty()) {
    args.push_back("--listen");
    args.push_back(config.listen);
  }
  if (!config.pid.empty()) {
    args.push_back("--pid");
    args.push_back(config.pid);
  }
  if (!config.name.empty()) {
    args.push_back("--name");
    args.push_back(config.name);
  }
  if (config.verbose) args.push_back("--verbose");
  if (config.once) args.push_back("--once");
  if (!shutdown_file_.empty()) {
    args.push_back("--shutdown-file");
    args.push_back(shutdown_file_.string());
  }

  lines_.clear();
  pending_line_.clear();
  exit_code_ = kNoExitCode;

#if defined(_WIN32)
  SECURITY_ATTRIBUTES inherit{};
  inherit.nLength = sizeof(inherit);
  inherit.bInheritHandle = TRUE;

  HANDLE out_read = nullptr;
  HANDLE out_write = nullptr;
  HANDLE err_read = nullptr;
  HANDLE err_write = nullptr;
  if (!CreatePipe(&out_read, &out_write, &inherit, 0)) {
    error = "CreatePipe(stdout) failed (" + std::to_string(GetLastError()) + ")";
    return false;
  }
  if (!CreatePipe(&err_read, &err_write, &inherit, 0)) {
    const DWORD pipe_error = GetLastError();
    CloseHandle(out_read);
    CloseHandle(out_write);
    remove_shutdown_file(shutdown_file_);
    shutdown_file_.clear();
    error = "CreatePipe(stderr) failed (" + std::to_string(pipe_error) + ")";
    return false;
  }
  SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);

  std::string command = quote_windows_arg(config.binary.string());
  for (const std::string &arg : args) {
    command.push_back(' ');
    command += quote_windows_arg(arg);
  }

  STARTUPINFOA si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = out_write;
  si.hStdError = err_write;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION pi{};
  std::vector<char> cmd_buf(command.begin(), command.end());
  cmd_buf.push_back('\0');
  const BOOL ok = CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                                 CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
  CloseHandle(out_write);
  CloseHandle(err_write);
  if (!ok) {
    CloseHandle(out_read);
    CloseHandle(err_read);
    remove_shutdown_file(shutdown_file_);
    shutdown_file_.clear();
    error = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
    return false;
  }
  CloseHandle(pi.hThread);
  child_ = pi.hProcess;
  stdout_read_ = out_read;
  stderr_read_ = err_read;
#else
  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
    error = "pipe() failed";
    if (out_pipe[0] >= 0) { ::close(out_pipe[0]); ::close(out_pipe[1]); }
    if (err_pipe[0] >= 0) { ::close(err_pipe[0]); ::close(err_pipe[1]); }
    remove_shutdown_file(shutdown_file_);
    shutdown_file_.clear();
    return false;
  }

  std::vector<char *> argv;
  const std::string binary = config.binary.string();
  argv.push_back(const_cast<char *>(binary.c_str()));
  for (const std::string &arg : args) argv.push_back(const_cast<char *>(arg.c_str()));
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    error = "fork() failed";
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(err_pipe[0]); ::close(err_pipe[1]);
    remove_shutdown_file(shutdown_file_);
    shutdown_file_.clear();
    return false;
  }
  if (pid == 0) {
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(err_pipe[0]); ::close(err_pipe[1]);
    ::setpgid(0, 0);
    ::execv(binary.c_str(), argv.data());
    _exit(127);
  }

  ::close(out_pipe[1]);
  ::close(err_pipe[1]);
  const int out_flags = ::fcntl(out_pipe[0], F_GETFL, 0);
  (void)::fcntl(out_pipe[0], F_SETFL, out_flags | O_NONBLOCK);
  const int err_flags = ::fcntl(err_pipe[0], F_GETFL, 0);
  (void)::fcntl(err_pipe[0], F_SETFL, err_flags | O_NONBLOCK);
  child_pid_ = pid;
  stdout_fd_ = out_pipe[0];
  stderr_fd_ = err_pipe[0];
#endif

  lines_.push_back("[bridge] started " + config.binary.filename().string() +
                   " -> " + config.host + ":" + std::to_string(config.mdbg_port));
  if (lines_.size() > kMaxLines) lines_.pop_front();
  return true;
}

void GdbBridgeRunner::reap_child(bool blocking) {
#if defined(_WIN32)
  if (child_ == nullptr) return;
  const DWORD timeout = blocking ? INFINITE : 0;
  const DWORD wait = WaitForSingleObject(static_cast<HANDLE>(child_), timeout);
  if (wait == WAIT_OBJECT_0) {
    DWORD code = 0;
    if (GetExitCodeProcess(static_cast<HANDLE>(child_), &code))
      exit_code_ = static_cast<int>(code);
    CloseHandle(static_cast<HANDLE>(child_));
    child_ = nullptr;
  }
#else
  if (child_pid_ <= 0) return;
  int status = 0;
  const pid_t r = ::waitpid(child_pid_, &status, blocking ? 0 : WNOHANG);
  if (r == child_pid_) {
    if (WIFEXITED(status)) exit_code_ = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) exit_code_ = 128 + WTERMSIG(status);
    child_pid_ = -1;
  }
#endif
}

void GdbBridgeRunner::stop() {
  const bool asked_gracefully = create_shutdown_file(shutdown_file_);
#if defined(_WIN32)
  if (child_ != nullptr) {
    if (!asked_gracefully) {
      (void)TerminateProcess(static_cast<HANDLE>(child_), (UINT)1);
    } else {
      const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(kTerminateGraceMs);
      while (child_ != nullptr && std::chrono::steady_clock::now() <= deadline) {
        reap_child(false);
        if (child_ != nullptr)
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      if (child_ != nullptr)
        (void)TerminateProcess(static_cast<HANDLE>(child_), (UINT)1);
    }
    if (child_ != nullptr) {
      (void)WaitForSingleObject(static_cast<HANDLE>(child_), 5000);
      reap_child(true);
    }
  }
  if (stdout_read_ != nullptr) CloseHandle(static_cast<HANDLE>(stdout_read_));
  if (stderr_read_ != nullptr) CloseHandle(static_cast<HANDLE>(stderr_read_));
  stdout_read_ = nullptr;
  stderr_read_ = nullptr;
#else
  if (child_pid_ > 0) {
    (void)asked_gracefully;
    (void)::kill(child_pid_, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(kTerminateGraceMs);
    while (child_pid_ > 0 && std::chrono::steady_clock::now() <= deadline) {
      reap_child(false);
      if (child_pid_ > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (child_pid_ > 0) {
      (void)::kill(child_pid_, SIGKILL);
      reap_child(true);
    }
  }
  if (stdout_fd_ >= 0) ::close(stdout_fd_);
  if (stderr_fd_ >= 0) ::close(stderr_fd_);
  stdout_fd_ = -1;
  stderr_fd_ = -1;
#endif
  remove_shutdown_file(shutdown_file_);
  shutdown_file_.clear();
  if (lines_.size() >= kMaxLines) lines_.pop_front();
  lines_.push_back("[bridge] stopped");
}

bool GdbBridgeRunner::running() const {
#if defined(_WIN32)
  return child_ != nullptr;
#else
  return child_pid_ > 0;
#endif
}

void GdbBridgeRunner::append_output(const char *data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    const char c = data[i];
    if (c == '\n') {
      if (!pending_line_.empty() && pending_line_.back() == '\r')
        pending_line_.pop_back();
      lines_.push_back(pending_line_);
      if (lines_.size() > kMaxLines) lines_.pop_front();
      pending_line_.clear();
      continue;
    }
    if (pending_line_.size() < kMaxLineBytes) pending_line_.push_back(c);
  }
}

void GdbBridgeRunner::poll_output() {
  char buffer[4096];
#if defined(_WIN32)
  const HANDLE reads[2] = {static_cast<HANDLE>(stdout_read_),
                           static_cast<HANDLE>(stderr_read_)};
  for (HANDLE handle : reads) {
    if (handle == nullptr) continue;
    for (;;) {
      DWORD available = 0;
      if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr) ||
          available == 0) break;
      DWORD to_read = available;
      if (to_read > sizeof(buffer)) to_read = sizeof(buffer);
      DWORD got = 0;
      if (!ReadFile(handle, buffer, to_read, &got, nullptr) || got == 0) break;
      append_output(buffer, got);
    }
  }
#else
  const int fds[2] = {stdout_fd_, stderr_fd_};
  for (int fd : fds) {
    if (fd < 0) continue;
    for (;;) {
      const ssize_t got = ::read(fd, buffer, sizeof(buffer));
      if (got > 0) {
        append_output(buffer, static_cast<size_t>(got));
        continue;
      }
      if (got < 0 && errno == EINTR) continue;
      break;
    }
  }
#endif
  reap_child(false);
}

} // namespace memdbg::frontend
#endif /* !MEMDBG_PLATFORM_IOS */

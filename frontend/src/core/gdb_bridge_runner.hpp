/*
 * MemDBG - IDA GDB bridge subprocess runner.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_GDB_BRIDGE_RUNNER_HPP
#define MEMDBG_FRONTEND_GDB_BRIDGE_RUNNER_HPP

#include <cstdint>
#include <deque>
#include <filesystem>
#include <string>
#include <vector>

namespace memdbg::frontend {

/* Runs `memdbg_gdb_bridge` as a child process so IDA can be driven without a
 * separate terminal. Output is captured into a bounded scrollback buffer that
 * the UI thread drains with poll_output(). */
class GdbBridgeRunner {
public:
  struct Config {
    std::filesystem::path binary;
    std::string host;
    uint16_t mdbg_port = 9020;
    std::string listen; /* "[host:]port" forwarded as --listen */
    std::string pid;    /* decimal, empty to omit */
    std::string name;   /* process name, empty to omit */
    bool verbose = false;
    bool once = false;
  };

  GdbBridgeRunner() = default;
  ~GdbBridgeRunner();

  GdbBridgeRunner(const GdbBridgeRunner &) = delete;
  GdbBridgeRunner &operator=(const GdbBridgeRunner &) = delete;

  /* Locates `memdbg_gdb_bridge[.exe]` next to the running frontend
   * executable. Returns an empty path when not found. */
  static std::filesystem::path locate_binary();

  bool start(const Config &config, std::string &error);

  /* Terminates the child: SIGTERM first (the bridge detaches the target on
   * it), then SIGKILL / TerminateProcess after a grace period. */
  void stop();

  bool running() const;

  /* Drains pending child output into the scrollback buffer. Call once per
   * frame from the UI thread. */
  void poll_output();

  const std::deque<std::string> &lines() const { return lines_; }
  bool has_exit_code() const { return exit_code_ != kNoExitCode; }
  int exit_code() const { return exit_code_; }

private:
  static constexpr int kNoExitCode = -1000;
  static constexpr size_t kMaxLines = 400;
  static constexpr size_t kMaxLineBytes = 4096;

  void reap_child(bool blocking);
  void append_output(const char *data, size_t size);

#if defined(_WIN32)
  void *child_ = nullptr; /* HANDLE */
  void *stdout_read_ = nullptr;
  void *stderr_read_ = nullptr;
#else
  int child_pid_ = -1;
  int stdout_fd_ = -1;
  int stderr_fd_ = -1;
#endif
  int exit_code_ = kNoExitCode;
  std::filesystem::path shutdown_file_;
  std::string pending_line_;
  std::deque<std::string> lines_;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_GDB_BRIDGE_RUNNER_HPP */

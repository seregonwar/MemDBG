/*
 * MemDBG - Crash logger for the ImGui frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Ring-buffered logger that writes to a crash-log file in the executable's
 * directory.  Every log() call flushes to disk immediately, so even on a
 * hard crash the file contains all recent activity.  Signal handlers
 * (SIGSEGV, SIGABRT, SIGFPE, SIGILL) append a crash marker and close the
 * file before the process terminates.
 */

#ifndef MEMDBG_FRONTEND_CRASH_LOGGER_HPP
#define MEMDBG_FRONTEND_CRASH_LOGGER_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

namespace memdbg::frontend {

class CrashLogger {
public:
  CrashLogger();
  ~CrashLogger();

  CrashLogger(const CrashLogger &) = delete;
  CrashLogger &operator=(const CrashLogger &) = delete;

  // Open the crash-log file.  Call once at startup.
  // Returns false if the file cannot be created.
  bool open(const char *log_path);

  // Close and flush the log file.
  void close();

  // Append a timestamped entry.  Thread-safe.
  // Flushes to disk immediately so data survives a crash.
  void log(const char *category, const char *message);

  // Flush the ring buffer to disk.
  void flush();

  // Capture console-side log lines (from UdpLogListener).
  // Uses the monotonic `current_received` counter for delta detection.
  // Captures the full snapshot when new lines arrive.
  void capture_console_lines(const std::vector<std::string> &lines,
                             uint64_t &last_received,
                             uint64_t current_received);

  // Enable / disable logging at runtime.
  void set_enabled(bool enabled) { enabled_.store(enabled); }
  bool enabled() const { return enabled_.load(); }

  // True when the log file is open and writable.
  bool is_open() const;

private:
  static constexpr size_t kRingCapacity = 2048;
  static constexpr size_t kMaxLine = 1024;

  // ---- Signal handler (static, registered once) ----
  static void signal_handler(int signum);
  static CrashLogger *s_instance;  // set on open(), cleared on close()

  // ---- Internal helpers ----
  void ring_push(const char *category, const char *message);
  void ring_flush();
  void ring_clear();

  // ---- Ring buffer ----
  struct Entry {
    std::time_t timestamp;
    char category[64];
    char message[kMaxLine];
  };

  Entry   ring_[kRingCapacity];
  size_t  ring_head_  = 0;
  size_t  ring_count_ = 0;

  mutable std::mutex mutex_;
  std::atomic_bool enabled_{false};

  // File write handle (platform-specific)
  void *file_ = nullptr;  // FILE* cast to void to avoid <cstdio> in header
  bool   file_open_ = false;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CRASH_LOGGER_HPP */

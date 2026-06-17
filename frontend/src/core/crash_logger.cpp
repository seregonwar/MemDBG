/*
 * MemDBG - Crash logger implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "crash_logger.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#if !defined(_WIN32)
#include <csignal>
#include <unistd.h>
#endif

namespace memdbg::frontend {

/* ---- Static instance (for signal handler access) ---- */

CrashLogger *CrashLogger::s_instance = nullptr;

/* ---- Construction / destruction ---- */

CrashLogger::CrashLogger() {
  ring_clear();
}

CrashLogger::~CrashLogger() {
  close();
}

/* ---- Public API ---- */

bool CrashLogger::open(const char *log_path) {
  close();

  if (!log_path || log_path[0] == '\0') return false;

  std::FILE *fp = std::fopen(log_path, "a");
  if (!fp) return false;

  // Write a startup marker
  std::time_t now = std::time(nullptr);
  char time_buf[32];
  std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S",
                std::localtime(&now));

  std::fprintf(fp, "=== MemDBG Crash Log started at %s ===\n", time_buf);
  std::fflush(fp);

  std::lock_guard<std::mutex> lock(mutex_);
  file_      = static_cast<void *>(fp);
  file_open_ = true;
  enabled_.store(true);

  // Register signal handlers (once)
  if (s_instance == nullptr) {
    s_instance = this;
#if !defined(_WIN32)
    struct sigaction sa{};
    sa.sa_handler = CrashLogger::signal_handler;
    sa.sa_flags   = SA_RESETHAND;  // one-shot; default handler runs after us
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
#endif
  }

  return true;
}

void CrashLogger::close() {
  if (s_instance == this) {
    s_instance = nullptr;
  }

  std::lock_guard<std::mutex> lock(mutex_);

  if (file_open_ && file_ != nullptr) {
    auto *fp = static_cast<std::FILE *>(file_);

    // Flush any remaining ring entries
    ring_flush();

    std::time_t now = std::time(nullptr);
    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S",
                  std::localtime(&now));
    std::fprintf(fp, "=== MemDBG Crash Log closed at %s ===\n", time_buf);
    std::fclose(fp);
    file_      = nullptr;
    file_open_ = false;
  }
  enabled_.store(false);
}

void CrashLogger::log(const char *category, const char *message) {
  if (!enabled_.load()) return;
  if (!category) category = "general";
  if (!message) message = "";

  std::lock_guard<std::mutex> lock(mutex_);
  ring_push(category, message);

  // Flush immediately so data survives a hard crash.
  // The ring will be empty after this, so the signal handler
  // does NOT need to call ring_flush() — avoiding any race.
  ring_flush();
}

void CrashLogger::flush() {
  std::lock_guard<std::mutex> lock(mutex_);
  ring_flush();
}

bool CrashLogger::is_open() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return file_open_ && file_ != nullptr;
}

void CrashLogger::capture_console_lines(const std::vector<std::string> &lines,
                                        uint64_t &last_received,
                                        uint64_t current_received) {
  if (!enabled_.load()) return;
  if (lines.empty()) return;
  if (current_received <= last_received) return;

  // Capture ALL current ring entries.  The monotonic `current_received`
  // counter from UdpLogListener::stats() tells us new data arrived.
  // We write the full snapshot each time — duplicates may appear in the
  // file across frames, but no entries are ever lost.
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto &line : lines) {
    ring_push("console", line.c_str());
  }
  last_received = current_received;

  // Flush immediately so console logs survive a crash.
  ring_flush();
}

/* ---- Signal handler (async-signal-safe) ---- */

void CrashLogger::signal_handler(int signum) {
  CrashLogger *instance = s_instance;
  if (instance == nullptr) return;

  // Access file_ without mutex — safe in signal context since
  // log() flushes every entry immediately, so ring is always empty.
  auto *fp = static_cast<std::FILE *>(instance->file_);
  if (fp == nullptr) return;

  const char *signame = "UNKNOWN";
  switch (signum) {
  case SIGSEGV: signame = "SIGSEGV"; break;
  case SIGABRT: signame = "SIGABRT"; break;
  case SIGFPE:  signame = "SIGFPE";  break;
  case SIGILL:  signame = "SIGILL";  break;
  default: break;
  }

  // Use only async-signal-safe functions.  std::localtime is NOT safe
  // (can call malloc), so emit the crash time as a raw epoch value.
  char header[256];
  int header_len = std::snprintf(header, sizeof(header),
      "\n!!! CRASH DETECTED: signal %d (%s) at epoch %lld !!!\n",
      signum, signame, static_cast<long long>(std::time(nullptr)));

  if (header_len > 0) {
#if !defined(_WIN32)
    ::write(fileno(fp), header, static_cast<size_t>(header_len));
    ::fsync(fileno(fp));
#else
    std::fwrite(header, 1, static_cast<size_t>(header_len), fp);
    std::fflush(fp);
#endif
  }

  // Write footer and close the fd
  const char *footer = "=== End of crash log ===\n";
  size_t footer_len = std::strlen(footer);
#if !defined(_WIN32)
  ::write(fileno(fp), footer, footer_len);
  ::close(fileno(fp));
#else
  std::fwrite(footer, 1, footer_len, fp);
  std::fclose(fp);
#endif
  instance->file_      = nullptr;
  instance->file_open_ = false;

  // Exit without calling non-async-signal-safe functions.
  // SA_RESETHAND ensures if we return, the default handler runs.
  // _exit() is async-signal-safe and terminates immediately.
  _exit(128 + signum);
}

/* ---- Ring buffer internals ---- */

void CrashLogger::ring_push(const char *category, const char *message) {
  Entry &entry = ring_[ring_head_];

  entry.timestamp = std::time(nullptr);

  std::strncpy(entry.category, category, sizeof(entry.category) - 1U);
  entry.category[sizeof(entry.category) - 1U] = '\0';

  std::strncpy(entry.message, message, sizeof(entry.message) - 1U);
  entry.message[sizeof(entry.message) - 1U] = '\0';

  ring_head_ = (ring_head_ + 1U) % kRingCapacity;
  if (ring_count_ < kRingCapacity) {
    ring_count_++;
  }
}

void CrashLogger::ring_flush() {
  if (!file_open_ || file_ == nullptr) return;
  if (ring_count_ == 0U) return;

  auto *fp = static_cast<std::FILE *>(file_);

  const size_t oldest = (ring_head_ + kRingCapacity - ring_count_) % kRingCapacity;
  bool write_error = false;
  for (size_t i = 0; i < ring_count_; ++i) {
    const Entry &entry = ring_[(oldest + i) % kRingCapacity];

    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S",
                  std::localtime(&entry.timestamp));

    if (std::fprintf(fp, "[%s] [%s] %s\n",
                     time_buf, entry.category, entry.message) < 0) {
      write_error = true;
      break;
    }
  }

  // Only clear the ring if the write + flush succeeded
  if (std::fflush(fp) == 0 && !write_error) {
    ring_count_ = 0;
  }
}

void CrashLogger::ring_clear() {
  ring_head_  = 0;
  ring_count_ = 0;
}

} // namespace memdbg::frontend

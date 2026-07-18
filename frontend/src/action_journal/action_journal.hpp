/*
 * MemDBG - Action journal for structured user action recording.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * JSON-lines journal that records every user action so the last
 * actions survive a frontend crash.  Together with CrashLogger this
 * gives a complete picture of what happened before a crash.
 *
 * Session markers ("session_start" / "clean_shutdown") let the
 * frontend detect an unclean exit on next launch and offer to
 * pre-fill a GitHub issue with the recorded actions.
 */

#ifndef MEMDBG_FRONTEND_ACTION_JOURNAL_HPP
#define MEMDBG_FRONTEND_ACTION_JOURNAL_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace memdbg::frontend {

struct ActionJournalEntry {
  std::time_t timestamp = 0;
  std::string action;
  std::string detail;   // JSON object with key-value params
};

class ActionJournal {
public:
  ActionJournal();
  ~ActionJournal();

  ActionJournal(const ActionJournal &) = delete;
  ActionJournal &operator=(const ActionJournal &) = delete;

  // Open the journal file.  Call once at startup.
  // Returns false if the file cannot be created.
  bool open(const char *journal_path);

  // Close and flush the journal file.
  void close();

  // Record a user action. Thread-safe. Flushes to disk immediately.
  // `detail` should be a JSON object string, e.g. "{\"host\":\"192.168.1.100\",\"port\":9020}"
  void record(const char *action, const char *detail);

  // Write a session marker (session_start / clean_shutdown).
  // Called automatically by open()/close(), but can be called manually.
  void record_marker(const char *marker);

  // Enable / disable journaling at runtime.
  void set_enabled(bool enabled) { enabled_.store(enabled); }
  bool enabled() const { return enabled_.load(); }

  // True when the journal file is open and writable.
  bool is_open() const;

  // Truncate the active journal and start a fresh session atomically.
  bool clear();

  // Default journal path under app data dir.
  static std::filesystem::path default_path();

  // Load recent entries from an existing journal file (for crash review).
  // Returns true if the journal has a clean_shutdown marker.
  static bool load_recent(const std::filesystem::path &path,
                          std::vector<ActionJournalEntry> &out_entries,
                          size_t max_entries = 200,
                          bool *out_clean_shutdown = nullptr);

  // Build a GitHub issue URL pre-filled with crash details.
  // Uses the console_crash.yml template fields.
  static std::string build_crash_report_url(
      const std::vector<ActionJournalEntry> &actions,
      const char *version_string,
      const char *platform_name,
      bool anonymize = true,
      bool include_telemetry = true);

  // Escape a string for safe inclusion in a JSON string literal.
  // Escapes \", \\, and control characters (U+0000–U+001F).
  // Callers building manual JSON detail strings should wrap every
  // user-controlled value with this function.
  static std::string json_escape(const std::string &value);

private:
  mutable std::mutex mutex_;
  std::atomic_bool enabled_{false};

  void *file_ = nullptr;  // FILE* cast to void
  bool   file_open_ = false;
  std::filesystem::path path_;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_ACTION_JOURNAL_HPP */

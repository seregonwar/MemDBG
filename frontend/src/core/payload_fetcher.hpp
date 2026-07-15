/*
 * MemDBG - Payload fetcher: auto-download latest payload from GitHub releases.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PAYLOAD_FETCHER_HPP
#define MEMDBG_FRONTEND_PAYLOAD_FETCHER_HPP

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

#include "platform_utils.hpp"

namespace memdbg::frontend {

/* Result of a payload fetch / check operation. */
struct PayloadInfo {
  bool available = false;       /* true if a payload was found on GitHub */
  bool up_to_date = false;      /* true if local cache matches remote */
  bool downloaded = false;      /* true if a fresh download just completed */

  std::string tag_name;         /* e.g. "v1.5.0" */
  std::string asset_name;       /* e.g. "MemDBG-ps5.elf" */
  std::string download_url;     /* direct download URL */
  std::string local_path;       /* cached file on disk */
  int64_t asset_size = 0;       /* bytes (remote fingerprint for comparison) */
  int64_t local_size = 0;       /* bytes on disk (0 if not present) */

  std::string error;            /* last error (empty on success) */
};

/* Background worker that periodically checks GitHub releases for a
 * payload binary and downloads it when a new version is detected.
 *
 * Thread-safe: public methods lock internally.  The worker runs on its
 * own thread so the UI never blocks. */
class PayloadFetcher {
public:
  PayloadFetcher();
  ~PayloadFetcher();

  /* Start the background worker.  Safe to call multiple times (no-op
   * after the first call).  Pass the current payload binary name to
   * search for in the release assets (e.g. "MemDBG-"). */
  void start(const std::string &asset_filter);

  /* Stop the background worker and join its thread. */
  void stop();

  /* Trigger an immediate check (wakes the worker if sleeping). */
  void refresh();

  /* Get the latest payload info (thread-safe snapshot). */
  PayloadInfo info() const;

  /* True while the worker is performing a network operation. */
  bool busy() const { return busy_.load(); }

  /* True after the first check completed (whether or not a payload was found). */
  bool checked() const { return checked_.load(); }

  /* Whether auto-fetch is enabled (persisted setting). */
  bool auto_fetch_enabled() const { return auto_fetch_.load(); }
  void set_auto_fetch(bool enabled) { auto_fetch_.store(enabled); }

  /* UI thread calls this every frame.  Returns true once when the worker
   * has detected a new payload version (even if auto-fetch is off).
   * The caller should push a toast notification with the returned tag. */
  std::string take_notify() {
    if (!notify_available_.exchange(false)) return {};
    std::lock_guard<std::mutex> lock(mutex_);
    return notify_tag_;
  }

  /* Platform filter: "" = auto, "ps4", or "ps5". */
  std::string platform() const {
    std::lock_guard<std::mutex> lock(platform_mutex_);
    return platform_;
  }
  void set_platform(const std::string &p);

  /* Directory where payloads are cached. */
  static std::filesystem::path cache_dir();

private:
  void worker_loop();
  PayloadInfo check_now();

  std::atomic<bool> started_{false};
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> busy_{false};
  std::atomic<bool> checked_{false};
  std::atomic<bool> auto_fetch_{false};
  std::atomic<bool> refresh_requested_{false};
  std::atomic<bool> notify_available_{false};
  std::string notify_tag_;       /* protected by mutex_ */

  std::string asset_filter_;
  std::string platform_;        /* "", "ps4", or "ps5" */
  mutable std::mutex platform_mutex_;
  PayloadInfo info_;
  mutable std::mutex mutex_;
  std::thread worker_;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_PAYLOAD_FETCHER_HPP */

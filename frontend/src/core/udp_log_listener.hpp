/*
 * MemDBG - UDP log listener for the ImGui frontend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_UDP_LOG_LISTENER_HPP
#define MEMDBG_FRONTEND_UDP_LOG_LISTENER_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace memdbg::frontend {

struct UdpLogStats {
  uint64_t received  = 0;
  uint64_t dropped   = 0;   // socket-level loss (recv errors, buffer overflow)
  uint64_t evicted   = 0;   // lines pushed out of the ring buffer
  uint16_t port      = 0;
  int      bind_attempts = 0;
  int      ring_capacity  = 0;
};

class UdpLogListener {
public:
  UdpLogListener();
  ~UdpLogListener();

  UdpLogListener(const UdpLogListener &) = delete;
  UdpLogListener &operator=(const UdpLogListener &) = delete;

  // Start listening — retries bind up to 5 times with exponential backoff.
  // Returns true on success, sets last_error() on failure.
  bool start(uint16_t port);

  void stop();
  bool running() const;
  std::string last_error() const;
  UdpLogStats stats() const;

  // Returns a snapshot of buffered lines (oldest first).
  std::vector<std::string> snapshot() const;
  void clear();

private:
  void thread_main(uint16_t port);

  // ---- Ring buffer (O(1) insert, no mass-erase) ----
  static constexpr size_t kRingCapacity = 4096;
  std::string ring_[kRingCapacity];
  size_t      ring_head_  = 0;   // next write slot
  size_t      ring_count_ = 0;   // items currently stored

  void ring_push(std::string line);
  std::vector<std::string> ring_snapshot() const;
  void ring_clear();

  mutable std::mutex mutex_;
  std::condition_variable startup_cv_;
  std::thread thread_;
  std::atomic_bool running_{false};
  std::atomic_bool stop_requested_{false};
  std::string last_error_;
  bool startup_done_ = false;
  bool startup_ok_   = false;
  uint64_t received_ = 0;
  uint64_t dropped_  = 0;    // socket errors / overflow
  uint64_t evicted_  = 0;    // ring buffer evictions
  uint16_t port_     = 0;
  int      bind_attempts_ = 0;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_UDP_LOG_LISTENER_HPP */

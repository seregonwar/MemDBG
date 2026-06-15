/*
 * memDBG - UDP log listener for the ImGui frontend.
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
  uint64_t received = 0;
  uint64_t dropped = 0;
  uint16_t port = 0;
};

class UdpLogListener {
public:
  UdpLogListener();
  ~UdpLogListener();

  UdpLogListener(const UdpLogListener &) = delete;
  UdpLogListener &operator=(const UdpLogListener &) = delete;

  bool start(uint16_t port);
  void stop();
  bool running() const;
  std::string last_error() const;
  UdpLogStats stats() const;
  std::vector<std::string> snapshot() const;
  void clear();

private:
  void thread_main(uint16_t port);

  mutable std::mutex mutex_;
  std::condition_variable startup_cv_;
  std::vector<std::string> lines_;
  std::thread thread_;
  std::atomic_bool running_{false};
  std::atomic_bool stop_requested_{false};
  std::string last_error_;
  bool startup_done_ = false;
  bool startup_ok_ = false;
  uint64_t received_ = 0;
  uint64_t dropped_ = 0;
  uint16_t port_ = 0;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_UDP_LOG_LISTENER_HPP */

/*
 * MemDBG - UDP discovery client for auto-detecting nearby payloads.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP
#define MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "platform.hpp"

namespace memdbg::frontend {

struct DiscoveryConsole {
  std::string ip;
  uint16_t debug_port = 0;
  uint16_t udp_log_port = 0;
  uint32_t capabilities = 0;
  uint16_t platform_id = 0;
  std::string version;
  std::string name;
};

class DiscoveryClient {
public:
  DiscoveryClient() = default;
  ~DiscoveryClient();

  /* Broadcast a discovery ping and collect unicast replies for up to
   * timeout_seconds.  Returns true if the scan completed (even with no
   * replies), false on socket failure or cancellation. */
  bool discover(uint16_t discovery_port, double timeout_seconds,
                std::vector<DiscoveryConsole> &out, std::string &error);

  /* Cancel an in-progress discovery.  Safe to call from any thread.
   * Shuts down the socket so recvfrom() unblocks immediately. */
  void cancel();

  /* True after cancel() was called on the current discovery. */
  bool cancelled() const { return cancelled_.load(); }

private:
  std::atomic<bool> cancelled_{false};
  platform::socket_handle_t fd_ = platform::invalid_socket();
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP */

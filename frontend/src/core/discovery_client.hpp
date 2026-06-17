/*
 * MemDBG - UDP discovery client for auto-detecting nearby payloads.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP
#define MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP

#include <cstdint>
#include <string>
#include <vector>

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
  /* Broadcast a discovery ping and collect unicast replies for up to
   * timeout_seconds.  Returns true if the scan completed (even with no
   * replies), false on socket failure. */
  bool discover(uint16_t discovery_port, double timeout_seconds,
                std::vector<DiscoveryConsole> &out, std::string &error);
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_DISCOVERY_CLIENT_HPP */

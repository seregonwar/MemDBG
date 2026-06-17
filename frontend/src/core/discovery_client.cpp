/*
 * MemDBG - UDP discovery client implementation.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "discovery_client.hpp"

#include "memdbg/core/memdbg_protocol.h"
#include "platform.hpp"

#include <chrono>
#include <cstring>
#include <set>

namespace memdbg::frontend {

bool DiscoveryClient::discover(uint16_t discovery_port, double timeout_seconds,
                               std::vector<DiscoveryConsole> &out,
                               std::string &error) {
  out.clear();
  error.clear();

  if (!platform::socket_startup(&error)) {
    return false;
  }

  platform::socket_handle_t fd = platform::invalid_socket();

#if defined(_WIN32)
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
  fd = socket(AF_INET, SOCK_DGRAM, 0);
#endif

  if (!platform::socket_valid(fd)) {
    error = "discovery: socket failed: " +
            platform::socket_error_text(platform::socket_last_error_code());
    platform::socket_cleanup();
    return false;
  }

  platform::socket_set_reuse_addr(fd);
  if (!platform::socket_set_broadcast(fd)) {
    error = "discovery: broadcast not available: " +
            platform::socket_error_text(platform::socket_last_error_code());
    platform::socket_close(fd);
    platform::socket_cleanup();
    return false;
  }

  /* Bind to an ephemeral port so we can receive unicast replies. */
  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = INADDR_ANY;
  bind_addr.sin_port = 0;
  if (bind(fd, reinterpret_cast<const sockaddr *>(&bind_addr),
           sizeof(bind_addr)) != 0) {
    error = "discovery: bind failed: " +
            platform::socket_error_text(platform::socket_last_error_code());
    platform::socket_close(fd);
    platform::socket_cleanup();
    return false;
  }

  const uint32_t timeout_ms = static_cast<uint32_t>(
      std::max(100.0, timeout_seconds * 1000.0));
  platform::socket_set_recv_timeout(fd, timeout_ms);

  memdbg_discovery_ping_t ping{};
  ping.magic = MEMDBG_PACKET_MAGIC;
  ping.version = MEMDBG_PROTOCOL_VERSION;
  ping.reserved = 0;

  sockaddr_in broadcast_addr{};
  broadcast_addr.sin_family = AF_INET;
  broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
  broadcast_addr.sin_port = htons(discovery_port);

  if (sendto(fd, reinterpret_cast<const char *>(&ping), sizeof(ping), 0,
             reinterpret_cast<const sockaddr *>(&broadcast_addr),
             sizeof(broadcast_addr)) < 0) {
    error = "discovery: sendto failed: " +
            platform::socket_error_text(platform::socket_last_error_code());
    platform::socket_close(fd);
    platform::socket_cleanup();
    return false;
  }

  std::set<std::string> seen;
  const auto start = std::chrono::steady_clock::now();
  const auto end = start + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < end) {
    memdbg_discovery_response_t resp{};
    sockaddr_in sender{};
    platform::socklen_type sender_len = sizeof(sender);

    int n = platform::socket_recvfrom(
        fd, &resp, sizeof(resp), reinterpret_cast<sockaddr *>(&sender),
        &sender_len);

    if (n < 0) {
      const int code = platform::socket_last_error_code();
      if (platform::socket_error_would_block(code) ||
          platform::socket_error_interrupted(code)) {
        continue;
      }
      break;
    }

    if (static_cast<size_t>(n) < sizeof(resp) ||
        resp.magic != MEMDBG_PACKET_MAGIC ||
        resp.protocol_version != MEMDBG_PROTOCOL_VERSION) {
      continue;
    }

    char ip_str[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &sender.sin_addr, ip_str, sizeof(ip_str)) ==
        nullptr) {
      continue;
    }

    if (!seen.insert(ip_str).second)
      continue;

    DiscoveryConsole console;
    console.ip = ip_str;
    console.debug_port = resp.debug_port;
    console.udp_log_port = resp.udp_log_port;
    console.capabilities = resp.capabilities;
    console.platform_id = resp.platform_id;
    console.version.assign(resp.version, strnlen(resp.version, sizeof(resp.version)));
    console.name.assign(resp.name, strnlen(resp.name, sizeof(resp.name)));
    out.push_back(std::move(console));
  }

  platform::socket_close(fd);
  platform::socket_cleanup();
  return true;
}

} // namespace memdbg::frontend

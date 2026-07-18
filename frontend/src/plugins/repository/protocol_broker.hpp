/*
 * MemDBG - Loopback protocol broker for GUI plugins.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_FRONTEND_PLUGIN_PROTOCOL_BROKER_HPP
#define MEMDBG_FRONTEND_PLUGIN_PROTOCOL_BROKER_HPP

#include "core/client/client_pool.hpp"
#include "core/platform.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

namespace memdbg::frontend::plugins {

class ProtocolBroker {
public:
  ProtocolBroker() = default;
  ~ProtocolBroker();

  ProtocolBroker(const ProtocolBroker &) = delete;
  ProtocolBroker &operator=(const ProtocolBroker &) = delete;

  bool start(ClientPool &pool);
  void stop();
  uint16_t port() const { return port_; }
  bool running() const { return running_.load(); }

private:
  void run();
  void serve_one(platform::socket_handle_t fd);
  std::shared_ptr<Client> lease_for(uint16_t command) const;

  ClientPool *pool_ = nullptr;
  std::atomic<bool> running_{false};
  std::atomic<platform::socket_handle_t> listen_fd_{
      platform::invalid_socket()};
  std::atomic<platform::socket_handle_t> active_fd_{
      platform::invalid_socket()};
  std::mutex active_client_mutex_;
  std::shared_ptr<Client> active_client_;
  uint16_t port_ = 0U;
  bool socket_runtime_active_ = false;
  std::thread thread_;
};

} // namespace memdbg::frontend::plugins

#endif

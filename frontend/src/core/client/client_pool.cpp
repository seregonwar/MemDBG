/*
 * MemDBG - Connection pool for parallel client connections.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "client_pool.hpp"

#include <future>

namespace memdbg::frontend {

ClientPool::ClientPool()
  : control_(std::make_unique<Client>())
  , memory_(nullptr)
  , scan_(nullptr)
  , poll_(nullptr)
{}

ClientPool::~ClientPool() {
  disconnect_all();
}

void ClientPool::disconnect() {
  disconnect_all();
}

void ClientPool::cancel_all_pending_io() {
  if (control_) control_->cancel_pending_io();
  if (memory_)  memory_->cancel_pending_io();
  if (scan_)    scan_->cancel_pending_io();
  if (poll_)    poll_->cancel_pending_io();
}

void ClientPool::connect_additional_roles_async(const std::string &host,
                                                 uint16_t port,
                                                 uint32_t timeout_ms) {
  if (roles_pending_.exchange(true)) return; /* already in progress */
  pending_host_       = host;
  pending_port_       = port;
  pending_timeout_ms_ = timeout_ms;

  /* Launch a background thread to connect the extra roles.
   * The polling code in connection.cpp checks roles_active_ to
   * know when setup is complete.  The thread is stored so that
   * disconnect_all() can join it on shutdown. */
  role_thread_ = std::thread([this]() {
    auto conn = [this](std::unique_ptr<Client> &out,
                       const char *label) {
      /* If disconnect_all() was called before we got here, bail out. */
      if (!roles_pending_.load()) return;
      auto c = std::make_unique<Client>();
      if (c->connect_to(pending_host_, pending_port_,
                        pending_timeout_ms_)) {
        out = std::move(c);
      }
    };

    conn(memory_, "pool-memory");
    conn(scan_,   "pool-scan");
    conn(poll_,   "pool-poll");

    if (roles_pending_.load()) {
      roles_active_.store(true);
      roles_pending_.store(false);
    }
  });
}

void ClientPool::disconnect_all() {
  /* Signal the background thread to stop before we reset the pointers. */
  roles_pending_.store(false);
  roles_active_.store(false);

  if (role_thread_.joinable()) role_thread_.join();

  if (control_) { control_->disconnect(); }
  if (memory_)  { memory_->disconnect();  memory_.reset(); }
  if (scan_)    { scan_->disconnect();    scan_.reset(); }
  if (poll_)    { poll_->disconnect();    poll_.reset(); }
}

} // namespace memdbg::frontend

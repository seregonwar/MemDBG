/*
 * MemDBG - Connection pool for parallel client connections.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The ClientPool wraps a primary "control" Client and optionally manages
 * additional parallel connections (Memory, Scan, Poll) for better
 * throughput.  All existing code accesses the primary connection via
 * pool.control() and continues to work unchanged.
 */

#ifndef MEMDBG_FRONTEND_CLIENT_POOL_HPP
#define MEMDBG_FRONTEND_CLIENT_POOL_HPP

#include "memdbg_client.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace memdbg::frontend {

class ClientPool {
public:
  ClientPool();
  ~ClientPool();

  ClientPool(const ClientPool &) = delete;
  ClientPool &operator=(const ClientPool &) = delete;

  /* ---- Primary control connection ---- */

  /** Returns the primary control Client.  This is the only connection
   *  used for protocol operations; additional pool roles are transparent. */
  Client &control() { return *control_; }
  const Client &control() const { return *control_; }

  /** Disconnect all pooled connections (control + extras). */
  void disconnect();

  /** Cancel pending I/O on all pooled connections. */
  void cancel_all_pending_io();

  /* ---- Additional role connections (parallel memory/scan/poll) ---- */

  /** Asynchronously connect additional roles (memory, scan, poll).
   *  Called once after the control connection has established hello. */
  void connect_additional_roles_async(const std::string &host,
                                      uint16_t port,
                                      uint32_t timeout_ms);

  /** True if additional role connections have been set up. */
  bool has_extra_roles() const { return roles_active_; }

  /** Access individual role connections (may be null if not connected). */
  Client *memory_client() { return memory_.get(); }
  Client *scan_client() { return scan_.get(); }
  Client *poll_client() { return poll_.get(); }

private:
  void disconnect_all();

  std::unique_ptr<Client> control_;
  std::unique_ptr<Client> memory_;
  std::unique_ptr<Client> scan_;
  std::unique_ptr<Client> poll_;

  std::atomic<bool> roles_active_{false};
  std::atomic<bool> roles_pending_{false};

  std::thread role_thread_;                /* background connector thread */

  /* Async state for connect_additional_roles_async */
  std::string pending_host_;
  uint16_t pending_port_ = 0;
  uint32_t pending_timeout_ms_ = 0;
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CLIENT_POOL_HPP */

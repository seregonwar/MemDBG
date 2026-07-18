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
#include <array>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace memdbg::frontend {

class ClientPool {
public:
  ClientPool();
  ~ClientPool();

  ClientPool(const ClientPool &) = delete;
  ClientPool &operator=(const ClientPool &) = delete;

  /* ---- Primary control connection ---- */

  /** Returns the primary control Client.  Legacy call sites use this channel;
   *  high-throughput paths acquire one of the role leases below. */
  Client &control() { return *control_; }
  const Client &control() const { return *control_; }

  /** Hold a role connection for the full duration of an asynchronous job.
   *  Falls back to the persistent control connection until that role is ready. */
  std::shared_ptr<Client> memory_lease() const;
  std::shared_ptr<Client> scan_lease() const;
  std::shared_ptr<Client> poll_lease() const;
  std::shared_ptr<Client> control_lease() const { return control_; }

  /** Disconnect all pooled connections (control + extras). */
  void disconnect();

  /** Cancel pending I/O on all pooled connections. */
  void cancel_all_pending_io();

  /* ---- Additional role connections (parallel memory/scan/poll) ---- */

  /** Asynchronously connect additional roles (memory, scan, poll).
   *  Called once after the control connection has established hello. */
  void connect_additional_roles_async(const std::string &host,
                                      uint16_t port,
                                      uint32_t timeout_ms,
                                      const HelloInfo &expected_hello);

  /** True if additional role connections have been set up. */
  bool has_extra_roles() const { return roles_active_; }

  /** Access individual role connections (may be null if not connected). */
  std::shared_ptr<Client> memory_client() const;
  std::shared_ptr<Client> scan_client() const;
  std::shared_ptr<Client> poll_client() const;

private:
  void disconnect_all();

  std::shared_ptr<Client> control_;
  std::shared_ptr<Client> memory_;
  std::shared_ptr<Client> scan_;
  std::shared_ptr<Client> poll_;
  std::array<std::shared_ptr<Client>, 3> connecting_{};

  std::atomic<bool> roles_active_{false};
  std::atomic<bool> roles_pending_{false};
  std::atomic<uint64_t> role_generation_{0};
  mutable std::mutex roles_mutex_;
  std::condition_variable roles_cv_;

  std::thread role_thread_;                /* background connector thread */
};

} // namespace memdbg::frontend

#endif /* MEMDBG_FRONTEND_CLIENT_POOL_HPP */

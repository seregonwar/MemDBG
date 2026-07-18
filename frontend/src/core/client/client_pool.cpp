/*
 * MemDBG - Connection pool for parallel client connections.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "client_pool.hpp"

#include <chrono>

namespace memdbg::frontend {

ClientPool::ClientPool()
  : control_(std::make_shared<Client>())
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
  std::shared_ptr<Client> memory;
  std::shared_ptr<Client> scan;
  std::shared_ptr<Client> poll;
  std::array<std::shared_ptr<Client>, 3> connecting;
  {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    memory = memory_;
    scan = scan_;
    poll = poll_;
    connecting = connecting_;
  }
  if (memory) memory->cancel_pending_io();
  if (scan) scan->cancel_pending_io();
  if (poll) poll->cancel_pending_io();
  for (const auto &client : connecting)
    if (client) client->cancel_pending_io();
}

void ClientPool::connect_additional_roles_async(const std::string &host,
                                                 uint16_t port,
                                                 uint32_t timeout_ms,
                                                 const HelloInfo &expected_hello) {
  if (roles_pending_.exchange(true)) return; /* already in progress */

  /* Invalidate and wake an older maintenance thread before joining it. */
  const uint64_t generation = role_generation_.fetch_add(1U) + 1U;
  roles_cv_.notify_all();

  /* A previous maintenance ping may be blocked in network I/O. Closing its
     sockets makes replacement deterministic instead of waiting for 3 timeouts. */
  std::array<std::shared_ptr<Client>, 6> previous;
  {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    previous = {memory_, scan_, poll_, connecting_[0], connecting_[1],
                connecting_[2]};
  }
  for (const auto &client : previous)
    if (client) client->cancel_pending_io();

  /* A completed std::thread remains joinable. Reap it before assigning a
   * replacement, otherwise std::thread::operator= terminates the process. */
  if (role_thread_.joinable()) role_thread_.join();

  std::shared_ptr<Client> old_memory;
  std::shared_ptr<Client> old_scan;
  std::shared_ptr<Client> old_poll;
  {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    old_memory = std::move(memory_);
    old_scan = std::move(scan_);
    old_poll = std::move(poll_);
  }
  if (old_memory) old_memory->disconnect();
  if (old_scan) old_scan->disconnect();
  if (old_poll) old_poll->disconnect();
  roles_active_.store(false);
  /* Launch a background thread to connect the extra roles.
   * The polling code in connection.cpp checks roles_active_ to
   * know when setup is complete.  The thread is stored so that
   * disconnect_all() can join it on shutdown. */
  role_thread_ = std::thread([this, host, port, timeout_ms, expected_hello,
                              generation]() {
    auto current = [this, generation]() {
      return role_generation_.load() == generation;
    };
    auto conn = [this, &current, &host, port, timeout_ms, &expected_hello,
                 generation](size_t index, std::shared_ptr<Client> *out) {
      if (!current()) return;
      auto client = std::make_shared<Client>();
      client->set_socket_timeout_ms(timeout_ms);
      {
        std::lock_guard<std::mutex> lock(roles_mutex_);
        if (!current()) return;
        connecting_[index] = client;
      }

      HelloInfo hello;
      const bool connected =
          client->connect_to(host, port, timeout_ms) && client->hello(hello);
      const bool compatible = connected &&
          hello.protocol_version == expected_hello.protocol_version &&
          hello.feature_level == expected_hello.feature_level &&
          hello.platform_id == expected_hello.platform_id &&
          hello.capabilities == expected_hello.capabilities &&
          hello.version == expected_hello.version;

      {
        std::lock_guard<std::mutex> lock(roles_mutex_);
        if (connecting_[index] == client) connecting_[index].reset();
        if (compatible && current() && role_generation_.load() == generation)
          *out = client;
      }
      if (!compatible || !current()) client->disconnect();
    };

    std::thread memory_connector(conn, 0U, &memory_);
    std::thread scan_connector(conn, 1U, &scan_);
    std::thread poll_connector(conn, 2U, &poll_);
    memory_connector.join();
    scan_connector.join();
    poll_connector.join();

    if (current()) {
      bool any_connected = false;
      {
        std::lock_guard<std::mutex> lock(roles_mutex_);
        any_connected = static_cast<bool>(memory_ || scan_ || poll_);
      }
      roles_active_.store(any_connected);
      roles_pending_.store(false);
    }

    /* Keep role sockets alive below the daemon's default 30-second idle
       timeout. Client::ping serializes with an in-flight role request, so it
       cannot interleave bytes into another command. */
    while (current()) {
      std::shared_ptr<Client> memory;
      std::shared_ptr<Client> scan;
      std::shared_ptr<Client> poll;
      {
        std::unique_lock<std::mutex> lock(roles_mutex_);
        if (roles_cv_.wait_for(lock, std::chrono::seconds(10),
                               [&current]() { return !current(); }))
          break;
        memory = memory_;
        scan = scan_;
        poll = poll_;
      }

      std::array<std::shared_ptr<Client>, 3> clients = {memory, scan, poll};
      std::array<bool, 3> healthy = {true, true, true};
      std::array<std::thread, 3> ping_threads;
      std::array<bool, 3> ping_started = {false, false, false};
      for (size_t i = 0U; i < clients.size(); ++i) {
        if (!clients[i]) continue;
        ping_threads[i] = std::thread([&clients, &healthy, i]() {
          healthy[i] = clients[i]->ping();
        });
        ping_started[i] = true;
      }
      for (size_t i = 0U; i < ping_threads.size(); ++i)
        if (ping_started[i]) ping_threads[i].join();

      std::array<bool, 3> reconnect = {false, false, false};
      {
        std::lock_guard<std::mutex> lock(roles_mutex_);
        if (!healthy[0] && memory_ == memory) memory_.reset();
        if (!healthy[1] && scan_ == scan) scan_.reset();
        if (!healthy[2] && poll_ == poll) poll_.reset();
        reconnect = {!memory_, !scan_, !poll_};
        roles_active_.store(static_cast<bool>(memory_ || scan_ || poll_));
      }

      /* Restore failed roles without making healthy channels wait for a
         sequence of connection timeouts. */
      std::array<std::thread, 3> reconnect_threads;
      std::array<bool, 3> reconnect_started = {false, false, false};
      std::array<std::shared_ptr<Client> *, 3> outputs = {
          &memory_, &scan_, &poll_};
      for (size_t i = 0U; i < reconnect.size(); ++i) {
        if (!reconnect[i] || !current()) continue;
        reconnect_threads[i] = std::thread(conn, i, outputs[i]);
        reconnect_started[i] = true;
      }
      for (size_t i = 0U; i < reconnect_threads.size(); ++i)
        if (reconnect_started[i]) reconnect_threads[i].join();
      if (current()) {
        std::lock_guard<std::mutex> lock(roles_mutex_);
        roles_active_.store(static_cast<bool>(memory_ || scan_ || poll_));
      }
    }
  });
}

std::shared_ptr<Client> ClientPool::memory_client() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return memory_;
}

std::shared_ptr<Client> ClientPool::scan_client() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return scan_;
}

std::shared_ptr<Client> ClientPool::poll_client() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return poll_;
}

std::shared_ptr<Client> ClientPool::memory_lease() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return memory_ && memory_->connected() ? memory_ : control_;
}

std::shared_ptr<Client> ClientPool::scan_lease() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return scan_ && scan_->connected() ? scan_ : control_;
}

std::shared_ptr<Client> ClientPool::poll_lease() const {
  std::lock_guard<std::mutex> lock(roles_mutex_);
  return poll_ && poll_->connected() ? poll_ : control_;
}

void ClientPool::disconnect_all() {
  /* Signal the background thread to stop before we reset the pointers. */
  roles_pending_.store(false);
  roles_active_.store(false);
  role_generation_.fetch_add(1U);
  roles_cv_.notify_all();

  cancel_all_pending_io();

  if (role_thread_.joinable()) role_thread_.join();

  std::shared_ptr<Client> memory;
  std::shared_ptr<Client> scan;
  std::shared_ptr<Client> poll;
  {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    memory = std::move(memory_);
    scan = std::move(scan_);
    poll = std::move(poll_);
    connecting_.fill(nullptr);
  }
  if (memory) memory->disconnect();
  if (scan) scan->disconnect();
  if (poll) poll->disconnect();
  if (control_) control_->disconnect();
}

} // namespace memdbg::frontend

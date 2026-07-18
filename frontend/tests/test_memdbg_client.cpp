/*
 * MemDBG - Client connection cancellation tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"
#include "client_pool.hpp"
#include "plugins/repository/protocol_broker.hpp"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <future>
#include <vector>
#include <mutex>
#include <string>
#include <thread>

namespace memdbg::frontend {
namespace {

bool socket_read_exact(platform::socket_handle_t fd, void *data, size_t size) {
  auto *cursor = static_cast<uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    const int received = platform::socket_recv(fd, cursor + total, size - total);
    if (received <= 0) return false;
    total += static_cast<size_t>(received);
  }
  return true;
}

bool socket_write_all(platform::socket_handle_t fd, const void *data,
                      size_t size) {
  const auto *cursor = static_cast<const uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    const int sent = platform::socket_send(fd, cursor + total, size - total);
    if (sent <= 0) return false;
    total += static_cast<size_t>(sent);
  }
  return true;
}

class HelloTestServer {
public:
  HelloTestServer() {
    std::string error;
    if (!platform::socket_startup(&error)) {
      error_ = error;
      return;
    }
    runtime_active_ = true;
    listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::socket_valid(listener_)) {
      error_ = "listener socket failed";
      return;
    }
    (void)platform::socket_set_reuse_addr(listener_);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener_, reinterpret_cast<sockaddr *>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener_, 2) != 0) {
      error_ = "listener bind/listen failed";
      return;
    }

    platform::socklen_type length =
        static_cast<platform::socklen_type>(sizeof(address));
    if (::getsockname(listener_, reinterpret_cast<sockaddr *>(&address),
                      &length) != 0) {
      error_ = "listener getsockname failed";
      return;
    }
    port_ = ntohs(address.sin_port);
    worker_ = std::thread(&HelloTestServer::run, this);
  }

  ~HelloTestServer() {
    release_first();
    if (platform::socket_valid(listener_)) {
      platform::socket_shutdown_both(listener_);
      platform::socket_close(listener_);
      listener_ = platform::invalid_socket();
    }
    if (worker_.joinable()) worker_.join();
    if (runtime_active_) platform::socket_cleanup();
  }

  HelloTestServer(const HelloTestServer &) = delete;
  HelloTestServer &operator=(const HelloTestServer &) = delete;

  bool valid() const { return error_.empty() && port_ != 0; }
  const std::string &error() const { return error_; }
  uint16_t port() const { return port_; }

  bool wait_for_first_request(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, timeout, [this]() { return first_request_; });
  }

  void release_first() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      release_first_ = true;
    }
    cv_.notify_all();
  }

  bool served_reconnect() const { return served_reconnect_.load(); }

private:
  platform::socket_handle_t accept_client() {
    sockaddr_in peer{};
    platform::socklen_type length =
        static_cast<platform::socklen_type>(sizeof(peer));
    return ::accept(listener_, reinterpret_cast<sockaddr *>(&peer), &length);
  }

  bool read_hello_request(platform::socket_handle_t fd,
                          memdbg_packet_header_t &request) {
    return socket_read_exact(fd, &request, sizeof(request)) &&
           request.magic == MEMDBG_PACKET_MAGIC &&
           request.version == MEMDBG_PROTOCOL_VERSION &&
           request.command == MEMDBG_CMD_HELLO && request.length == 0;
  }

  void run() {
    platform::socket_handle_t first = accept_client();
    memdbg_packet_header_t first_request{};
    if (!platform::socket_valid(first) ||
        !read_hello_request(first, first_request)) {
      if (platform::socket_valid(first)) platform::socket_close(first);
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      first_request_ = true;
    }
    cv_.notify_all();
    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, [this]() { return release_first_; });
    }
    platform::socket_close(first);

    platform::socket_handle_t second = accept_client();
    memdbg_packet_header_t request{};
    if (!platform::socket_valid(second) || !read_hello_request(second, request)) {
      if (platform::socket_valid(second)) platform::socket_close(second);
      return;
    }

    memdbg_hello_response_t hello{};
    hello.protocol_version = MEMDBG_PROTOCOL_VERSION;
    hello.platform_id = MEMDBG_PLATFORM_HOST;
    hello.debug_port = port_;
    std::memcpy(hello.version, "0.2.0", 6U);
    std::memcpy(hello.name, "test", 5U);

    memdbg_response_header_t response{};
    response.magic = MEMDBG_PACKET_MAGIC;
    response.version = MEMDBG_PROTOCOL_VERSION;
    response.command = MEMDBG_CMD_HELLO;
    response.request_id = request.request_id;
    response.status = MEMDBG_OK;
    response.length = sizeof(hello);
    served_reconnect_ =
        socket_write_all(second, &response, sizeof(response)) &&
        socket_write_all(second, &hello, sizeof(hello));
    platform::socket_close(second);
  }

  platform::socket_handle_t listener_ = platform::invalid_socket();
  bool runtime_active_ = false;
  uint16_t port_ = 0;
  std::string error_;
  std::thread worker_;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  bool first_request_ = false;
  bool release_first_ = false;
  std::atomic<bool> served_reconnect_{false};
};

bool run_cancel_reconnect_cycle(Client &client, int cycle) {
  HelloTestServer server;
  if (!server.valid()) {
    std::printf("  FAIL  cycle %d server: %s\n", cycle,
                server.error().c_str());
    return false;
  }

  auto attempt = std::async(std::launch::async, [&client, &server]() {
    HelloInfo hello;
    return client.connect_to("127.0.0.1", server.port(), 1000U) &&
           client.hello(hello);
  });
  if (!server.wait_for_first_request(std::chrono::seconds(2))) {
    std::printf("  FAIL  cycle %d did not receive first HELLO\n", cycle);
    server.release_first();
    attempt.wait();
    return false;
  }

  client.cancel_pending_io();
  const bool cancelled_promptly =
      attempt.wait_for(std::chrono::milliseconds(750)) ==
      std::future_status::ready;
  server.release_first();
  const bool cancelled = cancelled_promptly && !attempt.get() &&
                         !client.connected();

  HelloInfo hello;
  const bool reconnected =
      client.connect_to("127.0.0.1", server.port(), 1000U) &&
      client.hello(hello) && hello.version == "0.2.0";
  client.disconnect();
  const bool passed = cancelled && reconnected && server.served_reconnect();
  std::printf("  %s  cancel/reconnect cycle %d\n",
              passed ? "PASS" : "FAIL", cycle);
  return passed;
}

class PoolTestServer {
public:
  PoolTestServer() {
    std::string error;
    if (!platform::socket_startup(&error)) return;
    runtime_active_ = true;
    listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::socket_valid(listener_)) return;
    (void)platform::socket_set_reuse_addr(listener_);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener_, reinterpret_cast<sockaddr *>(&address),
               sizeof(address)) != 0 || ::listen(listener_, 8) != 0)
      return;
    platform::socklen_type size =
        static_cast<platform::socklen_type>(sizeof(address));
    if (::getsockname(listener_, reinterpret_cast<sockaddr *>(&address),
                      &size) != 0)
      return;
    port_ = ntohs(address.sin_port);
    worker_ = std::thread(&PoolTestServer::accept_loop, this);
  }

  ~PoolTestServer() {
    stopped_.store(true);
    if (platform::socket_valid(listener_)) {
      platform::socket_shutdown_both(listener_);
      platform::socket_close(listener_);
      listener_ = platform::invalid_socket();
    }
    if (worker_.joinable()) worker_.join();
    std::vector<std::thread> clients;
    {
      std::lock_guard<std::mutex> lock(client_mutex_);
      clients.swap(clients_);
    }
    for (auto &thread : clients)
      if (thread.joinable()) thread.join();
    if (runtime_active_) platform::socket_cleanup();
  }

  bool valid() const { return port_ != 0; }
  uint16_t port() const { return port_; }
  uint32_t hello_count() const { return hello_count_.load(); }

private:
  void accept_loop() {
    while (!stopped_.load()) {
      sockaddr_in peer{};
      platform::socklen_type size =
          static_cast<platform::socklen_type>(sizeof(peer));
      auto fd = ::accept(listener_, reinterpret_cast<sockaddr *>(&peer), &size);
      if (!platform::socket_valid(fd)) break;
      std::lock_guard<std::mutex> lock(client_mutex_);
      clients_.emplace_back(&PoolTestServer::serve, this, fd);
    }
  }

  void serve(platform::socket_handle_t fd) {
    while (!stopped_.load()) {
      memdbg_packet_header_t request{};
      if (!socket_read_exact(fd, &request, sizeof(request))) break;
      if (request.length != 0U) {
        std::vector<uint8_t> discard(request.length);
        if (!socket_read_exact(fd, discard.data(), discard.size())) break;
      }
      memdbg_response_header_t response{};
      response.magic = MEMDBG_PACKET_MAGIC;
      response.version = MEMDBG_PROTOCOL_VERSION;
      response.command = request.command;
      response.request_id = request.request_id;
      response.status = MEMDBG_OK;
      if (request.command == MEMDBG_CMD_HELLO) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        memdbg_hello_response_t hello{};
        hello.protocol_version = MEMDBG_PROTOCOL_VERSION;
        hello.platform_id = MEMDBG_PLATFORM_HOST;
        hello.capabilities = 0x1234U;
        hello.debug_port = port_;
        std::memcpy(hello.version, "pool-test", 10U);
        std::memcpy(hello.name, "pool", 5U);
        response.length = sizeof(hello);
        if (!socket_write_all(fd, &response, sizeof(response)) ||
            !socket_write_all(fd, &hello, sizeof(hello)))
          break;
        hello_count_.fetch_add(1U);
      } else if (request.command == MEMDBG_CMD_PING) {
        if (!socket_write_all(fd, &response, sizeof(response))) break;
      } else if (request.command == MEMDBG_CMD_PROCESS_MAPS_V2) {
        /* Older deployed payloads reported unknown opcodes as PROTOCOL rather
           than UNSUPPORTED. */
        response.status = MEMDBG_ERR_PROTOCOL;
        if (!socket_write_all(fd, &response, sizeof(response))) break;
      } else if (request.command == MEMDBG_CMD_PROCESS_MAPS) {
        std::vector<uint8_t> payload(sizeof(uint32_t) +
                                     sizeof(memdbg_map_entry_t));
        const uint32_t count = 1U;
        memdbg_map_entry_t entry{};
        entry.start = 0x1000U;
        entry.end = 0x3000U;
        entry.protection = MEMDBG_MAP_PROT_READ;
        std::memcpy(payload.data(), &count, sizeof(count));
        std::memcpy(payload.data() + sizeof(count), &entry, sizeof(entry));
        response.length = static_cast<uint32_t>(payload.size());
        if (!socket_write_all(fd, &response, sizeof(response)) ||
            !socket_write_all(fd, payload.data(), payload.size()))
          break;
      } else {
        response.status = MEMDBG_ERR_UNSUPPORTED;
        if (!socket_write_all(fd, &response, sizeof(response))) break;
      }
    }
    platform::socket_close(fd);
  }

  platform::socket_handle_t listener_ = platform::invalid_socket();
  bool runtime_active_ = false;
  uint16_t port_ = 0;
  std::atomic<bool> stopped_{false};
  std::atomic<uint32_t> hello_count_{0U};
  std::thread worker_;
  std::mutex client_mutex_;
  std::vector<std::thread> clients_;
};

bool run_pool_parallel_roles_test() {
  PoolTestServer server;
  if (!server.valid()) return false;
  HelloInfo expected;
  expected.protocol_version = MEMDBG_PROTOCOL_VERSION;
  expected.platform_id = MEMDBG_PLATFORM_HOST;
  expected.capabilities = 0x1234U;
  expected.version = "pool-test";

  ClientPool pool;
  const auto start = std::chrono::steady_clock::now();
  pool.connect_additional_roles_async("127.0.0.1", server.port(), 1000U,
                                      expected);
  const auto deadline = start + std::chrono::seconds(3);
  while (!pool.has_extra_roles() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);
  const bool first = pool.memory_client() && pool.scan_client() &&
                     pool.poll_client() && server.hello_count() == 3U &&
                     elapsed < std::chrono::milliseconds(500);

  pool.connect_additional_roles_async("127.0.0.1", server.port(), 1000U,
                                      expected);
  const auto second_deadline = std::chrono::steady_clock::now() +
                               std::chrono::seconds(3);
  while ((!pool.has_extra_roles() || server.hello_count() < 6U) &&
         std::chrono::steady_clock::now() < second_deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const bool second = pool.memory_client() && pool.scan_client() &&
                      pool.poll_client() && server.hello_count() == 6U;
  pool.disconnect();
  std::printf("  %s  parallel role setup (%lld ms) and reconnect\n",
              first && second ? "PASS" : "FAIL",
              static_cast<long long>(elapsed.count()));
  return first && second;
}

bool broker_ping(uint16_t port, uint32_t request_id) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(fd)) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0) {
    platform::socket_close(fd);
    return false;
  }
  memdbg_packet_header_t request{};
  request.magic = MEMDBG_PACKET_MAGIC;
  request.version = MEMDBG_PROTOCOL_VERSION;
  request.command = MEMDBG_CMD_PING;
  request.request_id = request_id;
  memdbg_response_header_t response{};
  const bool ok = socket_write_all(fd, &request, sizeof(request)) &&
                  socket_read_exact(fd, &response, sizeof(response)) &&
                  response.magic == MEMDBG_PACKET_MAGIC &&
                  response.command == MEMDBG_CMD_PING &&
                  response.request_id == request_id &&
                  response.status == MEMDBG_OK && response.length == 0U;
  platform::socket_close(fd);
  return ok;
}

bool broker_rejects_oversized_frame(uint16_t port) {
  auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(fd)) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0) {
    platform::socket_close(fd);
    return false;
  }
  memdbg_packet_header_t request{};
  request.magic = MEMDBG_PACKET_MAGIC;
  request.version = MEMDBG_PROTOCOL_VERSION;
  request.command = MEMDBG_CMD_MEMORY_WRITE;
  request.request_id = 0xA5A5U;
  request.length = MEMDBG_PROTOCOL_MAX_PACKET + 1U;
  memdbg_response_header_t response{};
  const bool ok = socket_write_all(fd, &request, sizeof(request)) &&
                  socket_read_exact(fd, &response, sizeof(response)) &&
                  response.magic == MEMDBG_PACKET_MAGIC &&
                  response.command == request.command &&
                  response.request_id == request.request_id &&
                  response.status == MEMDBG_ERR_PROTOCOL &&
                  response.length == 0U;
  platform::socket_close(fd);
  return ok;
}

bool run_plugin_broker_reuse_test() {
  PoolTestServer server;
  if (!server.valid()) return false;
  ClientPool pool;
  HelloInfo hello;
  if (!pool.control().connect_to("127.0.0.1", server.port(), 1000U) ||
      !pool.control().hello(hello))
    return false;

  pool.connect_additional_roles_async("127.0.0.1", server.port(), 1000U,
                                      hello);
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
  while ((!pool.memory_client() || !pool.scan_client() || !pool.poll_client()) &&
         std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

  plugins::ProtocolBroker broker;
  bool ok = server.hello_count() == 4U && broker.start(pool);
  for (uint32_t i = 1U; ok && i <= 16U; ++i)
    ok = broker_ping(broker.port(), i);
  ok = ok && broker_rejects_oversized_frame(broker.port());
  ok = ok && server.hello_count() == 4U;
  broker.stop();
  pool.disconnect();
  std::printf("  %s  plugin broker reuses four-session pool and rejects oversized frames\n",
              ok ? "PASS" : "FAIL");
  return ok;
}

bool run_legacy_maps_fallback_test() {
  PoolTestServer server;
  if (!server.valid()) return false;
  Client client;
  HelloInfo hello;
  std::vector<MapEntry> maps;
  const bool ok = client.connect_to("127.0.0.1", server.port(), 1000U) &&
                  client.hello(hello) && client.process_maps(42, maps) &&
                  maps.size() == 1U && maps[0].start == 0x1000U &&
                  maps[0].end == 0x3000U;
  client.disconnect();
  std::printf("  %s  Maps V2 falls back from legacy PROTOCOL status\n",
              ok ? "PASS" : "FAIL");
  return ok;
}

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Client Cancellation Tests ===\n");
  Client client;
  int failed = 0;
  if (!run_cancel_reconnect_cycle(client, 1)) ++failed;
  if (!run_cancel_reconnect_cycle(client, 2)) ++failed;
  if (!run_pool_parallel_roles_test()) ++failed;
  if (!run_plugin_broker_reuse_test()) ++failed;
  if (!run_legacy_maps_fallback_test()) ++failed;
  return failed == 0 ? 0 : 1;
}

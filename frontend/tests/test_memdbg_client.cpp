/*
 * MemDBG - Client connection cancellation tests.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"

#include "memdbg/core/memdbg.h"
#include "memdbg/core/memdbg_protocol.h"

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <future>
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

} // namespace
} // namespace memdbg::frontend

int main() {
  using namespace memdbg::frontend;

  std::printf("=== Client Cancellation Tests ===\n");
  Client client;
  int failed = 0;
  if (!run_cancel_reconnect_cycle(client, 1)) ++failed;
  if (!run_cancel_reconnect_cycle(client, 2)) ++failed;
  return failed == 0 ? 0 : 1;
}

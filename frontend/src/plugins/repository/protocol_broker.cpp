/*
 * MemDBG - Loopback protocol broker for GUI plugins.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "protocol_broker.hpp"

#include "memdbg/core/memdbg.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace memdbg::frontend::plugins {
namespace {

bool read_exact(platform::socket_handle_t fd, void *dst, size_t length) {
  auto *cursor = static_cast<uint8_t *>(dst);
  while (length != 0U) {
    const int got = platform::socket_recv(fd, cursor, length);
    if (got <= 0) return false;
    cursor += static_cast<size_t>(got);
    length -= static_cast<size_t>(got);
  }
  return true;
}

bool write_all(platform::socket_handle_t fd, const void *src, size_t length) {
  const auto *cursor = static_cast<const uint8_t *>(src);
  while (length != 0U) {
    const int sent = platform::socket_send(fd, cursor, length);
    if (sent <= 0) return false;
    cursor += static_cast<size_t>(sent);
    length -= static_cast<size_t>(sent);
  }
  return true;
}

} // namespace

ProtocolBroker::~ProtocolBroker() { stop(); }

bool ProtocolBroker::start(ClientPool &pool) {
  if (running_.load()) return true;
  std::string error;
  if (!platform::socket_startup(&error)) return false;
  socket_runtime_active_ = true;

  const auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(fd)) {
    stop();
    return false;
  }
  listen_fd_.store(fd);
  (void)platform::socket_set_reuse_addr(fd);
  (void)platform::socket_set_nosigpipe(fd);

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(0U);
  if (::bind(fd, reinterpret_cast<const sockaddr *>(&address),
             sizeof(address)) != 0 ||
      ::listen(fd, 8) != 0) {
    stop();
    return false;
  }

  platform::socklen_type length =
      static_cast<platform::socklen_type>(sizeof(address));
  if (::getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) != 0) {
    stop();
    return false;
  }

  pool_ = &pool;
  port_ = ntohs(address.sin_port);
  running_.store(true);
  thread_ = std::thread(&ProtocolBroker::run, this);
  return true;
}

void ProtocolBroker::stop() {
  running_.store(false);
  std::shared_ptr<Client> active_client;
  {
    std::lock_guard<std::mutex> lock(active_client_mutex_);
    active_client = active_client_;
  }
  if (active_client) active_client->cancel_pending_io();
  const auto active = active_fd_.exchange(platform::invalid_socket());
  if (platform::socket_valid(active)) {
    platform::socket_shutdown_both(active);
    platform::socket_close(active);
  }
  const auto listener = listen_fd_.exchange(platform::invalid_socket());
  if (platform::socket_valid(listener)) {
    platform::socket_shutdown_both(listener);
    platform::socket_close(listener);
  }
  if (thread_.joinable()) thread_.join();
  pool_ = nullptr;
  port_ = 0U;
  if (socket_runtime_active_) {
    platform::socket_cleanup();
    socket_runtime_active_ = false;
  }
}

std::shared_ptr<Client> ProtocolBroker::lease_for(uint16_t command) const {
  if (pool_ == nullptr) return {};
  const uint16_t family = static_cast<uint16_t>(command & 0xFF00U);
  if (family == 0x0300U || family == 0x0B00U)
    return pool_->scan_lease();
  if (family == 0x0400U || family == 0x0700U)
    return pool_->poll_lease();

  switch (command) {
  case MEMDBG_CMD_PROCESS_LIST:
  case MEMDBG_CMD_PROCESS_MAPS:
  case MEMDBG_CMD_PROCESS_MAPS_V2:
  case MEMDBG_CMD_PROCESS_INFO:
  case MEMDBG_CMD_BATCH_PROCESS_INFO:
  case MEMDBG_CMD_MEMORY_READ:
  case MEMDBG_CMD_BATCH_READ:
    return pool_->memory_lease();
  default:
    return pool_->control_lease();
  }
}

void ProtocolBroker::serve_one(platform::socket_handle_t fd) {
  memdbg_packet_header_t request{};
  if (!read_exact(fd, &request, sizeof(request))) return;

  memdbg_response_header_t response{};
  response.magic = MEMDBG_PACKET_MAGIC;
  response.version = MEMDBG_PROTOCOL_VERSION;
  response.command = request.command;
  response.request_id = request.request_id;
  response.status = MEMDBG_ERR_PROTOCOL;

  if (request.magic != MEMDBG_PACKET_MAGIC ||
      request.version != MEMDBG_PROTOCOL_VERSION ||
      request.length > MEMDBG_PROTOCOL_MAX_PACKET) {
    (void)write_all(fd, &response, sizeof(response));
    return;
  }

  std::vector<uint8_t> body(request.length);
  if (!body.empty() && !read_exact(fd, body.data(), body.size())) return;

  auto client = lease_for(request.command);
  std::vector<uint8_t> payload;
  int32_t status = MEMDBG_ERR_STATE;
  if (client && client->connected()) {
    bool forward = false;
    {
      std::lock_guard<std::mutex> lock(active_client_mutex_);
      if (running_.load()) {
        active_client_ = client;
        forward = true;
      }
    }
    if (forward &&
        !client->raw_request(request.command,
                             body.empty() ? nullptr : body.data(),
                             request.length, payload, status)) {
      status = MEMDBG_ERR_NET;
      payload.clear();
    }
    {
      std::lock_guard<std::mutex> lock(active_client_mutex_);
      if (active_client_ == client) active_client_.reset();
    }
  }
  if (payload.size() > std::numeric_limits<uint32_t>::max()) {
    status = MEMDBG_ERR_OVERFLOW;
    payload.clear();
  }

  response.status = status;
  response.length = static_cast<uint32_t>(payload.size());
  if (!write_all(fd, &response, sizeof(response))) return;
  if (!payload.empty()) (void)write_all(fd, payload.data(), payload.size());
}

void ProtocolBroker::run() {
  while (running_.load()) {
    const auto listener = listen_fd_.load();
    if (!platform::socket_valid(listener)) break;
    sockaddr_in peer{};
    platform::socklen_type peer_length =
        static_cast<platform::socklen_type>(sizeof(peer));
    const auto client = ::accept(listener, reinterpret_cast<sockaddr *>(&peer),
                                 &peer_length);
    if (!platform::socket_valid(client)) {
      if (!running_.load()) break;
      continue;
    }
    active_fd_.store(client);
    (void)platform::socket_set_recv_timeout(client, 30000U);
    (void)platform::socket_set_send_timeout(client, 30000U);
    (void)platform::socket_set_nosigpipe(client);
    serve_one(client);
    const auto owned = active_fd_.exchange(platform::invalid_socket());
    if (owned == client) platform::socket_close(client);
  }
}

} // namespace memdbg::frontend::plugins

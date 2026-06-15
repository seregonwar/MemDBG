/*
 * memDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace memdbg::frontend {

namespace {

template <typename T> bool read_object(const std::vector<uint8_t> &data, T &out) {
  if (data.size() < sizeof(T)) {
    return false;
  }
  std::memcpy(&out, data.data(), sizeof(T));
  return true;
}

std::string fixed_string(const char *data, size_t size) {
  size_t len = 0;
  while (len < size && data[len] != '\0') {
    ++len;
  }
  return std::string(data, len);
}

} // namespace

Client::Client() = default;

Client::~Client() { disconnect(); }

bool Client::connect_to(const std::string &host, uint16_t port) {
  disconnect();

  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0) {
    set_error_from_errno("socket");
    return false;
  }

  timeval timeout{};
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
  (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  (void)::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    set_error("invalid IPv4 address");
    disconnect();
    return false;
  }

  if (::connect(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    set_error_from_errno("connect");
    disconnect();
    return false;
  }

  last_error_.clear();
  return true;
}

void Client::disconnect() {
  if (fd_ >= 0) {
    (void)::shutdown(fd_, SHUT_RDWR);
    (void)::close(fd_);
    fd_ = -1;
  }
}

bool Client::connected() const { return fd_ >= 0; }

const std::string &Client::last_error() const { return last_error_; }

bool Client::hello(HelloInfo &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_HELLO, nullptr, 0, response)) {
    return false;
  }

  memdbg_hello_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short HELLO response");
    return false;
  }

  out.protocol_version = wire.protocol_version;
  out.platform_id = wire.platform_id;
  out.capabilities = wire.capabilities;
  out.debug_port = wire.debug_port;
  out.udp_log_port = wire.udp_log_port;
  out.version = fixed_string(wire.version, sizeof(wire.version));
  out.name = fixed_string(wire.name, sizeof(wire.name));
  return true;
}

bool Client::ping() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PING, nullptr, 0, response);
}

bool Client::shutdown_payload() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_SHUTDOWN, nullptr, 0, response);
}

bool Client::process_list(std::vector<ProcessEntry> &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_LIST, nullptr, 0, response)) {
    return false;
  }
  if (response.size() < sizeof(uint32_t)) {
    set_error("short process list response");
    return false;
  }

  uint32_t count = 0;
  std::memcpy(&count, response.data(), sizeof(count));
  size_t expected = sizeof(count) + static_cast<size_t>(count) *
                                       sizeof(memdbg_process_entry_t);
  if (response.size() < expected) {
    set_error("truncated process list response");
    return false;
  }

  out.clear();
  out.reserve(count);
  const auto *entries = reinterpret_cast<const memdbg_process_entry_t *>(
      response.data() + sizeof(count));
  for (uint32_t i = 0; i < count; ++i) {
    ProcessEntry entry;
    entry.pid = entries[i].pid;
    entry.name = fixed_string(entries[i].name, sizeof(entries[i].name));
    out.push_back(std::move(entry));
  }
  return true;
}

bool Client::process_maps(int32_t pid, std::vector<MapEntry> &out) {
  memdbg_process_maps_request_t body{};
  body.pid = pid;

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_MAPS, &body, sizeof(body), response)) {
    return false;
  }
  if (response.size() < sizeof(uint32_t)) {
    set_error("short map response");
    return false;
  }

  uint32_t count = 0;
  std::memcpy(&count, response.data(), sizeof(count));
  size_t expected =
      sizeof(count) + static_cast<size_t>(count) * sizeof(memdbg_map_entry_t);
  if (response.size() < expected) {
    set_error("truncated map response");
    return false;
  }

  out.clear();
  out.reserve(count);
  const auto *entries =
      reinterpret_cast<const memdbg_map_entry_t *>(response.data() + sizeof(count));
  for (uint32_t i = 0; i < count; ++i) {
    MapEntry entry;
    entry.start = entries[i].start;
    entry.end = entries[i].end;
    entry.protection = entries[i].protection;
    entry.flags = entries[i].flags;
    entry.name = fixed_string(entries[i].name, sizeof(entries[i].name));
    out.push_back(std::move(entry));
  }
  return true;
}

bool Client::process_info(int32_t pid, ProcessInfo &out) {
  memdbg_process_info_request_t body{};
  body.pid = pid;

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_INFO, &body, sizeof(body), response)) {
    return false;
  }

  memdbg_process_info_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process info response");
    return false;
  }

  out.pid = wire.pid;
  out.name = fixed_string(wire.name, sizeof(wire.name));
  out.title_id = fixed_string(wire.title_id, sizeof(wire.title_id));
  out.content_id = fixed_string(wire.content_id, sizeof(wire.content_id));
  out.path = fixed_string(wire.path, sizeof(wire.path));
  return true;
}

bool Client::memory_read(int32_t pid, uint64_t address, uint32_t length,
                         std::vector<uint8_t> &out) {
  memdbg_memory_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  return request(MEMDBG_CMD_MEMORY_READ, &body, sizeof(body), out);
}

bool Client::memory_write(int32_t pid, uint64_t address,
                          const std::vector<uint8_t> &data, uint32_t &written) {
  memdbg_memory_request_t header{};
  header.pid = pid;
  header.address = address;
  header.length = static_cast<uint32_t>(data.size());

  std::vector<uint8_t> body(sizeof(header) + data.size());
  std::memcpy(body.data(), &header, sizeof(header));
  if (!data.empty()) {
    std::memcpy(body.data() + sizeof(header), data.data(), data.size());
  }

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_MEMORY_WRITE, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }
  if (response.size() < sizeof(uint32_t)) {
    set_error("short write response");
    return false;
  }
  std::memcpy(&written, response.data(), sizeof(written));
  return true;
}

bool Client::scan_exact(const memdbg_scan_exact_request_t &request_body,
                        ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_EXACT, &request_body, sizeof(request_body),
               response)) {
    return false;
  }

  memdbg_scan_response_prefix_t prefix{};
  if (!read_object(response, prefix)) {
    set_error("short scan response");
    return false;
  }
  size_t expected = sizeof(prefix) + static_cast<size_t>(prefix.count) *
                                        sizeof(memdbg_scan_result_entry_t);
  if (response.size() < expected) {
    set_error("truncated scan response");
    return false;
  }

  out.count = prefix.count;
  out.truncated = prefix.truncated != 0;
  out.bytes_scanned = prefix.bytes_scanned;
  out.elapsed_ns = prefix.elapsed_ns;
  out.read_calls = prefix.read_calls;
  out.regions_scanned = prefix.regions_scanned;
  out.read_errors = prefix.read_errors;
  out.addresses.clear();
  out.addresses.reserve(prefix.count);
  const auto *entries = reinterpret_cast<const memdbg_scan_result_entry_t *>(
      response.data() + sizeof(prefix));
  for (uint32_t i = 0; i < prefix.count; ++i) {
    out.addresses.push_back(entries[i].address);
  }
  return true;
}

bool Client::scan_process_exact(
    const memdbg_scan_process_exact_request_t &request_body, ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT, &request_body,
               sizeof(request_body), response)) {
    return false;
  }

  memdbg_scan_response_prefix_t prefix{};
  if (!read_object(response, prefix)) {
    set_error("short process scan response");
    return false;
  }
  size_t expected = sizeof(prefix) + static_cast<size_t>(prefix.count) *
                                        sizeof(memdbg_scan_result_entry_t);
  if (response.size() < expected) {
    set_error("truncated process scan response");
    return false;
  }

  out.count = prefix.count;
  out.truncated = prefix.truncated != 0;
  out.bytes_scanned = prefix.bytes_scanned;
  out.elapsed_ns = prefix.elapsed_ns;
  out.read_calls = prefix.read_calls;
  out.regions_scanned = prefix.regions_scanned;
  out.read_errors = prefix.read_errors;
  out.addresses.clear();
  out.addresses.reserve(prefix.count);
  const auto *entries = reinterpret_cast<const memdbg_scan_result_entry_t *>(
      response.data() + sizeof(prefix));
  for (uint32_t i = 0; i < prefix.count; ++i) {
    out.addresses.push_back(entries[i].address);
  }
  return true;
}

bool Client::request(uint16_t command, const void *payload,
                     uint32_t payload_len, std::vector<uint8_t> &response) {
  if (fd_ < 0) {
    set_error("not connected");
    return false;
  }

  memdbg_packet_header_t header{};
  header.magic = MEMDBG_PACKET_MAGIC;
  header.version = MEMDBG_PROTOCOL_VERSION;
  header.command = command;
  header.request_id = next_request_id_++;
  header.length = payload_len;

  if (!write_all(&header, sizeof(header))) {
    return false;
  }
  if (payload_len != 0 && payload != nullptr && !write_all(payload, payload_len)) {
    return false;
  }

  memdbg_response_header_t response_header{};
  if (!read_exact(&response_header, sizeof(response_header))) {
    return false;
  }
  if (response_header.magic != MEMDBG_PACKET_MAGIC ||
      response_header.version != MEMDBG_PROTOCOL_VERSION ||
      response_header.command != command ||
      response_header.request_id != header.request_id) {
    set_error("invalid response header");
    return false;
  }
  if (response_header.length > MEMDBG_PROTOCOL_MAX_PACKET + 1024U * 1024U) {
    set_error("response too large");
    return false;
  }

  response.assign(response_header.length, 0);
  if (!response.empty() && !read_exact(response.data(), response.size())) {
    return false;
  }

  if (response_header.status != 0) {
    std::ostringstream oss;
    oss << "payload status " << response_header.status;
    set_error(oss.str());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Client::read_exact(void *data, size_t size) {
  auto *cursor = static_cast<uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    ssize_t n = ::recv(fd_, cursor + total, size - total, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      set_error_from_errno("recv");
      return false;
    }
    if (n == 0) {
      set_error("connection closed");
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

bool Client::write_all(const void *data, size_t size) {
  const auto *cursor = static_cast<const uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    ssize_t n = ::send(fd_, cursor + total, size - total, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      set_error_from_errno("send");
      return false;
    }
    if (n == 0) {
      set_error("socket write returned zero");
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

void Client::set_error_from_errno(const std::string &prefix) {
  last_error_ = prefix + ": " + std::strerror(errno);
}

void Client::set_error(const std::string &message) { last_error_ = message; }

std::string platform_name(uint16_t platform_id) {
  switch (platform_id) {
  case MEMDBG_PLATFORM_PS4:
    return "PS4";
  case MEMDBG_PLATFORM_PS5:
    return "PS5";
  case MEMDBG_PLATFORM_HOST:
    return "Host";
  default:
    return "Unknown";
  }
}

std::string capability_text(uint32_t capabilities) {
  struct CapName {
    uint32_t bit;
    const char *name;
  };
  static const CapName names[] = {
      {MEMDBG_CAP_PROCESS_LIST, "processes"},
      {MEMDBG_CAP_PROCESS_MAPS, "maps"},
      {MEMDBG_CAP_MEMORY_READ, "read"},
      {MEMDBG_CAP_MEMORY_WRITE, "write"},
      {MEMDBG_CAP_SCAN_EXACT, "range scan"},
      {MEMDBG_CAP_UDP_LOG, "udp log"},
      {MEMDBG_CAP_SCAN_PROCESS_EXACT, "process scan"},
      {MEMDBG_CAP_SCAN_TELEMETRY, "scan telemetry"},
      {MEMDBG_CAP_PROCESS_INFO, "process info"},
  };

  std::ostringstream oss;
  bool first = true;
  for (const auto &cap : names) {
    if ((capabilities & cap.bit) == 0) {
      continue;
    }
    if (!first) {
      oss << ", ";
    }
    oss << cap.name;
    first = false;
  }
  return first ? "none" : oss.str();
}

} // namespace memdbg::frontend

/*
 * MemDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"

#include "memdbg/core/memdbg.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern "C" {
int lz4_decompress_safe(const char *src, char *dst, int compressed_size, int dst_capacity);
}

namespace {

/* Decompress LZ4 prefix format: byte 0 = 0x00 (raw) or 0x01 (LZ4).
   LZ4: bytes 1-4 = uncompressed_size LE, bytes 5+ = compressed data. */
static bool maybe_decompress(const std::vector<uint8_t> &response,
                             std::vector<uint8_t> &out) {
  if (response.empty()) { out.clear(); return true; }
  if (response[0] == 0x00U) {
    /* Uncompressed — strip 1-byte prefix */
    out.assign(response.begin() + 1, response.end());
    return true;
  }
  if (response[0] == 0x01U && response.size() >= 5U) {
    /* LZ4 compressed: 4-byte uncompressed size + compressed payload */
    uint32_t uncomp_len = (uint32_t)response[1] |
                          ((uint32_t)response[2] << 8U) |
                          ((uint32_t)response[3] << 16U) |
                          ((uint32_t)response[4] << 24U);
    out.resize(uncomp_len);
    int dec = lz4_decompress_safe(
        (const char *)(response.data() + 5),
        (char *)out.data(),
        (int)(response.size() - 5U),
        (int)uncomp_len);
    if (dec != (int)uncomp_len) {
      /* Decompression failed — return what we got */
      out.clear();
      return false;
    }
    return true;
  }
  /* Unknown format — pass through as-is */
  out = response;
  return true;
}

} // namespace

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

const char *payload_status_name(int32_t status) {
  switch (static_cast<memdbg_status_t>(status)) {
  case MEMDBG_OK:
    return "ok";
  case MEMDBG_ERR_PARAM:
    return "invalid parameter";
  case MEMDBG_ERR_NOMEM:
    return "out of memory";
  case MEMDBG_ERR_IO:
    return "i/o error";
  case MEMDBG_ERR_NET:
    return "network error";
  case MEMDBG_ERR_PROTOCOL:
    return "protocol error";
  case MEMDBG_ERR_UNSUPPORTED:
    return "unsupported";
  case MEMDBG_ERR_NOT_FOUND:
    return "not found";
  case MEMDBG_ERR_PERMISSION:
    return "permission denied";
  case MEMDBG_ERR_OVERFLOW:
    return "overflow";
  case MEMDBG_ERR_STATE:
    return "invalid state";
  default:
    return "unknown error";
  }
}

const char *payload_status_hint(int32_t status) {
  switch (static_cast<memdbg_status_t>(status)) {
  case MEMDBG_ERR_IO:
    return "verify the target process, selected map/range, and payload privileges";
  case MEMDBG_ERR_PERMISSION:
    return "the payload could not access the target process memory";
  case MEMDBG_ERR_PARAM:
    return "check that a process and a valid address/range are selected";
  case MEMDBG_ERR_UNSUPPORTED:
    return "this payload/platform does not expose the requested operation";
  default:
    return "";
  }
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

int Client::release_fd() {
  int fd = fd_;
  fd_ = -1;
  last_error_.clear();
  return fd;
}

void Client::take_fd(int fd) {
  if (fd_ >= 0) disconnect();
  fd_ = fd;
  last_error_.clear();
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
  std::vector<uint8_t> raw;
  if (!request(MEMDBG_CMD_MEMORY_READ, &body, sizeof(body), raw))
    return false;
  if (!maybe_decompress(raw, out)) {
    set_error("LZ4 decompression failed");
    return false;
  }
  return true;
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

template <typename EntryT>
static bool parse_scan_response(const std::vector<uint8_t> &response,
                                ScanResult &out,
                                size_t entry_addr_offset = offsetof(EntryT, address)) {
  memdbg_scan_response_prefix_t prefix{};
  if (response.size() < sizeof(prefix)) return false;
  std::memcpy(&prefix, response.data(), sizeof(prefix));
  size_t expected = sizeof(prefix) + static_cast<size_t>(prefix.count) *
                                        sizeof(EntryT);
  if (response.size() < expected) return false;
  out.count = prefix.count;
  out.truncated = prefix.truncated != 0;
  out.bytes_scanned = prefix.bytes_scanned;
  out.elapsed_ns = prefix.elapsed_ns;
  out.read_calls = prefix.read_calls;
  out.regions_scanned = prefix.regions_scanned;
  out.read_errors = prefix.read_errors;
  out.addresses.clear();
  out.addresses.reserve(prefix.count);
  const auto *entries = reinterpret_cast<const EntryT *>(
      response.data() + sizeof(prefix));
  for (uint32_t i = 0; i < prefix.count; ++i) {
    uint64_t addr = 0;
    std::memcpy(&addr,
                reinterpret_cast<const uint8_t *>(&entries[i]) + entry_addr_offset,
                sizeof(uint64_t));
    out.addresses.push_back(addr);
  }
  return true;
}

bool Client::scan_exact(const memdbg_scan_exact_request_t &request_body,
                        ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_EXACT, &request_body, sizeof(request_body),
               response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out);
}

bool Client::scan_process_exact(
    const memdbg_scan_process_exact_request_t &request_body, ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out);
}

bool Client::scan_aob(const memdbg_scan_aob_request_t &request_body,
                      const std::vector<uint8_t> &pattern,
                      const std::vector<uint8_t> &mask, ScanResult &out) {
  size_t pat_len = pattern.size();
  if (pat_len != mask.size() || pat_len > 256U) {
    set_error("invalid AOB pattern/mask");
    return false;
  }
  std::vector<uint8_t> body;
  body.resize(sizeof(request_body) + pat_len + pat_len);
  memcpy(body.data(), &request_body, sizeof(request_body));
  memcpy(body.data() + sizeof(request_body), pattern.data(), pat_len);
  memcpy(body.data() + sizeof(request_body) + pat_len, mask.data(), pat_len);
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_AOB, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out);
}

bool Client::scan_process_aob(
    const memdbg_scan_process_aob_request_t &request_body,
    const std::vector<uint8_t> &pattern,
    const std::vector<uint8_t> &mask, ScanResult &out) {
  size_t pat_len = pattern.size();
  if (pat_len != mask.size() || pat_len > 256U) {
    set_error("invalid AOB pattern/mask");
    return false;
  }
  std::vector<uint8_t> body;
  body.resize(sizeof(request_body) + pat_len + pat_len);
  memcpy(body.data(), &request_body, sizeof(request_body));
  memcpy(body.data() + sizeof(request_body), pattern.data(), pat_len);
  memcpy(body.data() + sizeof(request_body) + pat_len, mask.data(), pat_len);
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_AOB, body.data(),
               static_cast<uint32_t>(body.size()), response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out);
}

bool Client::scan_pointer(const memdbg_scan_pointer_request_t &request_body,
                          ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_POINTER, &request_body, sizeof(request_body),
               response)) {
    return false;
  }
  /* Pointer scan returns memdbg_pointer_chain_entry_t (16 bytes),
   * extracting base_address at offset 0. */
  return parse_scan_response<memdbg_pointer_chain_entry_t>(
      response, out, offsetof(memdbg_pointer_chain_entry_t, base_address));
}

bool Client::telemetry(TelemetrySnapshot &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TELEMETRY, nullptr, 0, response)) {
    return false;
  }

  memdbg_telemetry_response_t wire{};
  if (response.size() < sizeof(wire)) {
    set_error("short telemetry response");
    return false;
  }
  std::memcpy(&wire, response.data(), sizeof(wire));

  out.total_bytes_read    = wire.total_bytes_read;
  out.total_bytes_written = wire.total_bytes_written;
  out.total_read_calls    = wire.total_read_calls;
  out.total_write_calls   = wire.total_write_calls;
  out.uptime_seconds      = wire.uptime_seconds;
  out.active_connections  = wire.active_connections;
  out.thread_pool_size    = wire.thread_pool_size;
  out.scan_cache_hits     = wire.scan_cache_hits;
  out.scan_cache_misses   = wire.scan_cache_misses;
  return true;
}

bool Client::batch_read(int32_t pid,
                        const std::vector<memdbg_batch_read_item_t> &items,
                        BatchReadResult &out) {
  if (items.empty() || items.size() > MEMDBG_BATCH_READ_MAX_ITEMS) {
    set_error("batch_read: invalid item count");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(items.size());
  memdbg_batch_read_request_t header{};
  header.pid   = pid;
  header.count = count;

  size_t body_len = sizeof(header) + count * sizeof(memdbg_batch_read_item_t);
  std::vector<uint8_t> body(body_len);
  memcpy(body.data(), &header, sizeof(header));
  memcpy(body.data() + sizeof(header), items.data(),
         count * sizeof(memdbg_batch_read_item_t));

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_READ, body.data(),
               static_cast<uint32_t>(body_len), response)) {
    return false;
  }

  size_t results_size = count * sizeof(memdbg_batch_read_result_entry_t);
  if (response.size() < results_size) {
    set_error("batch_read: short response");
    return false;
  }

  out.entries.resize(count);
  memcpy(out.entries.data(), response.data(), results_size);

  /* Decompress data portion */
  std::vector<uint8_t> compressed_data(
      response.begin() + (ptrdiff_t)results_size, response.end());
  if (!maybe_decompress(compressed_data, out.data)) {
    set_error("batch_read: LZ4 decompression failed");
    return false;
  }

  return true;
}

bool Client::batch_write(int32_t pid,
                         const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &items,
                         BatchWriteResult &out) {
  if (items.empty() || items.size() > MEMDBG_BATCH_WRITE_MAX_ITEMS) {
    set_error("batch_write: invalid item count");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(items.size());

  /* Calculate total body size: header + items (with inline data) */
  size_t body_len = sizeof(memdbg_batch_write_request_t);
  for (const auto &item : items)
    body_len += sizeof(memdbg_batch_write_item_t) + item.second.size();

  std::vector<uint8_t> body(body_len);

  memdbg_batch_write_request_t header{};
  header.pid   = pid;
  header.count = count;
  memcpy(body.data(), &header, sizeof(header));

  uint8_t *cursor = body.data() + sizeof(header);
  for (const auto &item : items) {
    memdbg_batch_write_item_t witem{};
    witem.address = item.first;
    witem.length  = static_cast<uint32_t>(item.second.size());
    memcpy(cursor, &witem, sizeof(witem));
    cursor += sizeof(witem);
    if (!item.second.empty()) {
      memcpy(cursor, item.second.data(), item.second.size());
      cursor += item.second.size();
    }
  }

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_WRITE, body.data(),
               static_cast<uint32_t>(body_len), response)) {
    return false;
  }

  size_t results_size = count * sizeof(memdbg_batch_write_result_entry_t);
  if (response.size() < results_size) {
    set_error("batch_write: short response");
    return false;
  }

  out.entries.resize(count);
  memcpy(out.entries.data(), response.data(), results_size);

  return true;
}

bool Client::scan_unknown(const memdbg_scan_process_exact_request_t &request_body,
                          ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_UNKNOWN, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out);
}

bool Client::foreground_app(int32_t pid, char *title_id, size_t title_id_size,
                            char *content_id, size_t content_id_size,
                            char *name, size_t name_size, char *app_ver,
                            size_t app_ver_size) {
  (void)pid;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_FOREGROUND_APP, nullptr, 0, response))
    return false;
  memdbg_foreground_app_response_t app;
  if (response.size() < sizeof(app)) {
    set_error("short foreground app response");
    return false;
  }
  memcpy(&app, response.data(), sizeof(app));
  if (title_id)    std::snprintf(title_id, title_id_size, "%s", app.title_id);
  if (content_id)  std::snprintf(content_id, content_id_size, "%s", app.content_id);
  if (name)        std::snprintf(name, name_size, "%s", app.name);
  if (app_ver)     std::snprintf(app_ver, app_ver_size, "%s", app.app_ver);
  return true;
}

bool Client::process_stop(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 1U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_STOP, &body, sizeof(body), response);
}

bool Client::process_continue(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 2U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_CONTINUE, &body, sizeof(body), response);
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
    const char *hint = payload_status_hint(response_header.status);
    oss << "payload status " << response_header.status << " ("
        << payload_status_name(response_header.status) << ")";
    if (hint[0] != '\0') {
      oss << ": " << hint;
    }
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
      {MEMDBG_CAP_SCAN_AOB, "aob scan"},
      {MEMDBG_CAP_SCAN_POINTER, "pointer scan"},
      {MEMDBG_CAP_FOREGROUND_APP, "foreground app"},
      {MEMDBG_CAP_PROCESS_CONTROL, "process control"},
      {MEMDBG_CAP_BATCH_READ, "batch read"},
      {MEMDBG_CAP_PERF_TELEMETRY, "perf telemetry"},
      {MEMDBG_CAP_SCAN_UNKNOWN, "unknown scan"},
      {MEMDBG_CAP_BATCH_WRITE, "batch write"},
      {MEMDBG_CAP_LZ4, "lz4 compression"},
      {MEMDBG_CAP_SCAN_PROCESS_AOB, "process aob scan"},
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

/*
 * MemDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"

#include "memdbg/core/memdbg.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>

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

constexpr uint32_t kMaxProcessEntries =
    (MEMDBG_PROTOCOL_MAX_PACKET - sizeof(uint32_t)) /
    sizeof(memdbg_process_entry_t);
constexpr uint32_t kMaxMapEntries =
    (MEMDBG_PROTOCOL_MAX_PACKET - sizeof(uint32_t)) /
    sizeof(memdbg_map_entry_t);
constexpr size_t kLegacyThreadEntryV1Size = sizeof(int32_t) + 24U;
constexpr size_t kLegacyThreadEntryV2Size = sizeof(int32_t) + sizeof(uint32_t) + 24U;

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

const char *payload_status_hint(uint16_t command, int32_t status) {
  if (command == MEMDBG_CMD_DEBUG_ATTACH) {
    switch (static_cast<memdbg_status_t>(status)) {
    case MEMDBG_ERR_PERMISSION:
      return "ptrace attach was denied; try a user process/game process and check payload privileges";
    case MEMDBG_ERR_NOT_FOUND:
      return "the target process no longer exists; refresh PIDs";
    case MEMDBG_ERR_STATE:
      return "the debugger is already attached or the target did not enter a traceable stop state";
    case MEMDBG_ERR_IO:
      return "ptrace attach failed on the payload; check /data/memdbg/memdbg.log for the errno line";
    default:
      break;
    }
  }

  if (command == MEMDBG_CMD_SCAN_PROCESS_EXACT ||
      command == MEMDBG_CMD_SCAN_PROCESS_AOB ||
      command == MEMDBG_CMD_SCAN_UNKNOWN ||
      command == MEMDBG_CMD_SCAN_POINTER) {
    switch (static_cast<memdbg_status_t>(status)) {
    case MEMDBG_ERR_STATE:
      return "another process-wide scan is already running; wait for it to finish before starting a new one";
    case MEMDBG_ERR_NOT_FOUND:
      return "the target process no longer exists; refresh PIDs";
    default:
      break;
    }
  }

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
  std::lock_guard<std::mutex> lock(io_mutex_);
  disconnect_unlocked();

  std::string startup_error;
  if (!platform::socket_startup(&startup_error)) {
    set_error(startup_error);
    return false;
  }
  socket_runtime_active_ = true;

  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(fd_)) {
    set_error_from_errno("socket");
    disconnect_unlocked();
    return false;
  }

  (void)platform::socket_set_recv_timeout(fd_, 10000U);
  (void)platform::socket_set_send_timeout(fd_, 10000U);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    set_error("invalid IPv4 address");
    disconnect_unlocked();
    return false;
  }

  if (::connect(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    set_error_from_errno("connect");
    disconnect_unlocked();
    return false;
  }

  (void)platform::socket_set_nosigpipe(fd_);

  last_error_.clear();
  return true;
}

void Client::disconnect() {
  std::lock_guard<std::mutex> lock(io_mutex_);
  disconnect_unlocked();
}

void Client::disconnect_unlocked() {
  if (platform::socket_valid(fd_)) {
    platform::socket_shutdown_both(fd_);
    platform::socket_close(fd_);
    fd_ = platform::invalid_socket();
  }
  if (socket_runtime_active_) {
    platform::socket_cleanup();
    socket_runtime_active_ = false;
  }
}

void Client::close_after_connection_loss() {
  disconnect_unlocked();
}

platform::socket_handle_t Client::release_fd() {
  std::lock_guard<std::mutex> lock(io_mutex_);
  platform::socket_handle_t fd = fd_;
  fd_ = platform::invalid_socket();
  last_error_.clear();
  return fd;
}

void Client::take_fd(platform::socket_handle_t fd) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  if (platform::socket_valid(fd_)) disconnect_unlocked();
  if (platform::socket_valid(fd) && !socket_runtime_active_) {
    std::string startup_error;
    if (!platform::socket_startup(&startup_error)) {
      platform::socket_close(fd);
      set_error(startup_error);
      return;
    }
    socket_runtime_active_ = true;
  }
  fd_ = fd;
  last_error_.clear();
}

bool Client::connected() const { return platform::socket_valid(fd_); }

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
  if (count > kMaxProcessEntries) {
    set_error("process list response has an invalid item count");
    return false;
  }
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
    if (entries[i].pid <= 0) {
      continue;
    }
    ProcessEntry entry;
    entry.pid = entries[i].pid;
    entry.name = fixed_string(entries[i].name, sizeof(entries[i].name));
    if (entry.name.empty()) {
      entry.name = "pid " + std::to_string(entry.pid);
    }
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
  if (count > kMaxMapEntries) {
    set_error("map response has an invalid item count");
    return false;
  }
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
    if (entries[i].end <= entries[i].start) {
      continue;
    }
    MapEntry entry;
    entry.start = entries[i].start;
    entry.end = entries[i].end;
    entry.protection = entries[i].protection & 0x7U;
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

bool Client::batch_process_info(const std::vector<int32_t> &pids,
                                std::vector<ProcessInfo> &out) {
  out.clear();
  if (pids.empty()) return true;
  if (pids.size() > 128U) {
    set_error("batch_process_info: too many PIDs (max 128)");
    return false;
  }

  uint32_t count = static_cast<uint32_t>(pids.size());
  size_t body_len = sizeof(memdbg_batch_process_info_request_t) +
                    count * sizeof(int32_t);
  std::vector<uint8_t> body(body_len);

  auto *hdr = reinterpret_cast<memdbg_batch_process_info_request_t *>(body.data());
  hdr->count = count;
  hdr->reserved = 0;
  auto *pid_buf = reinterpret_cast<int32_t *>(body.data() + sizeof(*hdr));
  for (uint32_t i = 0; i < count; ++i)
    pid_buf[i] = pids[i];

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_BATCH_PROCESS_INFO, body.data(),
               static_cast<uint32_t>(body_len), response))
    return false;

  if (response.size() < sizeof(memdbg_batch_process_info_response_t)) {
    set_error("batch_process_info: short response");
    return false;
  }

  auto *prefix = reinterpret_cast<const memdbg_batch_process_info_response_t *>(
      response.data());
  if (prefix->count != count) {
    set_error("batch_process_info: count mismatch");
    return false;
  }

  size_t expected = sizeof(*prefix) +
                    count * sizeof(memdbg_process_info_response_t);
  if (response.size() < expected) {
    set_error("batch_process_info: truncated response");
    return false;
  }

  auto *entries = reinterpret_cast<const memdbg_process_info_response_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    ProcessInfo info;
    info.pid = entries[i].pid;
    info.name = fixed_string(entries[i].name, sizeof(entries[i].name));
    info.title_id = fixed_string(entries[i].title_id, sizeof(entries[i].title_id));
    info.content_id = fixed_string(entries[i].content_id, sizeof(entries[i].content_id));
    info.path = fixed_string(entries[i].path, sizeof(entries[i].path));
    out.push_back(std::move(info));
  }
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
                                std::string &error,
                                size_t entry_addr_offset = offsetof(EntryT, address)) {
  memdbg_scan_response_prefix_t prefix{};
  if (response.size() < sizeof(prefix)) {
    error = "short scan response";
    return false;
  }
  std::memcpy(&prefix, response.data(), sizeof(prefix));
  size_t expected = sizeof(prefix) + static_cast<size_t>(prefix.count) *
                                        sizeof(EntryT);
  if (response.size() < expected) {
    error = "truncated scan response";
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
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out, last_error_);
}

bool Client::scan_process_exact(
    const memdbg_scan_process_exact_request_t &request_body, ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out, last_error_);
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
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out, last_error_);
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
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out, last_error_);
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
      response, out, last_error_, offsetof(memdbg_pointer_chain_entry_t, base_address));
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
  return parse_scan_response<memdbg_scan_result_entry_t>(response, out, last_error_);
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

bool Client::process_kill(int32_t pid) {
  memdbg_process_control_request_t body;
  body.pid = pid;
  body.action = 3U;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_KILL, &body, sizeof(body), response);
}

bool Client::debug_attach(int32_t pid) {
  memdbg_debug_attach_request_t body{pid, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_ATTACH, &body, sizeof(body), response);
}

bool Client::debug_detach() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_DETACH, nullptr, 0, response);
}

bool Client::debug_stop() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_STOP, nullptr, 0, response);
}

bool Client::debug_continue() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CONTINUE, nullptr, 0, response);
}

bool Client::debug_step(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_STEP, &body, sizeof(body), response);
}

bool Client::debug_get_threads(std::vector<DebugThreadEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_THREADS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_threads_response_prefix_t)) {
    set_error("short thread list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_threads_response_prefix_t *>(
      response.data());
  if (prefix->count == 0U) return true;

  const size_t body_size = response.size() - sizeof(*prefix);
  size_t entry_size = prefix->reserved;
  if (entry_size != sizeof(memdbg_debug_thread_entry_t) &&
      entry_size != kLegacyThreadEntryV1Size &&
      entry_size != kLegacyThreadEntryV2Size) {
    const size_t full_size = sizeof(memdbg_debug_thread_entry_t);
    if (prefix->count > 0U && body_size >= prefix->count * full_size) {
      entry_size = full_size;
    } else if (prefix->count > 0U &&
               body_size >= prefix->count * kLegacyThreadEntryV2Size) {
      entry_size = kLegacyThreadEntryV2Size;
    } else {
      entry_size = kLegacyThreadEntryV1Size;
    }
  }

  if (entry_size == 0U || body_size < entry_size) {
    set_error("empty thread list response");
    return false;
  }

  const size_t available_count = body_size / entry_size;
  const uint32_t count = static_cast<uint32_t>(
      available_count < prefix->count ? available_count : prefix->count);
  if (count == 0U && prefix->count != 0U) {
    set_error("truncated thread list response");
    return false;
  }

  const uint8_t *entries = response.data() + sizeof(*prefix);
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    const uint8_t *entry = entries + static_cast<size_t>(i) * entry_size;
    DebugThreadEntry e;
    std::memcpy(&e.lwp, entry, sizeof(e.lwp));
    if (entry_size == sizeof(memdbg_debug_thread_entry_t)) {
      auto *full = reinterpret_cast<const memdbg_debug_thread_entry_t *>(entry);
      e.state = full->state;
      e.stop_info.pl_event = full->stop_info.pl_event;
      e.stop_info.stop_signal = full->stop_info.stop_signal;
      e.stop_info.pl_flags = full->stop_info.pl_flags;
      e.stop_info._pad = full->stop_info._pad;
      e.stop_info.pl_sigmask_lo = full->stop_info.pl_sigmask_lo;
      e.stop_info.pl_sigmask_hi = full->stop_info.pl_sigmask_hi;
      e.stop_info.pl_siglist_lo = full->stop_info.pl_siglist_lo;
      e.stop_info.pl_siglist_hi = full->stop_info.pl_siglist_hi;
      e.priority = full->priority;
      e.runtime_us = full->runtime_us;
      e.pctcpu = full->pctcpu;
      e.cpu_id = full->cpu_id;
      e.name.assign(full->name, strnlen(full->name, sizeof(full->name)));
    } else if (entry_size == kLegacyThreadEntryV2Size) {
      std::memcpy(&e.state, entry + sizeof(int32_t), sizeof(e.state));
      const char *name = reinterpret_cast<const char *>(entry + sizeof(int32_t) + sizeof(uint32_t));
      e.name.assign(name, strnlen(name, 24U));
    } else {
      const char *name = reinterpret_cast<const char *>(entry + sizeof(int32_t));
      e.name.assign(name, strnlen(name, 24U));
    }
    out.push_back(std::move(e));
  }
  return true;
}

bool Client::debug_get_regs(int32_t lwp, DebugRegs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_REGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_regs_t)) {
    set_error("short regs response");
    return false;
  }
  std::memcpy(&out.regs, response.data(), sizeof(out.regs));
  return true;
}

bool Client::debug_set_regs(int32_t lwp, const DebugRegs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_regs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.regs, sizeof(in.regs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_REGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_get_dbregs(int32_t lwp, DebugDbregs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_DBREGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_dbregs_t)) {
    set_error("short dbregs response");
    return false;
  }
  std::memcpy(&out.dbregs, response.data(), sizeof(out.dbregs));
  return true;
}

bool Client::debug_set_dbregs(int32_t lwp, const DebugDbregs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_dbregs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.dbregs, sizeof(in.dbregs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_DBREGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_set_breakpoint(uint64_t address, uint32_t kind) {
  memdbg_debug_breakpoint_request_t body{address, kind, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_BREAKPOINT, &body, sizeof(body), response);
}

bool Client::debug_set_breakpoint_cond(uint64_t address, uint32_t kind,
                                       uint32_t cond_reg, uint32_t cond_op,
                                       uint64_t cond_value) {
  memdbg_debug_breakpoint_cond_request_t body{address, kind, cond_reg,
                                               cond_op, 0, cond_value};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_BREAKPOINT_COND, &body, sizeof(body),
                 response);
}

bool Client::debug_clear_breakpoint(uint64_t address) {
  memdbg_debug_breakpoint_request_t body{address, 0, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CLEAR_BREAKPOINT, &body, sizeof(body), response);
}

bool Client::debug_set_watchpoint(uint64_t address, uint32_t length,
                                  uint32_t type) {
  memdbg_debug_watchpoint_request_t body{address, length, type};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_WATCHPOINT, &body, sizeof(body), response);
}

bool Client::debug_clear_watchpoint(uint64_t address) {
  memdbg_debug_watchpoint_request_t body{address, 0, 0};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_CLEAR_WATCHPOINT, &body, sizeof(body), response);
}

bool Client::debug_clear_all_breakpoints(uint32_t &cleared) {
  cleared = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_CLEAR_ALL_BREAKPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_clear_all_response_t)) {
    set_error("short clear-all-bp response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_clear_all_response_t *>(
      response.data());
  cleared = resp->cleared;
  return true;
}

bool Client::debug_clear_all_watchpoints(uint32_t &cleared) {
  cleared = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_CLEAR_ALL_WATCHPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_clear_all_response_t)) {
    set_error("short clear-all-wp response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_clear_all_response_t *>(
      response.data());
  cleared = resp->cleared;
  return true;
}

bool Client::debug_suspend_thread(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SUSPEND_THREAD, &body, sizeof(body), response);
}

bool Client::debug_resume_thread(int32_t lwp) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_RESUME_THREAD, &body, sizeof(body), response);
}

bool Client::debug_get_breakpoints(std::vector<DebugBreakpointEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_BREAKPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_breakpoint_list_prefix_t)) {
    set_error("short breakpoint list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_breakpoint_list_prefix_t *>(
      response.data());
  size_t expected = sizeof(*prefix) +
                    prefix->count * sizeof(memdbg_debug_breakpoint_list_entry_t);
  if (response.size() < expected) {
    set_error("truncated breakpoint list response");
    return false;
  }
  auto *entries = reinterpret_cast<const memdbg_debug_breakpoint_list_entry_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    DebugBreakpointEntry e;
    e.address    = entries[i].address;
    e.kind       = entries[i].kind;
    e.installed  = (entries[i].flags & 1U) != 0;
    e.active     = (entries[i].flags & 2U) != 0;
    e.cond_reg   = entries[i].cond_reg;
    e.cond_op    = entries[i].cond_op;
    e.cond_value = entries[i].cond_value;
    out.push_back(e);
  }
  return true;
}

bool Client::debug_get_watchpoints(std::vector<DebugWatchpointEntry> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_WATCHPOINTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_watchpoint_list_prefix_t)) {
    set_error("short watchpoint list response");
    return false;
  }
  auto *prefix = reinterpret_cast<const memdbg_debug_watchpoint_list_prefix_t *>(
      response.data());
  size_t expected = sizeof(*prefix) +
                    prefix->count * sizeof(memdbg_debug_watchpoint_list_entry_t);
  if (response.size() < expected) {
    set_error("truncated watchpoint list response");
    return false;
  }
  auto *entries = reinterpret_cast<const memdbg_debug_watchpoint_list_entry_t *>(
      response.data() + sizeof(*prefix));
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    DebugWatchpointEntry e;
    e.address   = entries[i].address;
    e.length    = entries[i].length;
    e.type      = entries[i].type;
    e.slot      = entries[i].slot;
    e.installed = (entries[i].flags != 0);
    out.push_back(e);
  }
  return true;
}

bool Client::debug_poll_events(bool &stopped, int32_t &stop_lwp) {
  stopped = false;
  stop_lwp = 0;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_POLL_EVENTS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_debug_poll_response_t)) {
    set_error("short poll response");
    return false;
  }
  auto *resp = reinterpret_cast<const memdbg_debug_poll_response_t *>(response.data());
  stopped = resp->stopped != 0;
  stop_lwp = resp->stop_lwp;
  return true;
}

bool Client::request(uint16_t command, const void *payload,
                     uint32_t payload_len, std::vector<uint8_t> &response) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  if (!platform::socket_valid(fd_)) {
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
    const char *hint = payload_status_hint(command, response_header.status);
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
  if (!platform::socket_valid(fd_)) {
    set_error("not connected");
    return false;
  }

  auto *cursor = static_cast<uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    int n = platform::socket_recv(fd_, cursor + total, size - total);
    if (n < 0) {
      int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err)) {
        continue;
      }
      set_error_from_errno("recv");
      close_after_connection_loss();
      return false;
    }
    if (n == 0) {
      set_error("connection closed by console");
      close_after_connection_loss();
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

bool Client::write_all(const void *data, size_t size) {
  if (!platform::socket_valid(fd_)) {
    set_error("not connected");
    return false;
  }

  const auto *cursor = static_cast<const uint8_t *>(data);
  size_t total = 0;
  while (total < size) {
    int n = platform::socket_send(fd_, cursor + total, size - total);
    if (n < 0) {
      int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err)) {
        continue;
      }
      set_error_from_errno("send");
      close_after_connection_loss();
      return false;
    }
    if (n == 0) {
      set_error("send: connection lost");
      close_after_connection_loss();
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

void Client::set_error_from_errno(const std::string &prefix) {
  int err = platform::socket_last_error_code();
#if EPIPE
  if (err == EPIPE)
    last_error_ = prefix + ": connection lost — the console disconnected abruptly";
  else
#endif
#if ECONNRESET
  if (err == ECONNRESET)
    last_error_ = prefix + ": connection reset by console";
  else
#endif
    last_error_ = prefix + ": " + platform::socket_error_text(err);
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
    return "Unknown (" + std::to_string(platform_id) + ")";
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

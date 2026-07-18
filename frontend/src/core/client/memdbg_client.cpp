/*
 * MemDBG - ImGui frontend client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_client.hpp"
#include "process_list_parser.hpp"
#include "process_maps_parser.hpp"

#include "memdbg/core/memdbg.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
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

constexpr size_t kLegacyThreadEntryV1Size = sizeof(int32_t) + 24U;
constexpr size_t kLegacyThreadEntryV2Size = sizeof(int32_t) + sizeof(uint32_t) + 24U;

uint32_t max_response_for_command(uint16_t command) {
  return command == MEMDBG_CMD_PROCESS_MAPS ||
         command == MEMDBG_CMD_PROCESS_MAPS_V2
             ? MEMDBG_PROTOCOL_MAX_MAP_RESPONSE
             : MEMDBG_PROTOCOL_MAX_PACKET + 1024U * 1024U;
}

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

  if (command == MEMDBG_CMD_SCAN_EXACT ||
      command == MEMDBG_CMD_SCAN_PROCESS_EXACT ||
      command == MEMDBG_CMD_SCAN_AOB ||
      command == MEMDBG_CMD_SCAN_PROCESS_AOB ||
      command == MEMDBG_CMD_SCAN_UNKNOWN ||
      command == MEMDBG_CMD_SCAN_UNKNOWN_V2 ||
      command == MEMDBG_CMD_SCAN_POINTER) {
    switch (static_cast<memdbg_status_t>(status)) {
    case MEMDBG_ERR_STATE:
      return "another process-wide scan is already running; wait for it to finish before starting a new one";
    case MEMDBG_ERR_NOT_FOUND:
      return "the target process no longer exists; refresh PIDs";
    case MEMDBG_ERR_PROTOCOL:
      return (command == MEMDBG_CMD_SCAN_UNKNOWN ||
              command == MEMDBG_CMD_SCAN_UNKNOWN_V2)
          ? "unknown-scan request ABI mismatch; update the payload and frontend together"
          : "scan request size mismatch; the frontend and payload protocol versions may be out of sync";
    case MEMDBG_ERR_UNSUPPORTED:
      return (command == MEMDBG_CMD_SCAN_UNKNOWN ||
              command == MEMDBG_CMD_SCAN_UNKNOWN_V2)
          ? "the payload does not support this unknown-scan request ABI version"
          : "this scan request is not supported by the payload";
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

bool Client::connect_to(const std::string &host, uint16_t port,
                        uint32_t timeout_ms) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  disconnect_unlocked();
  cancel_requested_.store(false);
  compressed_maps_support_.store(-1);

  std::string startup_error;
  if (!platform::socket_startup(&startup_error)) {
    set_error(startup_error);
    return false;
  }
  socket_runtime_active_ = true;

  const platform::socket_handle_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
  fd_.store(fd);
  if (!platform::socket_valid(fd)) {
    set_error_from_errno("socket");
    disconnect_unlocked();
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    set_error("invalid IPv4 address");
    disconnect_unlocked();
    return false;
  }

  if (!platform::socket_set_blocking(fd, false)) {
    set_error_from_errno("connect: non-blocking mode");
    disconnect_unlocked();
    return false;
  }

  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    const int connect_error = platform::socket_last_error_code();
    if (!platform::socket_error_connect_in_progress(connect_error)) {
      set_error("connect: " + platform::socket_error_text(connect_error));
      disconnect_unlocked();
      return false;
    }

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(timeout_ms);
    bool connected = false;
    while (!connected) {
      if (cancel_requested_.load()) {
        set_error("connect cancelled");
        disconnect_unlocked();
        return false;
      }

      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        set_error("connect: timed out");
        disconnect_unlocked();
        return false;
      }
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - now);
      const uint32_t wait_ms = static_cast<uint32_t>(
          std::min<int64_t>(remaining.count(), 50));
      const int wait_result = platform::socket_wait_writable(fd, wait_ms);
      if (wait_result < 0) {
        const int wait_error = platform::socket_last_error_code();
        if (platform::socket_error_interrupted(wait_error)) continue;
        if (cancel_requested_.load()) {
          set_error("connect cancelled");
        } else {
          set_error("connect: " + platform::socket_error_text(wait_error));
        }
        disconnect_unlocked();
        return false;
      }
      if (wait_result == 0) continue;

      const int socket_error = platform::socket_connect_error(fd);
      if (socket_error != 0) {
        set_error("connect: " + platform::socket_error_text(socket_error));
        disconnect_unlocked();
        return false;
      }
      connected = true;
    }
  }

  if (cancel_requested_.load()) {
    set_error("connect cancelled");
    disconnect_unlocked();
    return false;
  }
  if (!platform::socket_set_blocking(fd, true)) {
    set_error_from_errno("connect: blocking mode");
    disconnect_unlocked();
    return false;
  }

  (void)platform::socket_set_recv_timeout(fd, socket_timeout_ms_);
  (void)platform::socket_set_send_timeout(fd, socket_timeout_ms_);
  (void)platform::socket_set_nodelay(fd);
  (void)platform::socket_set_nosigpipe(fd);

  clear_error();
  return true;
}

void Client::set_socket_timeout_ms(uint32_t ms) {
  socket_timeout_ms_ = ms;
}

void Client::cancel_pending_io() {
  cancel_requested_.store(true);
  const platform::socket_handle_t fd =
      fd_.exchange(platform::invalid_socket());
  if (platform::socket_valid(fd)) {
    platform::socket_shutdown_both(fd);
    platform::socket_close(fd);
  }
}

void Client::disconnect() {
  cancel_pending_io();
  std::lock_guard<std::mutex> lock(io_mutex_);
  disconnect_unlocked();
}

void Client::disconnect_unlocked() {
  klog_disconnect();
  pipeline_reset_unlocked();
  compressed_maps_support_.store(-1);
  const platform::socket_handle_t fd =
      fd_.exchange(platform::invalid_socket());
  if (platform::socket_valid(fd)) {
    platform::socket_shutdown_both(fd);
    platform::socket_close(fd);
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
  platform::socket_handle_t fd = fd_.exchange(platform::invalid_socket());
  clear_error();
  return fd;
}

void Client::take_fd(platform::socket_handle_t fd) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  if (platform::socket_valid(fd_.load())) disconnect_unlocked();
  if (platform::socket_valid(fd) && !socket_runtime_active_) {
    std::string startup_error;
    if (!platform::socket_startup(&startup_error)) {
      platform::socket_close(fd);
      set_error(startup_error);
      return;
    }
    socket_runtime_active_ = true;
  }
  cancel_requested_.store(false);
  compressed_maps_support_.store(-1);
  fd_.store(fd);
  if (platform::socket_valid(fd)) (void)platform::socket_set_nodelay(fd);
  clear_error();
}

bool Client::connected() const {
  return platform::socket_valid(fd_.load());
}

std::string Client::last_error() const {
  std::lock_guard<std::mutex> lock(error_mutex_);
  return last_error_;
}

bool Client::hello(HelloInfo &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_HELLO, nullptr, 0, response)) {
    return false;
  }

  memdbg_hello_response_t wire{};
  if (response.size() < MEMDBG_HELLO_V1_SIZE) {
    set_error("short HELLO response");
    return false;
  }
  std::memcpy(&wire, response.data(),
              std::min(response.size(), sizeof(wire)));

  out.protocol_version = wire.protocol_version;
  out.feature_level = wire.feature_level != 0U ? wire.feature_level : 1U;
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

bool Client::raw_request(uint16_t command, const void *payload,
                         uint32_t payload_len,
                         std::vector<uint8_t> &response,
                         int32_t &status) {
  status = MEMDBG_OK;
  const bool ok = request(command, payload, payload_len, response, &status);
  /* request() consumes and validates the complete response before reporting a
     payload status. Such a response is a successful wire exchange even when
     the requested operation itself failed. */
  return ok || status != MEMDBG_OK;
}

bool Client::process_list(std::vector<ProcessEntry> &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_LIST, nullptr, 0, response)) {
    return false;
  }
  std::string parse_error;
  if (!detail::parse_process_list_response(response, out, parse_error)) {
    set_error(parse_error);
    return false;
  }
  return true;
}

bool Client::process_maps(int32_t pid, std::vector<MapEntry> &out) {
  memdbg_process_maps_request_t body{};
  body.pid = pid;

  std::vector<uint8_t> response;
  if (compressed_maps_support_.load() != 0) {
    int32_t payload_status = MEMDBG_OK;
    std::vector<uint8_t> framed;
    if (request(MEMDBG_CMD_PROCESS_MAPS_V2, &body, sizeof(body), framed,
                &payload_status)) {
      compressed_maps_support_.store(1);
      if (!maybe_decompress(framed, response)) {
        set_error("compressed map response could not be decompressed");
        return false;
      }
    } else if (payload_status == MEMDBG_ERR_UNSUPPORTED ||
               payload_status == MEMDBG_ERR_PROTOCOL) {
      /* Payloads predating the common unsupported-command response used
         ERR_PROTOCOL for unknown opcodes. Treat both as a V1 capability miss
         so a new desktop client remains compatible with deployed consoles. */
      compressed_maps_support_.store(0);
    } else {
      return false;
    }
  }
  if (compressed_maps_support_.load() == 0 &&
      !request(MEMDBG_CMD_PROCESS_MAPS, &body, sizeof(body), response)) {
    return false;
  }
  std::string parse_error;
  if (!detail::parse_process_maps_response(response, out, parse_error)) {
    set_error(parse_error);
    return false;
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
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
}

bool Client::scan_process_exact(
    const memdbg_scan_process_exact_request_t &request_body, ScanResult &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_SCAN_PROCESS_EXACT, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
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
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
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
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
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
  std::string error;
  const bool ok = parse_scan_response<memdbg_pointer_chain_entry_t>(
      response, out, error, offsetof(memdbg_pointer_chain_entry_t, base_address));
  if (!ok) set_error(error);
  return ok;
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

bool Client::scan_unknown(const memdbg_scan_unknown_request_t &request_body,
                          ScanResult &out) {
  std::vector<uint8_t> response;
  int32_t payload_status = MEMDBG_OK;
  if (!request(MEMDBG_CMD_SCAN_UNKNOWN_V2, &request_body,
               sizeof(request_body), response, &payload_status)) {
    if (payload_status != MEMDBG_ERR_UNSUPPORTED) return false;
    if (request_body.flags != 0U) {
      set_error("the payload does not support versioned unknown-scan filters");
      return false;
    }

    memdbg_scan_process_exact_request_t legacy{};
    legacy.pid = request_body.pid;
    legacy.value_type = request_body.value_type;
    legacy.value_length = request_body.value_length;
    legacy.alignment = request_body.alignment;
    legacy.max_results = request_body.max_results;
    legacy.protection_mask = request_body.protection_mask;
    legacy.start = request_body.start;
    legacy.end = request_body.end;
    if (!request(MEMDBG_CMD_SCAN_UNKNOWN, &legacy, sizeof(legacy), response))
      return false;
  }
  std::string error;
  const bool ok = parse_scan_response<memdbg_scan_result_entry_t>(response, out, error);
  if (!ok) set_error(error);
  return ok;
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

bool Client::process_protect(int32_t pid, uint64_t address, uint64_t length,
                             uint32_t protection,
                             ProcessProtectResult &out) {
  memdbg_process_protect_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  body.protection = protection;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_PROTECT, &body, sizeof(body), response))
    return false;
  memdbg_process_protect_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process protect response");
    return false;
  }
  out.old_protection = wire.old_protection;
  out.new_protection = wire.new_protection;
  return true;
}

bool Client::process_alloc(int32_t pid, uint64_t hint, uint64_t length,
                           uint32_t protection, uint32_t flags,
                           ProcessAllocResult &out) {
  memdbg_process_alloc_request_t body{};
  body.pid = pid;
  body.hint = hint;
  body.length = length;
  body.protection = protection;
  body.flags = flags;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_ALLOC, &body, sizeof(body), response))
    return false;
  memdbg_process_alloc_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short process alloc response");
    return false;
  }
  out.address = wire.address;
  out.length = wire.length;
  return true;
}

bool Client::process_free(int32_t pid, uint64_t address, uint64_t length) {
  memdbg_process_free_request_t body{};
  body.pid = pid;
  body.address = address;
  body.length = length;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_PROCESS_FREE, &body, sizeof(body), response);
}

bool Client::process_elf_load(int32_t pid, const std::vector<uint8_t> &elf_data,
                              uint32_t flags, const std::string &target_region,
                              uint32_t match_flags,
                              ProcessElfLoadResult &out) {
  if (elf_data.empty() || elf_data.size() > (64ULL << 20)) {
    set_error("ELF data too large (max 64MB)");
    return false;
  }

  memdbg_process_elf_load_request_t req{};
  req.pid        = pid;
  req.flags      = flags;
  req.image_size = static_cast<uint64_t>(elf_data.size());
  req.match_flags = match_flags;
  if (!target_region.empty()) {
    size_t len = target_region.size();
    if (len >= sizeof(req.target_region)) len = sizeof(req.target_region) - 1;
    memcpy(req.target_region, target_region.c_str(), len);
    req.target_region[len] = '\0';
  }

  std::vector<uint8_t> body(sizeof(req) + elf_data.size());
  memcpy(body.data(), &req, sizeof(req));
  memcpy(body.data() + sizeof(req), elf_data.data(), elf_data.size());

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_ELF_LOAD, body.data(),
               static_cast<uint32_t>(body.size()), response))
    return false;

  memdbg_process_elf_load_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short ELF load response");
    return false;
  }
  out.entry_address = wire.entry_address;
  out.load_base     = wire.load_base;
  return true;
}

bool Client::process_hijack(int32_t pid, const std::vector<uint8_t> &elf_data,
                            uint32_t flags, const std::string &target_region,
                            uint32_t match_flags, bool &accepted) {
  accepted = false;
  if (elf_data.empty() || elf_data.size() > (64ULL << 20)) {
    set_error("ELF data too large (max 64MB)");
    return false;
  }

  memdbg_process_hijack_request_t req{};
  req.pid          = pid;
  req.flags        = flags;
  req.payload_size = static_cast<uint64_t>(elf_data.size());
  req.match_flags  = match_flags;
  if (!target_region.empty()) {
    size_t len = target_region.size();
    if (len >= sizeof(req.target_region)) len = sizeof(req.target_region) - 1;
    memcpy(req.target_region, target_region.c_str(), len);
    req.target_region[len] = '\0';
  }

  std::vector<uint8_t> body(sizeof(req) + elf_data.size());
  memcpy(body.data(), &req, sizeof(req));
  memcpy(body.data() + sizeof(req), elf_data.data(), elf_data.size());

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_HIJACK, body.data(),
               static_cast<uint32_t>(body.size()), response))
    return false;

  memdbg_process_hijack_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short hijack response");
    return false;
  }
  accepted = wire.accepted != 0U;
  return true;
}

bool Client::process_stack(const memdbg_process_stack_request_t &request_body,
                           std::vector<StackFrame> &out, bool &truncated) {
  out.clear();
  truncated = false;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_STACK, &request_body,
               sizeof(request_body), response)) {
    return false;
  }
  if (response.size() < sizeof(memdbg_process_stack_response_prefix_t)) {
    set_error("short stack response");
    return false;
  }
  const auto *prefix =
      reinterpret_cast<const memdbg_process_stack_response_prefix_t *>(
          response.data());
  if (prefix->entry_size != sizeof(memdbg_process_stack_frame_t)) {
    set_error("unsupported stack frame entry size");
    return false;
  }
  const size_t entries_size =
      static_cast<size_t>(prefix->count) * sizeof(memdbg_process_stack_frame_t);
  const size_t header_size = sizeof(*prefix);
  if (response.size() < header_size + entries_size ||
      response.size() < header_size + entries_size + prefix->data_size) {
    set_error("truncated stack response");
    return false;
  }
  const auto *entries =
      reinterpret_cast<const memdbg_process_stack_frame_t *>(
          response.data() + header_size);
  const uint8_t *blob = response.data() + header_size + entries_size;
  const size_t blob_size = prefix->data_size;
  out.reserve(prefix->count);
  for (uint32_t i = 0; i < prefix->count; ++i) {
    const auto &wire = entries[i];
    StackFrame frame;
    frame.frame_pointer = wire.frame_pointer;
    frame.saved_frame_pointer = wire.saved_frame_pointer;
    frame.return_address = wire.return_address;
    frame.stack_address = wire.stack_address;
    frame.code_address = wire.code_address;
    if (wire.stack_data_offset <= blob_size &&
        wire.stack_size <= blob_size - wire.stack_data_offset) {
      frame.stack_bytes.assign(blob + wire.stack_data_offset,
                               blob + wire.stack_data_offset + wire.stack_size);
    }
    if (wire.code_data_offset <= blob_size &&
        wire.code_size <= blob_size - wire.code_data_offset) {
      frame.code_bytes.assign(blob + wire.code_data_offset,
                              blob + wire.code_data_offset + wire.code_size);
    }
    out.push_back(std::move(frame));
  }
  truncated = prefix->truncated != 0U;
  return true;
}

bool Client::process_call(const memdbg_process_call_request_t &request_body,
                          memdbg_process_call_response_t &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_CALL, &request_body,
               sizeof(request_body), response))
    return false;
  return read_object(response, out);
}

/* ---- Klog streaming ---- */

bool Client::klog_connect(const std::string &host, uint16_t &klog_port) {
  std::lock_guard<std::mutex> lock(io_mutex_);

  /* Close any existing klog socket */
  if (platform::socket_valid(klog_fd_)) {
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
  }

  if (!platform::socket_valid(fd_)) {
    set_error("not connected to payload");
    return false;
  }

  /* Send KLOG_CONNECT command on the main protocol socket */
  memdbg_klog_connect_request_t body{};
  body.reserved = 0;

  memdbg_packet_header_t header{};
  header.magic = MEMDBG_PACKET_MAGIC;
  header.version = MEMDBG_PROTOCOL_VERSION;
  header.command = MEMDBG_CMD_KLOG_CONNECT;
  header.request_id = next_request_id_++;
  header.length = sizeof(body);

  std::array<uint8_t, sizeof(header) + sizeof(body)> frame{};
  std::memcpy(frame.data(), &header, sizeof(header));
  std::memcpy(frame.data() + sizeof(header), &body, sizeof(body));
  if (!write_all(frame.data(), frame.size())) {
    return false;
  }

  memdbg_response_header_t response_header{};
  if (!read_exact(&response_header, sizeof(response_header))) {
    return false;
  }
  if (response_header.magic != MEMDBG_PACKET_MAGIC ||
      response_header.version != MEMDBG_PROTOCOL_VERSION ||
      response_header.command != MEMDBG_CMD_KLOG_CONNECT ||
      response_header.request_id != header.request_id) {
    set_error("invalid klog connect response header");
    return false;
  }
  if (response_header.status != 0) {
    std::ostringstream oss;
    oss << "klog connect: payload status " << response_header.status
        << " (" << payload_status_name(response_header.status) << ")";
    set_error(oss.str());
    return false;
  }
  if (response_header.length != sizeof(uint32_t)) {
    set_error("short klog connect response");
    return false;
  }

  uint32_t port = 0;
  if (!read_exact(&port, sizeof(port))) {
    return false;
  }
  klog_port = static_cast<uint16_t>(port);

  /* Open a secondary raw TCP connection for the klog stream */
  klog_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (!platform::socket_valid(klog_fd_)) {
    set_error_from_errno("klog socket");
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  (void)platform::socket_set_recv_timeout(klog_fd_, 100U); /* 100ms for background thread */
  (void)platform::socket_set_nosigpipe(klog_fd_);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(klog_port);
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    set_error("invalid klog IPv4 address");
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  if (::connect(klog_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    set_error_from_errno("klog connect");
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
    return false;
  }

  clear_error();

  /* Start background reader thread */
  klog_reader_closed_ = false;
  klog_reader_running_ = true;
  klog_reader_thread_ = std::thread(&Client::klog_reader_loop, this);

  return true;
}

void Client::klog_reader_loop() {
  uint8_t buf[4096];
  while (klog_reader_running_.load()) {
    int n = platform::socket_recv(klog_fd_, buf, sizeof(buf));
    if (n > 0) {
      std::vector<uint8_t> chunk(buf, buf + static_cast<size_t>(n));
      {
        std::lock_guard<std::mutex> lock(klog_buf_mutex_);
        klog_buf_.push_back(std::move(chunk));
      }
      klog_buf_cv_.notify_one();
    } else if (n == 0) {
      /* Connection closed */
      break;
    } else {
      int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err) ||
          platform::socket_error_would_block(err)) {
        /* No data yet, continue looping */
        continue;
      }
      /* Real error */
      break;
    }
  }
  klog_reader_closed_ = true;
  klog_buf_cv_.notify_all();
}

bool Client::klog_read(std::vector<uint8_t> &out) {
  out.clear();
  std::lock_guard<std::mutex> lock(klog_buf_mutex_);
  if (klog_buf_.empty()) {
    return !klog_reader_closed_.load();
  }
  out = std::move(klog_buf_.front());
  klog_buf_.pop_front();
  return true;
}

void Client::klog_disconnect() {
  klog_stop_reader();
  if (platform::socket_valid(klog_fd_)) {
    platform::socket_close(klog_fd_);
    klog_fd_ = platform::invalid_socket();
  }
}

void Client::klog_stop_reader() {
  klog_reader_running_ = false;
  if (klog_reader_thread_.joinable()) {
    klog_reader_thread_.join();
  }
  /* Drain remaining buffered data */
  {
    std::lock_guard<std::mutex> lock(klog_buf_mutex_);
    klog_buf_.clear();
  }
}

bool Client::klog_connected() const {
  return platform::socket_valid(klog_fd_) && !klog_reader_closed_.load();
}

bool Client::kernel_base(KernelBase &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_KERNEL_BASE, nullptr, 0, response))
    return false;
  memdbg_kernel_base_response_t wire{};
  if (!read_object(response, wire)) {
    set_error("short kernel base response");
    return false;
  }
  out.text_base = wire.text_base;
  out.data_base = wire.data_base;
  return true;
}

bool Client::kernel_read(uint64_t address, uint32_t length,
                         std::vector<uint8_t> &out) {
  memdbg_kernel_memory_request_t body{};
  body.address = address;
  body.length = length;
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_KERNEL_READ, &body, sizeof(body), response))
    return false;
  out = std::move(response);
  return true;
}

bool Client::kernel_write(uint64_t address, const std::vector<uint8_t> &data) {
  if (data.size() > MEMDBG_PROTOCOL_MAX_READ) {
    set_error("kernel write payload too large");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_kernel_memory_request_t) +
                               data.size());
  auto *body = reinterpret_cast<memdbg_kernel_memory_request_t *>(payload.data());
  body->address = address;
  body->length = static_cast<uint32_t>(data.size());
  if (!data.empty())
    std::memcpy(payload.data() + sizeof(*body), data.data(), data.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_KERNEL_WRITE, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_notify(const std::string &text) {
  if (text.size() > 4096U) {
    set_error("console notification text too long");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_console_text_request_t) +
                               text.size());
  auto *body = reinterpret_cast<memdbg_console_text_request_t *>(payload.data());
  body->length = static_cast<uint32_t>(text.size());
  body->reserved = 0;
  if (!text.empty())
    std::memcpy(payload.data() + sizeof(*body), text.data(), text.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_NOTIFY, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_print(const std::string &text) {
  if (text.size() > 4096U) {
    set_error("console print text too long");
    return false;
  }
  std::vector<uint8_t> payload(sizeof(memdbg_console_text_request_t) +
                               text.size());
  auto *body = reinterpret_cast<memdbg_console_text_request_t *>(payload.data());
  body->length = static_cast<uint32_t>(text.size());
  body->reserved = 0;
  if (!text.empty())
    std::memcpy(payload.data() + sizeof(*body), text.data(), text.size());
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_PRINT, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::console_reboot() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_CONSOLE_REBOOT, nullptr, 0, response);
}

bool Client::process_dump(int32_t pid, uint32_t flags, std::string &json_out) {
  memdbg_process_dump_request_t body{};
  body.pid = pid;
  body.flags = flags;

  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_PROCESS_DUMP, &body, sizeof(body), response))
    return false;

  json_out.assign(reinterpret_cast<const char *>(response.data()), response.size());
  return true;
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

bool Client::debug_get_fpregs(int32_t lwp, DebugFpregs &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_FPREGS, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_fpregs_t)) {
    set_error("short fpregs response");
    return false;
  }
  std::memcpy(&out.fpregs, response.data(), sizeof(out.fpregs));
  return true;
}

bool Client::debug_set_fpregs(int32_t lwp, const DebugFpregs &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_fpregs_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.fpregs, sizeof(in.fpregs));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_FPREGS, payload.data(),
                 static_cast<uint32_t>(payload.size()), response);
}

bool Client::debug_get_fsgsbase(int32_t lwp, DebugFsGsBase &out) {
  memdbg_debug_thread_request_t body{0, lwp};
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_DEBUG_GET_FSGSBASE, &body, sizeof(body), response))
    return false;
  if (response.size() < sizeof(memdbg_debug_fsgsbase_t)) {
    set_error("short fs/gs base response");
    return false;
  }
  std::memcpy(&out.base, response.data(), sizeof(out.base));
  return true;
}

bool Client::debug_set_fsgsbase(int32_t lwp, const DebugFsGsBase &in) {
  std::vector<uint8_t> payload(sizeof(memdbg_debug_thread_request_t) +
                               sizeof(memdbg_debug_fsgsbase_t));
  auto *body = reinterpret_cast<memdbg_debug_thread_request_t *>(payload.data());
  body->pid = 0;
  body->lwp = lwp;
  std::memcpy(payload.data() + sizeof(*body), &in.base, sizeof(in.base));
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_DEBUG_SET_FSGSBASE, payload.data(),
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

/* ---- Tracer ---- */

bool Client::tracer_attach(int32_t pid) {
  memdbg_tracer_attach_request_t req;
  req.pid = pid;
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_TRACER_ATTACH, &req, sizeof(req), response);
}

bool Client::tracer_detach() {
  std::vector<uint8_t> response;
  return request(MEMDBG_CMD_TRACER_DETACH, nullptr, 0, response);
}

bool Client::tracer_poll(std::vector<TracerEvent> &out) {
  out.clear();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TRACER_POLL, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_tracer_poll_response_prefix_t))
    return true; /* no events, not an error */
  auto *pfx = reinterpret_cast<const memdbg_tracer_poll_response_prefix_t *>(response.data());
  uint32_t count = pfx->count;
  if (count == 0) return true;
  const auto *evs = reinterpret_cast<const memdbg_tracer_event_t *>(
      response.data() + sizeof(memdbg_tracer_poll_response_prefix_t));
  out.reserve(count);
  for (uint32_t i = 0; i < count; i++) {
    TracerEvent e;
    e.timestamp_ns = evs[i].timestamp_ns;
    e.event_type    = evs[i].event_type;
    e.lwp           = evs[i].lwp;
    e.syscall_no    = evs[i].syscall_no;
    e.syscall_ret   = evs[i].syscall_ret;
    e.signal        = evs[i].signal;
    e.fault_addr    = evs[i].fault_addr;
    for (int j = 0; j < 6; j++) e.args[j] = evs[i].args[j];
    out.push_back(e);
  }
  return true;
}

bool Client::tracer_status(TracerStatus &out) {
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_TRACER_STATUS, nullptr, 0, response))
    return false;
  if (response.size() < sizeof(memdbg_tracer_status_response_t)) {
    set_error("short tracer status response");
    return false;
  }
  auto *st = reinterpret_cast<const memdbg_tracer_status_response_t *>(response.data());
  out.state        = st->state;
  out.events_total = st->events_total;
  out.crash_signal = st->crash_signal;
  out.start_time_ns = st->start_time_ns;
  out.elapsed_ns    = st->elapsed_ns;
  out.dump_path     = st->dump_path;
  return true;
}

bool Client::request(uint16_t command, const void *payload,
                     uint32_t payload_len, std::vector<uint8_t> &response,
                     int32_t *payload_status) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  if (payload_status != nullptr) *payload_status = MEMDBG_OK;
  if ((payload == nullptr && payload_len != 0U) ||
      payload_len > MEMDBG_PROTOCOL_MAX_PACKET) {
    set_error("invalid request payload");
    return false;
  }
  if (!platform::socket_valid(fd_)) {
    set_error("not connected");
    return false;
  }

  memdbg_packet_header_t header{};
  header.magic = MEMDBG_PACKET_MAGIC;
  header.version = MEMDBG_PROTOCOL_VERSION;
  header.command = command;
  header.request_id = next_request_id_unlocked();
  header.length = payload_len;

  /* Most protocol requests have tiny fixed bodies. Send header and body as a
     single TCP write to avoid an extra packet/ACK turn; large streaming
     requests stay zero-copy and rely on TCP_NODELAY for the header. */
  constexpr size_t kInlineRequestMax = 4096U;
  if (payload_len <= kInlineRequestMax) {
    std::array<uint8_t, sizeof(header) + kInlineRequestMax> frame{};
    std::memcpy(frame.data(), &header, sizeof(header));
    if (payload_len != 0U)
      std::memcpy(frame.data() + sizeof(header), payload, payload_len);
    if (!write_all(frame.data(), sizeof(header) + payload_len)) return false;
  } else {
    if (!write_all(&header, sizeof(header)) ||
        !write_all(payload, payload_len))
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
    close_after_connection_loss();
    return false;
  }
  const uint32_t max_response = max_response_for_command(command);
  if (response_header.length > max_response) {
    set_error("response too large");
    /* The announced body is still pending on the stream. Closing is required:
       otherwise the next request interprets body bytes as a response header. */
    close_after_connection_loss();
    return false;
  }

  response.assign(response_header.length, 0);
  if (!response.empty() && !read_exact(response.data(), response.size())) {
    return false;
  }

  if (response_header.status != 0) {
    if (payload_status != nullptr) *payload_status = response_header.status;
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
  clear_error();
  return true;
}

/* ---- Protocol pipelining ---- */

uint32_t Client::pipeline_send(uint16_t command, const void *payload,
                               uint32_t payload_len) {
  /* Serialize header + payload into the pipeline buffer without I/O.
   * Returns the request_id for later correlation with pipeline_flush().
   * If the buffer would exceed the safety limit, returns 0 (request_ids
   * start at 1) to signal that the caller must flush before sending more. */
  std::lock_guard<std::mutex> lock(io_mutex_);
  if ((!payload && payload_len != 0U) ||
      payload_len > MEMDBG_PROTOCOL_MAX_PACKET) {
    set_error("invalid pipeline request payload");
    return 0U;
  }

  const size_t frame_size = sizeof(memdbg_packet_header_t) + payload_len;
  if (frame_size > kPipelineMaxBuffer ||
      pipeline_buffer_.size() > kPipelineMaxBuffer - frame_size)
    return 0U; /* caller must flush first */

  uint32_t rid = next_request_id_unlocked();

  memdbg_packet_header_t header{};
  header.magic      = MEMDBG_PACKET_MAGIC;
  header.version    = MEMDBG_PROTOCOL_VERSION;
  header.command    = command;
  header.request_id = rid;
  header.length     = payload_len;

  const size_t off = pipeline_buffer_.size();
  pipeline_buffer_.resize(off + frame_size);
  std::memcpy(pipeline_buffer_.data() + off, &header, sizeof(header));
  if (payload_len != 0U && payload != nullptr)
    std::memcpy(pipeline_buffer_.data() + off + sizeof(header),
                payload, payload_len);

  pipeline_requests_.push_back({rid, command});
  return rid;
}

void Client::pipeline_reset() {
  std::lock_guard<std::mutex> lock(io_mutex_);
  pipeline_reset_unlocked();
}

void Client::pipeline_reset_unlocked() {
  pipeline_buffer_.clear();
  pipeline_requests_.clear();
  pipeline_responses_.clear();
  pipeline_statuses_.clear();
}

bool Client::pipeline_flush() {
  std::lock_guard<std::mutex> lock(io_mutex_);
  if (pipeline_requests_.empty()) return true;

  if (!platform::socket_valid(fd_)) {
    set_error("not connected");
    pipeline_reset_unlocked();
    return false;
  }

  /* Write the entire batch in one syscall. */
  if (!pipeline_buffer_.empty()) {
    if (!write_all(pipeline_buffer_.data(), pipeline_buffer_.size())) {
      pipeline_reset_unlocked();
      return false;
    }
    pipeline_buffer_.clear();
  }

  /* Read N responses in order. The daemon processes requests
   * sequentially on the same connection; responses arrive in
   * the order they were sent. */
  const size_t count = pipeline_requests_.size();
  for (size_t i = 0; i < count; ++i) {
    const PipelineRequest expected = pipeline_requests_[i];

    memdbg_response_header_t rhdr{};
    if (!read_exact(&rhdr, sizeof(rhdr))) {
      pipeline_reset_unlocked();
      return false;
    }

    if (rhdr.magic != MEMDBG_PACKET_MAGIC ||
        rhdr.version != MEMDBG_PROTOCOL_VERSION ||
        rhdr.command != expected.command ||
        rhdr.request_id != expected.request_id) {
      set_error("invalid pipeline response header");
      close_after_connection_loss();
      return false;
    }

    if (rhdr.length > max_response_for_command(expected.command)) {
      set_error("pipeline response too large");
      close_after_connection_loss();
      return false;
    }

    pipeline_statuses_[expected.request_id] = rhdr.status;

    if (rhdr.length > 0U) {
      std::vector<uint8_t> body(rhdr.length);
      if (!read_exact(body.data(), body.size())) {
        pipeline_reset_unlocked();
        return false;
      }
      pipeline_responses_[expected.request_id] = std::move(body);
    } else {
      pipeline_responses_[expected.request_id].clear();
    }
  }

  pipeline_requests_.clear();
  return true;
}

bool Client::read_pipeline_response(uint32_t request_id,
                                    std::vector<uint8_t> &response_body,
                                    int32_t *out_status) {
  std::lock_guard<std::mutex> lock(io_mutex_);
  auto it = pipeline_responses_.find(request_id);
  if (it == pipeline_responses_.end()) {
    set_error("pipeline response not found for request_id");
    return false;
  }

  response_body = std::move(it->second);
  auto status_it = pipeline_statuses_.find(request_id);
  if (out_status != nullptr)
    *out_status = status_it != pipeline_statuses_.end()
                      ? status_it->second : MEMDBG_ERR_PROTOCOL;

  pipeline_responses_.erase(it);
  if (status_it != pipeline_statuses_.end()) pipeline_statuses_.erase(status_it);

  return true;
}

size_t Client::pipeline_pending() const {
  std::lock_guard<std::mutex> lock(io_mutex_);
  return pipeline_requests_.size();
}

uint32_t Client::next_request_id_unlocked() {
  uint32_t request_id = next_request_id_++;
  if (request_id == 0U) request_id = next_request_id_++;
  return request_id;
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
      if (cancel_requested_.load()) {
        set_error("operation cancelled");
        close_after_connection_loss();
        return false;
      }
      int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err)) {
        continue;
      }
      if (platform::socket_error_would_block(err)) {
        set_error("recv: timed out waiting for payload response");
        close_after_connection_loss();
        return false;
      }
      set_error_from_errno("recv");
      close_after_connection_loss();
      return false;
    }
    if (n == 0) {
      set_error(cancel_requested_.load() ? "operation cancelled"
                                         : "connection closed by console");
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
      if (cancel_requested_.load()) {
        set_error("operation cancelled");
        close_after_connection_loss();
        return false;
      }
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
    set_error(prefix + ": connection lost — the console disconnected abruptly");
  else
#endif
#if ECONNRESET
  if (err == ECONNRESET)
    set_error(prefix + ": connection reset by console");
  else
#endif
    set_error(prefix + ": " + platform::socket_error_text(err));
}

void Client::set_error(const std::string &message) {
  std::lock_guard<std::mutex> lock(error_mutex_);
  last_error_ = message;
}

void Client::clear_error() {
  std::lock_guard<std::mutex> lock(error_mutex_);
  last_error_.clear();
}

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
      {MEMDBG_CAP_DISCOVERY, "discovery"},
      {MEMDBG_CAP_DEBUGGER, "debugger"},
      {MEMDBG_CAP_TRACER, "tracer"},
      {MEMDBG_CAP_MEMORY_PROTECT, "mprotect"},
      {MEMDBG_CAP_MEMORY_ALLOC, "remote alloc"},
      {MEMDBG_CAP_STACK_WALK, "stack walk"},
      {MEMDBG_CAP_REMOTE_CALL, "remote call"},
      {MEMDBG_CAP_KERNEL_ACCESS, "kernel access"},
      {MEMDBG_CAP_CONSOLE_UI, "console ui"},
      {MEMDBG_CAP_DEBUG_FPREGS, "fpu/ymm regs"},
      {MEMDBG_CAP_DEBUG_FSGS, "fs/gs base"},
      {MEMDBG_CAP_DISASSEMBLY, "disassembly"},
      {MEMDBG_CAP_KLOG_FORWARD, "klog"},
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

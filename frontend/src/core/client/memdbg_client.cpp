/*
 * MemDBG - ImGui frontend client (core lifecycle + internal I/O).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "client_internal.hpp"

namespace memdbg::frontend {

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
  socket_set_keepalive(fd);

  clear_error();
  return true;
}

void Client::set_socket_timeout_ms(uint32_t ms) {
  socket_timeout_ms_ = ms;
}

void Client::set_connection_role(memdbg_client_role_t role) {
  hello_role_ = static_cast<uint16_t>(role);
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
  if (io_mutex_.try_lock()) {
    send_goodbye_unlocked();
    disconnect_unlocked();
    io_mutex_.unlock();
    return;
  }
  cancel_pending_io();
  std::lock_guard<std::mutex> lock(io_mutex_);
  disconnect_unlocked();
}

void Client::send_goodbye_unlocked() {
  if (!platform::socket_valid(fd_.load()) || cancel_requested_.load()) return;
  memdbg_packet_header_t header{};
  header.magic = MEMDBG_PACKET_MAGIC;
  header.version = MEMDBG_PROTOCOL_VERSION;
  header.command = MEMDBG_CMD_GOODBYE;
  header.request_id = next_request_id_unlocked();
  if (!write_all(&header, sizeof(header))) return;
  memdbg_response_header_t response{};
  if (!read_exact(&response, sizeof(response))) return;
  if (response.magic != MEMDBG_PACKET_MAGIC ||
      response.version != MEMDBG_PROTOCOL_VERSION ||
      response.command != MEMDBG_CMD_GOODBYE ||
      response.request_id != header.request_id || response.status != MEMDBG_OK ||
      response.length != 0U)
    return;
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
  if (platform::socket_valid(fd)) {
    (void)platform::socket_set_nodelay(fd);
    socket_set_keepalive(fd);
  }
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
  memdbg_hello_request_t hello_request{};
  hello_request.magic = MEMDBG_HELLO_REQUEST_MAGIC;
  hello_request.version = MEMDBG_HELLO_REQUEST_VERSION;
  hello_request.role = hello_role_;
  hello_request.session_id = frontend_session_id();
  std::vector<uint8_t> response;
  if (!request(MEMDBG_CMD_HELLO, &hello_request, sizeof(hello_request),
               response)) {
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
  /* Read extended fields if present (protocol v2). */
  if (response.size() >= MEMDBG_HELLO_V2_SIZE) {
    out.daemon_instance_id = wire.daemon_instance_id;
    out.daemon_start_monotonic_ns = wire.daemon_start_monotonic_ns;
  }
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


/*
 * MemDBG - GDB Remote Serial Protocol framing.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_server.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace memdbg::gdb_bridge {

namespace platform = memdbg::frontend::platform;
namespace {
constexpr size_t kMaxRspPacketBytes = 0x200000U;
/* serve() uses a recv timeout so blocking reads wake up periodically and can
 * observe shutdown_requested() while IDA stays idle. */
constexpr uint32_t kServeRecvTimeoutMs = 1000U;
constexpr uint32_t kAcceptPollMs = 250U;

std::atomic<bool> &shutdown_flag() {
  static std::atomic<bool> flag{false};
  return flag;
}

std::string &shutdown_file_path() {
  static std::string path;
  return path;
}

/* Wait until the listen socket is readable or the timeout elapses.
 * Returns 1 readable, 0 timeout/retry, -1 error. */
int wait_readable(platform::socket_handle_t fd, uint32_t timeout_ms) {
#if defined(_WIN32)
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(fd, &read_set);
  timeval tv;
  tv.tv_sec = static_cast<long>(timeout_ms) / 1000L;
  tv.tv_usec = (static_cast<long>(timeout_ms) % 1000L) * 1000L;
  return ::select(0, &read_set, nullptr, nullptr, &tv);
#else
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  const int ready = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (ready < 0) return platform::socket_error_interrupted(errno) ? 0 : -1;
  return ready;
#endif
}
} // namespace

void request_shutdown() {
  shutdown_flag().store(true, std::memory_order_relaxed);
}

void configure_shutdown_file(const std::string &path) {
  shutdown_file_path() = path;
}

bool shutdown_requested() {
  if (shutdown_flag().load(std::memory_order_relaxed)) return true;
  const std::string &path = shutdown_file_path();
  if (path.empty()) return false;
  std::error_code ec;
  if (std::filesystem::exists(path, ec) && !ec) {
    shutdown_flag().store(true, std::memory_order_relaxed);
    return true;
  }
  return false;
}

uint8_t rsp_checksum(const std::string &payload) {
  unsigned sum = 0U;
  for (unsigned char c : payload)
    sum = (sum + c) & 0xFFU;
  return static_cast<uint8_t>(sum);
}

std::string rsp_escape(const std::string &payload) {
  std::string out;
  out.reserve(payload.size());
  for (unsigned char c : payload) {
    if (c == '$' || c == '#' || c == '}' || c == '*') {
      out.push_back('}');
      out.push_back(static_cast<char>(c ^ 0x20U));
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

bool rsp_decode(const std::string &encoded, std::string &out) {
  out.clear();
  out.reserve(encoded.size());
  for (size_t i = 0; i < encoded.size(); ++i) {
    const unsigned char current = static_cast<unsigned char>(encoded[i]);
    if (current == '}') {
      if (i + 1U >= encoded.size()) return false;
      out.push_back(static_cast<char>(static_cast<unsigned char>(encoded[++i]) ^ 0x20U));
      continue;
    }
    if (current == '*') {
      if (out.empty() || i + 1U >= encoded.size()) return false;
      const unsigned char encoded_count = static_cast<unsigned char>(encoded[++i]);
      if (encoded_count < 32U || encoded_count > 126U) return false;
      const size_t repeat = static_cast<size_t>(encoded_count - 29U);
      if (repeat > kMaxRspPacketBytes - out.size()) return false;
      out.append(repeat, out.back());
      continue;
    }
    out.push_back(static_cast<char>(current));
    if (out.size() > kMaxRspPacketBytes) return false;
  }
  return true;
}

std::string rsp_unescape(const std::string &escaped) {
  std::string out;
  if (!rsp_decode(escaped, out)) return std::string();
  return out;
}

RspConnection::RspConnection(platform::socket_handle_t fd) : fd_(fd) {}

RspConnection::~RspConnection() { close(); }

void RspConnection::close() {
  if (platform::socket_valid(fd_)) {
    platform::socket_close(fd_);
    fd_ = platform::invalid_socket();
  }
}

bool RspConnection::write_all(const void *data, size_t size) {
  const auto *bytes = static_cast<const uint8_t *>(data);
  size_t sent = 0U;
  while (sent < size) {
    const int n = platform::socket_send(fd_, bytes + sent, size - sent);
    if (n <= 0) {
      const int err = platform::socket_last_error_code();
      if (platform::socket_error_interrupted(err)) continue;
      return false;
    }
    sent += static_cast<size_t>(n);
  }
  return true;
}

int RspConnection::read_byte(uint32_t timeout_ms, bool *timed_out) {
  if (timed_out) *timed_out = false;
  if (!rx_buf_.empty()) {
    const unsigned char c = static_cast<unsigned char>(rx_buf_[0]);
    rx_buf_.erase(rx_buf_.begin());
    return static_cast<int>(c);
  }

  if (timeout_ms > 0U) { (void)platform::socket_set_recv_timeout(fd_, timeout_ms); }

  char ch = 0;
  const int n = platform::socket_recv(fd_, &ch, 1U);
  if (n == 1) return static_cast<unsigned char>(ch);
  if (n == 0) return -1;
  const int err = platform::socket_last_error_code();
  if (platform::socket_error_would_block(err) || platform::socket_error_interrupted(err)) {
    if (timed_out) *timed_out = true;
    return -2;
  }
  return -1;
}

RspPacket RspConnection::recv_packet() {
  RspPacket packet;
  for (;;) {
    bool timed_out = false;
    const int b = read_byte(0U, &timed_out);
    if (b == -2) {
      packet.timed_out = true;
      return packet;
    }
    if (b < 0) return packet;
    if (b == 0x03) {
      packet.is_interrupt = true;
      packet.ok = true;
      return packet;
    }
    if (b != '$') continue;

    std::string body;
    for (;;) {
      const int c = read_byte(kServeRecvTimeoutMs, nullptr);
      if (c < 0) return packet;
      if (c == '#') break;
      body.push_back(static_cast<char>(c));
      if (body.size() > kMaxRspPacketBytes) return packet;
    }

    const int c1 = read_byte(0U, nullptr);
    const int c2 = read_byte(0U, nullptr);
    if (c1 < 0 || c2 < 0) return packet;

    auto hex_nibble = [](int ch) -> int {
      if (ch >= '0' && ch <= '9') return ch - '0';
      if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
      if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
      return -1;
    };
    const int hi = hex_nibble(c1);
    const int lo = hex_nibble(c2);
    if (hi < 0 || lo < 0) {
      if (!no_ack_) (void)send_ack(false);
      continue;
    }
    const uint8_t got = static_cast<uint8_t>((hi << 4) | lo);
    if (got != rsp_checksum(body)) {
      if (!no_ack_) (void)send_ack(false);
      continue;
    }
    if (!rsp_decode(body, packet.payload)) {
      if (!no_ack_) (void)send_ack(false);
      continue;
    }
    if (!no_ack_) (void)send_ack(true);
    packet.ok = true;
    return packet;
  }
}

bool RspConnection::poll_interrupt(uint32_t timeout_ms) {
  bool timed_out = false;
  const int b = read_byte(timeout_ms, &timed_out);
  (void)platform::socket_set_recv_timeout(fd_, 0U);
  if (b == 0x03) return true;
  if (b >= 0) {
    /* Push back unexpected byte so recv_packet can process it later. */
    rx_buf_.insert(rx_buf_.begin(), static_cast<char>(b));
  }
  return false;
}

bool RspConnection::send_ack(bool positive) {
  const char c = positive ? '+' : '-';
  std::lock_guard<std::mutex> lock(write_mu_);
  return write_all(&c, 1U);
}

bool RspConnection::send_packet(const std::string &payload) {
  const std::string escaped = rsp_escape(payload);
  const uint8_t cs = rsp_checksum(escaped);
  char trailer[4];
  trailer[0] = '#';
  static const char *kHex = "0123456789abcdef";
  trailer[1] = kHex[(cs >> 4U) & 0x0FU];
  trailer[2] = kHex[cs & 0x0FU];

  std::lock_guard<std::mutex> lock(write_mu_);
  if (!write_all("$", 1U)) return false;
  if (!write_all(escaped.data(), escaped.size())) return false;
  if (!write_all(trailer, 3U)) return false;

  if (no_ack_) return true;

  /* Wait for ACK (best effort), then restore blocking recv. */
  bool timed_out = false;
  const int ack = read_byte(1000U, &timed_out);
  (void)platform::socket_set_recv_timeout(fd_, 0U);
  return ack == '+' || timed_out;
}

RspServer::RspServer() : listen_fd_(platform::invalid_socket()) {}

RspServer::~RspServer() { close_listen(); }

bool RspServer::listen_on(const std::string &host, uint16_t port, std::string &error) {
  close_listen();

  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (!platform::socket_valid(listen_fd_)) {
    error = "socket() failed: " + platform::socket_error_text(platform::socket_last_error_code());
    return false;
  }
  (void)platform::socket_set_reuse_addr(listen_fd_);
  (void)platform::socket_set_nosigpipe(listen_fd_);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (host.empty() || host == "0.0.0.0") {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    error = "invalid listen host: " + host;
    close_listen();
    return false;
  }

  if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    error = "bind() failed: " + platform::socket_error_text(platform::socket_last_error_code());
    close_listen();
    return false;
  }
  if (::listen(listen_fd_, 1) != 0) {
    error = "listen() failed: " + platform::socket_error_text(platform::socket_last_error_code());
    close_listen();
    return false;
  }

  sockaddr_in bound{};
  platform::socklen_type len = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&bound), &len) == 0) {
    listen_port_ = ntohs(bound.sin_port);
  } else {
    listen_port_ = port;
  }
  return true;
}

void RspServer::close_listen() {
  if (platform::socket_valid(listen_fd_)) {
    platform::socket_close(listen_fd_);
    listen_fd_ = platform::invalid_socket();
  }
}

platform::socket_handle_t RspServer::accept_client(std::string &error) {
  if (!platform::socket_valid(listen_fd_)) {
    error = "listen socket is not open";
    return platform::invalid_socket();
  }
  for (;;) {
    if (shutdown_requested()) {
      error = "shutdown requested";
      return platform::invalid_socket();
    }
    const int ready = wait_readable(listen_fd_, kAcceptPollMs);
    if (ready < 0) {
      error = "poll() failed: " +
              platform::socket_error_text(platform::socket_last_error_code());
      return platform::invalid_socket();
    }
    if (ready == 0) continue;
    break;
  }
  sockaddr_in peer{};
  platform::socklen_type len = sizeof(peer);
  platform::socket_handle_t client =
    ::accept(listen_fd_, reinterpret_cast<sockaddr *>(&peer), &len);
  if (!platform::socket_valid(client)) {
    error = "accept() failed: " + platform::socket_error_text(platform::socket_last_error_code());
    return platform::invalid_socket();
  }
  (void)platform::socket_set_nodelay(client);
  (void)platform::socket_set_nosigpipe(client);
  return client;
}

void RspServer::serve(platform::socket_handle_t client_fd, const Handler &handler) {
  RspConnection conn(client_fd);
  for (;;) {
    /* Idle reads wake up periodically so shutdown stays responsive even when
     * IDA has no outstanding request. */
    (void)platform::socket_set_recv_timeout(client_fd, kServeRecvTimeoutMs);
    RspPacket packet = conn.recv_packet();
    if (packet.timed_out && !packet.ok) {
      if (shutdown_requested()) break;
      continue;
    }
    if (!packet.ok) break;
    if (packet.is_interrupt) {
      /* Spurious interrupt outside run-control: ignore. */
      continue;
    }
    const std::string reply = handler(packet.payload, conn);
    if (!conn.send_packet(reply)) break;
    if (shutdown_requested()) break;
  }
}

} // namespace memdbg::gdb_bridge

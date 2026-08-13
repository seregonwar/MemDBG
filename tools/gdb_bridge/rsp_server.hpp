/*
 * MemDBG - GDB Remote Serial Protocol framing.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_RSP_SERVER_HPP
#define MEMDBG_GDB_BRIDGE_RSP_SERVER_HPP

#include "platform.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace memdbg::gdb_bridge {

struct RspPacket {
  std::string payload;
  bool is_interrupt = false; /* Ctrl-C (\x03) */
  bool ok = false;
};

class RspConnection {
public:
  explicit RspConnection(memdbg::frontend::platform::socket_handle_t fd);
  ~RspConnection();

  RspConnection(const RspConnection &) = delete;
  RspConnection &operator=(const RspConnection &) = delete;

  memdbg::frontend::platform::socket_handle_t fd() const { return fd_; }
  bool no_ack() const { return no_ack_; }
  void set_no_ack(bool enabled) { no_ack_ = enabled; }

  /* Blocking read of one RSP packet or interrupt. */
  RspPacket recv_packet();

  /* Non-blocking peek for Ctrl-C while waiting for a stop (poll timeout_ms).
   * Returns true if interrupt was consumed. */
  bool poll_interrupt(uint32_t timeout_ms);

  bool send_ack(bool positive);
  bool send_packet(const std::string &payload);

  void close();

private:
  bool write_all(const void *data, size_t size);
  int read_byte(uint32_t timeout_ms, bool *timed_out);

  memdbg::frontend::platform::socket_handle_t fd_;
  bool no_ack_ = false;
  std::mutex write_mu_;
  std::string rx_buf_;
};

class RspServer {
public:
  using Handler = std::function<std::string(const std::string &packet, RspConnection &conn)>;

  RspServer();
  ~RspServer();

  bool listen_on(const std::string &host, uint16_t port, std::string &error);
  void close_listen();

  /* Accept one client (blocking). Returns invalid socket on failure. */
  memdbg::frontend::platform::socket_handle_t accept_client(std::string &error);

  /* Serve packets until disconnect. Handler returns RSP payload (no $/#).
   * Empty string => empty OK packet. "E01" style errors are pass-through. */
  void serve(memdbg::frontend::platform::socket_handle_t client_fd, const Handler &handler);

  uint16_t listen_port() const { return listen_port_; }

private:
  memdbg::frontend::platform::socket_handle_t listen_fd_;
  uint16_t listen_port_ = 0;
};

uint8_t rsp_checksum(const std::string &payload);
std::string rsp_escape(const std::string &payload);
bool rsp_decode(const std::string &encoded, std::string &out);
std::string rsp_unescape(const std::string &escaped);

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_RSP_SERVER_HPP */

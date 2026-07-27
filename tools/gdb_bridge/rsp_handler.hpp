/*
 * MemDBG - RSP command dispatch onto MDBG Client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP
#define MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP

#include "memdbg_client.hpp"
#include "rsp_server.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace memdbg::gdb_bridge {

class RspHandler {
public:
  RspHandler(memdbg::frontend::Client &client, int32_t initial_pid);

  std::string handle(const std::string &packet, RspConnection &conn);

  int32_t attached_pid() const { return pid_; }
  bool attached() const { return attached_; }

private:
  std::string handle_query(const std::string &packet, RspConnection &conn);
  std::string handle_v(const std::string &packet, RspConnection &conn);
  std::string handle_memory_read(const std::string &packet);
  std::string handle_memory_write(const std::string &packet);
  std::string handle_breakpoint(const std::string &packet, bool enable);
  std::string handle_continue_or_step(bool step, RspConnection &conn,
                                      int32_t lwp);
  std::string stop_reply() const;
  std::string qxfer_features(const std::string &annex, size_t offset,
                             size_t length) const;
  bool ensure_attached();
  int32_t current_thread() const;
  void refresh_threads();

  memdbg::frontend::Client &client_;
  int32_t pid_ = 0;
  bool attached_ = false;
  int32_t general_thread_ = 0; /* Hg */
  int32_t continue_thread_ = 0; /* Hc; 0 = all */
  int32_t stop_lwp_ = 0;
  bool thread_info_started_ = false;
  std::vector<memdbg::frontend::Client::DebugThreadEntry> threads_;
};

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP */

/*
 * MemDBG - Shared MDBG session used by the x64dbg plugin (issue #39).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_X64DBG_SESSION_HPP
#define MEMDBG_X64DBG_SESSION_HPP

#include "memdbg_client.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace memdbg::x64dbg_bridge {

class Session {
public:
  bool connect(const std::string &host, uint16_t port);
  void disconnect();
  bool connected() const;

  bool attach(int32_t pid);
  bool detach();
  bool attached() const { return attached_; }
  int32_t pid() const { return pid_; }

  bool stop();
  bool cont();
  bool step();

  bool read_memory(uint64_t address, uint32_t length, std::vector<uint8_t> &out);
  bool write_memory(uint64_t address, const std::vector<uint8_t> &data);

  bool get_regs(frontend::Client::DebugRegs &out);
  bool set_regs(const frontend::Client::DebugRegs &in);

  bool set_soft_bp(uint64_t address);
  bool set_hw_bp(uint64_t address);
  bool clear_bp(uint64_t address);

  bool set_watchpoint(uint64_t address, uint32_t length, uint32_t type);
  bool clear_watchpoint(uint64_t address);

  /* Poll debugger stop events. stop_lwp is set when stopped==true. */
  bool poll_events(bool &stopped, int32_t &stop_lwp);

  bool get_fpregs(frontend::Client::DebugFpregs &out);
  bool set_gpr(const char *name, uint64_t value);
  bool list_maps(std::vector<frontend::MapEntry> &out);

  std::string last_error() const;

private:
  mutable std::mutex mu_;
  frontend::Client client_;
  bool attached_ = false;
  int32_t pid_ = 0;
  int32_t selected_lwp_ = 0;
  std::string last_error_;

  void set_error(const std::string &msg);
};

Session &global_session();

} // namespace memdbg::x64dbg_bridge

#endif /* MEMDBG_X64DBG_SESSION_HPP */

/*
 * MemDBG - Testable backend boundary for the GDB RSP bridge.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_RSP_BACKEND_HPP
#define MEMDBG_GDB_BRIDGE_RSP_BACKEND_HPP

#include "memdbg_client.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace memdbg::gdb_bridge {

class RspBackend {
public:
  virtual ~RspBackend() = default;

  virtual std::string last_error() const = 0;
  virtual bool process_list(std::vector<memdbg::frontend::ProcessEntry> &out) = 0;
  virtual bool process_maps(int32_t pid, std::vector<memdbg::frontend::MapEntry> &out) = 0;
  virtual bool process_info(int32_t pid, memdbg::frontend::ProcessInfo &out) = 0;
  virtual bool process_kill(int32_t pid) = 0;
  virtual bool memory_read(int32_t pid, uint64_t address, uint32_t length,
                           std::vector<uint8_t> &out) = 0;
  virtual bool memory_write(int32_t pid, uint64_t address, const std::vector<uint8_t> &data,
                            uint32_t &written) = 0;

  virtual bool debug_attach(int32_t pid) = 0;
  virtual bool debug_detach() = 0;
  virtual bool debug_stop() = 0;
  virtual bool debug_continue() = 0;
  virtual bool debug_step(int32_t lwp) = 0;
  virtual bool debug_get_threads(std::vector<memdbg::frontend::Client::DebugThreadEntry> &out) = 0;
  virtual bool debug_get_regs(int32_t lwp, memdbg::frontend::Client::DebugRegs &out) = 0;
  virtual bool debug_set_regs(int32_t lwp, const memdbg::frontend::Client::DebugRegs &in) = 0;
  virtual bool debug_get_dbregs(int32_t lwp, memdbg::frontend::Client::DebugDbregs &out) = 0;
  virtual bool debug_fpregs_supported() const = 0;
  virtual bool debug_get_fpregs(int32_t lwp, memdbg::frontend::Client::DebugFpregs &out) = 0;
  virtual bool debug_set_fpregs(int32_t lwp, const memdbg::frontend::Client::DebugFpregs &in) = 0;
  virtual bool debug_set_breakpoint(uint64_t address, uint32_t kind) = 0;
  virtual bool debug_clear_breakpoint(uint64_t address) = 0;
  virtual bool debug_set_watchpoint(uint64_t address, uint32_t length, uint32_t type) = 0;
  virtual bool debug_clear_watchpoint(uint64_t address) = 0;
  virtual bool
  debug_get_watchpoints(std::vector<memdbg::frontend::Client::DebugWatchpointEntry> &out) = 0;
  virtual bool debug_poll_events(bool &stopped, int32_t &stop_lwp) = 0;
};

std::unique_ptr<RspBackend> make_client_rsp_backend(memdbg::frontend::Client &client,
                                                    bool fpregs_supported);

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_RSP_BACKEND_HPP */

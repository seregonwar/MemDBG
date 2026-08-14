/*
 * MemDBG - Production Client adapter for the GDB RSP backend.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_backend.hpp"

#include <memory>

namespace memdbg::gdb_bridge {
namespace {

class ClientRspBackend final : public RspBackend {
public:
  ClientRspBackend(memdbg::frontend::Client &client, bool fpregs_supported)
    : client_(client), fpregs_supported_(fpregs_supported) {}

  std::string last_error() const override { return client_.last_error(); }
  bool process_list(std::vector<memdbg::frontend::ProcessEntry> &out) override {
    return client_.process_list(out);
  }
  bool process_maps(int32_t pid, std::vector<memdbg::frontend::MapEntry> &out) override {
    return client_.process_maps(pid, out);
  }
  bool process_info(int32_t pid, memdbg::frontend::ProcessInfo &out) override {
    return client_.process_info(pid, out);
  }
  bool process_kill(int32_t pid) override { return client_.process_kill(pid); }
  bool memory_read(int32_t pid, uint64_t address, uint32_t length,
                   std::vector<uint8_t> &out) override {
    return client_.memory_read(pid, address, length, out);
  }
  bool memory_write(int32_t pid, uint64_t address, const std::vector<uint8_t> &data,
                    uint32_t &written) override {
    return client_.memory_write(pid, address, data, written);
  }
  bool debug_attach(int32_t pid) override { return client_.debug_attach(pid); }
  bool debug_detach() override { return client_.debug_detach(); }
  bool debug_stop() override { return client_.debug_stop(); }
  bool debug_continue() override { return client_.debug_continue(); }
  bool debug_step(int32_t lwp) override { return client_.debug_step(lwp); }
  bool debug_get_threads(std::vector<memdbg::frontend::Client::DebugThreadEntry> &out) override {
    return client_.debug_get_threads(out);
  }
  bool debug_get_regs(int32_t lwp, memdbg::frontend::Client::DebugRegs &out) override {
    return client_.debug_get_regs(lwp, out);
  }
  bool debug_set_regs(int32_t lwp, const memdbg::frontend::Client::DebugRegs &in) override {
    return client_.debug_set_regs(lwp, in);
  }
  bool debug_get_dbregs(int32_t lwp, memdbg::frontend::Client::DebugDbregs &out) override {
    return client_.debug_get_dbregs(lwp, out);
  }
  bool debug_fpregs_supported() const override { return fpregs_supported_; }
  bool debug_get_fpregs(int32_t lwp, memdbg::frontend::Client::DebugFpregs &out) override {
    return client_.debug_get_fpregs(lwp, out);
  }
  bool debug_set_fpregs(int32_t lwp, const memdbg::frontend::Client::DebugFpregs &in) override {
    return client_.debug_set_fpregs(lwp, in);
  }
  bool debug_set_breakpoint(uint64_t address, uint32_t kind) override {
    return client_.debug_set_breakpoint(address, kind);
  }
  bool debug_clear_breakpoint(uint64_t address) override {
    return client_.debug_clear_breakpoint(address);
  }
  bool debug_set_watchpoint(uint64_t address, uint32_t length, uint32_t type) override {
    return client_.debug_set_watchpoint(address, length, type);
  }
  bool debug_clear_watchpoint(uint64_t address) override {
    return client_.debug_clear_watchpoint(address);
  }
  bool
  debug_get_watchpoints(std::vector<memdbg::frontend::Client::DebugWatchpointEntry> &out) override {
    return client_.debug_get_watchpoints(out);
  }
  bool debug_poll_events(bool &stopped, int32_t &stop_lwp) override {
    return client_.debug_poll_events(stopped, stop_lwp);
  }

private:
  memdbg::frontend::Client &client_;
  bool fpregs_supported_ = false;
};

} // namespace

std::unique_ptr<RspBackend> make_client_rsp_backend(memdbg::frontend::Client &client,
                                                    bool fpregs_supported) {
  return std::make_unique<ClientRspBackend>(client, fpregs_supported);
}

} // namespace memdbg::gdb_bridge

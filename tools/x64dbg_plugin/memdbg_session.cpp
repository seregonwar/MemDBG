/*
 * MemDBG - Shared MDBG session used by the x64dbg plugin (issue #39).
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "memdbg_session.hpp"

#include "plugin_util.hpp"

#include "memdbg/core/memdbg_protocol.h"

namespace memdbg::x64dbg_bridge {

void Session::set_error(const std::string &msg) { last_error_ = msg; }

std::string Session::last_error() const {
  std::lock_guard<std::mutex> lock(mu_);
  return last_error_;
}

bool Session::connect(const std::string &host, uint16_t port) {
  std::lock_guard<std::mutex> lock(mu_);
  if (attached_) {
    client_.debug_detach();
    attached_ = false;
    pid_ = 0;
    selected_lwp_ = 0;
  }
  client_.disconnect();
  if (!client_.connect_to(host, port)) {
    set_error("connect_to failed: " + client_.last_error());
    return false;
  }
  frontend::HelloInfo hello;
  if (!client_.hello(hello)) {
    set_error("hello failed: " + client_.last_error());
    client_.disconnect();
    return false;
  }
  if ((hello.capabilities & MEMDBG_CAP_DEBUGGER) == 0) {
    set_error("payload missing MEMDBG_CAP_DEBUGGER");
    /* Still usable for memory; keep connection. */
  }
  last_error_.clear();
  return true;
}

void Session::disconnect() {
  std::lock_guard<std::mutex> lock(mu_);
  if (attached_) {
    client_.debug_detach();
    attached_ = false;
  }
  pid_ = 0;
  selected_lwp_ = 0;
  client_.disconnect();
}

bool Session::connected() const {
  std::lock_guard<std::mutex> lock(mu_);
  return client_.connected();
}

bool Session::attach(int32_t pid) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!client_.connected()) {
    set_error("not connected");
    return false;
  }
  if (attached_) {
    client_.debug_detach();
    attached_ = false;
  }
  if (!client_.debug_attach(pid)) {
    set_error("debug_attach failed: " + client_.last_error());
    return false;
  }
  attached_ = true;
  pid_ = pid;
  selected_lwp_ = 0;

  std::vector<frontend::Client::DebugThreadEntry> threads;
  if (client_.debug_get_threads(threads) && !threads.empty()) {
    selected_lwp_ = threads.front().lwp;
  }
  last_error_.clear();
  return true;
}

bool Session::detach() {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    return true;
  }
  if (!client_.debug_detach()) {
    set_error("debug_detach failed: " + client_.last_error());
    return false;
  }
  attached_ = false;
  pid_ = 0;
  selected_lwp_ = 0;
  last_error_.clear();
  return true;
}

bool Session::stop() {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_stop()) {
    set_error("debug_stop failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::cont() {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_continue()) {
    set_error("debug_continue failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::step() {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (selected_lwp_ == 0) {
    std::vector<frontend::Client::DebugThreadEntry> threads;
    if (client_.debug_get_threads(threads) && !threads.empty()) {
      selected_lwp_ = threads.front().lwp;
    }
  }
  if (selected_lwp_ == 0) {
    set_error("no thread for step");
    return false;
  }
  if (!client_.debug_step(selected_lwp_)) {
    set_error("debug_step failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::read_memory(uint64_t address, uint32_t length,
                          std::vector<uint8_t> &out) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!client_.connected()) {
    set_error("not connected");
    return false;
  }
  if (!client_.memory_read(pid_ != 0 ? pid_ : 0, address, length, out)) {
    /* When not attached, pid 0 may fail; still report client error. */
    set_error("memory_read failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::write_memory(uint64_t address, const std::vector<uint8_t> &data) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!client_.connected()) {
    set_error("not connected");
    return false;
  }
  uint32_t written = 0;
  if (!client_.memory_write(pid_ != 0 ? pid_ : 0, address, data, written)) {
    set_error("memory_write failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::get_regs(frontend::Client::DebugRegs &out) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (selected_lwp_ == 0) {
    std::vector<frontend::Client::DebugThreadEntry> threads;
    if (client_.debug_get_threads(threads) && !threads.empty()) {
      selected_lwp_ = threads.front().lwp;
    }
  }
  if (!client_.debug_get_regs(selected_lwp_, out)) {
    set_error("debug_get_regs failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::set_regs(const frontend::Client::DebugRegs &in) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (selected_lwp_ == 0) {
    set_error("no thread selected");
    return false;
  }
  if (!client_.debug_set_regs(selected_lwp_, in)) {
    set_error("debug_set_regs failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::set_soft_bp(uint64_t address) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_set_breakpoint(address, 0)) {
    set_error("debug_set_breakpoint failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::set_hw_bp(uint64_t address) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_set_breakpoint(address, 1)) {
    set_error("debug_set_breakpoint(hw) failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::clear_bp(uint64_t address) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_clear_breakpoint(address)) {
    set_error("debug_clear_breakpoint failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::set_watchpoint(uint64_t address, uint32_t length, uint32_t type) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_set_watchpoint(address, length, type)) {
    set_error("debug_set_watchpoint failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::clear_watchpoint(uint64_t address) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_clear_watchpoint(address)) {
    set_error("debug_clear_watchpoint failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::poll_events(bool &stopped, int32_t &stop_lwp) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (!client_.debug_poll_events(stopped, stop_lwp)) {
    set_error("debug_poll_events failed: " + client_.last_error());
    return false;
  }
  if (stopped && stop_lwp != 0) {
    selected_lwp_ = stop_lwp;
  }
  last_error_.clear();
  return true;
}

bool Session::get_fpregs(frontend::Client::DebugFpregs &out) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (selected_lwp_ == 0) {
    std::vector<frontend::Client::DebugThreadEntry> threads;
    if (client_.debug_get_threads(threads) && !threads.empty()) {
      selected_lwp_ = threads.front().lwp;
    }
  }
  if (!client_.debug_get_fpregs(selected_lwp_, out)) {
    set_error("debug_get_fpregs failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::set_gpr(const char *name, uint64_t value) {
  if (!name || !*name) {
    set_error("missing register name");
    return false;
  }
  std::lock_guard<std::mutex> lock(mu_);
  if (!attached_) {
    set_error("not attached");
    return false;
  }
  if (selected_lwp_ == 0) {
    std::vector<frontend::Client::DebugThreadEntry> threads;
    if (client_.debug_get_threads(threads) && !threads.empty()) {
      selected_lwp_ = threads.front().lwp;
    }
  }
  frontend::Client::DebugRegs regs;
  if (!client_.debug_get_regs(selected_lwp_, regs)) {
    set_error("debug_get_regs failed: " + client_.last_error());
    return false;
  }

  if (!apply_gpr_name(regs.regs, name, value)) {
    set_error("unknown GPR name");
    return false;
  }

  if (!client_.debug_set_regs(selected_lwp_, regs)) {
    set_error("debug_set_regs failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

bool Session::list_maps(std::vector<frontend::MapEntry> &out) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!client_.connected()) {
    set_error("not connected");
    return false;
  }
  const int32_t pid = pid_ != 0 ? pid_ : 0;
  if (!client_.process_maps(pid, out)) {
    set_error("process_maps failed: " + client_.last_error());
    return false;
  }
  last_error_.clear();
  return true;
}

Session &global_session() {
  static Session session;
  return session;
}

} // namespace memdbg::x64dbg_bridge

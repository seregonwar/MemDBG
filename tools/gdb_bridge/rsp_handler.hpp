/*
 * MemDBG - RSP command dispatch onto MDBG Client.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP
#define MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP

#include "rsp_backend.hpp"
#include "rsp_protocol.hpp"
#include "rsp_server.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace memdbg::gdb_bridge {

class RspHandler {
public:
  RspHandler(memdbg::frontend::Client &client, int32_t initial_pid, bool fpregs_supported,
             bool verbose = false);
  RspHandler(RspBackend &backend, int32_t initial_pid, bool verbose = false);

  std::string handle(const std::string &packet, RspConnection &conn);

  /* Resume (best-effort) then detach; safe on disconnect / dtor paths. */
  void cleanup();

  int32_t attached_pid() const { return pid_; }
  bool attached() const { return attached_; }

private:
  std::string handle_query(const std::string &packet, RspConnection &conn);
  std::string handle_v(const std::string &packet, RspConnection &conn);
  std::string handle_memory_read(const std::string &packet);
  std::string handle_memory_write(const std::string &packet);
  std::string handle_breakpoint(const std::string &packet, bool enable);
  std::string handle_continue_or_step(bool step, RspConnection &conn, int32_t lwp);
  std::string stop_reply() const;
  std::string qxfer_features(const std::string &annex, size_t offset, size_t length) const;
  std::string qxfer_memory_map(size_t offset, size_t length);
  std::string qxfer_threads(size_t offset, size_t length);
  std::string qxfer_libraries(size_t offset, size_t length);
  std::string qxfer_exec_file(size_t offset, size_t length);
  std::string qxfer_osdata(const std::string &annex, size_t offset, size_t length);
  std::string handle_binary_memory_write(const std::string &packet);
  std::string handle_search_memory(const std::string &packet);
  std::string handle_read_all_registers();
  std::string handle_write_all_registers(const std::string &packet);
  std::string handle_read_register(const std::string &packet);
  std::string handle_write_register(const std::string &packet);
  std::string handle_resume_packet(const std::string &packet, bool step, RspConnection &conn);
  std::string memory_region_info(const std::string &packet);
  bool set_program_counter(uint64_t address);
  bool kill_process(int32_t target_pid);
  bool ensure_attached();
  bool safe_detach();
  void logf(const char *fmt, ...) const;
  void log_rsp_command(const std::string &packet) const;
  void capture_stop_reason(int32_t lwp);
  int32_t current_thread() const;
  void refresh_threads();
  bool refresh_memory_maps();

  std::unique_ptr<RspBackend> owned_backend_;
  RspBackend &backend_;
  int32_t pid_ = 0;
  bool attached_ = false;
  bool verbose_ = false;
  int32_t general_thread_ = 0; /* Hg */
  int32_t continue_thread_ = 0; /* Hc; 0 = all */
  int32_t stop_lwp_ = 0;
  uint8_t stop_signal_ = 5U; /* SIGTRAP */
  std::string stop_reason_;
  bool thread_info_started_ = false;
  std::vector<memdbg::frontend::Client::DebugThreadEntry> threads_;
  std::vector<memdbg::frontend::MapEntry> memory_maps_;
  bool memory_maps_known_ = false;
  /* Software breakpoints the bridge inserted: address -> original byte.
   * The payload writes INT3 (0xCC) into the target; masking it back out of
   * memory reads keeps IDA's disassembly intact. */
  std::unordered_map<uint64_t, uint8_t> sw_breakpoints_;
};

} // namespace memdbg::gdb_bridge

#endif /* MEMDBG_GDB_BRIDGE_RSP_HANDLER_HPP */

/*
 * MemDBG - GDB RSP register packet handling.
 * Copyright (C) 2026 SeregonWar
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "rsp_handler.hpp"

#include "gdb_regs.hpp"

namespace memdbg::gdb_bridge {

using namespace detail;

std::string RspHandler::handle_read_all_registers() {
  if (!ensure_attached()) return err_packet(1);
  memdbg::frontend::Client::DebugRegs regs;
  if (!backend_.debug_get_regs(current_thread(), regs)) return err_packet(1);

  if (backend_.debug_fpregs_supported()) {
    memdbg::frontend::Client::DebugFpregs fpregs;
    if (!backend_.debug_get_fpregs(current_thread(), fpregs)) return err_packet(1);
    return gdb_encode_g_packet(regs.regs, &fpregs.fpregs);
  }

  /* Preserve the target.xml packet size without touching unsafe PS4 ptrace
   * FP operations.  GDB and IDA accept zero-filled unavailable registers. */
  return gdb_encode_g_packet(regs.regs, nullptr);
}

std::string RspHandler::handle_write_all_registers(const std::string &packet) {
  if (!ensure_attached()) return err_packet(1);
  const std::string payload = packet.substr(1U);
  memdbg::frontend::Client::DebugRegs regs;
  if (!backend_.debug_get_regs(current_thread(), regs)) return err_packet(1);

  /* Accept the old core-only G layout for compatibility with simple clients. */
  if (payload.size() == kGdbCorePacketHexSize) {
    if (!gdb_decode_g_core(payload, regs.regs) ||
        !backend_.debug_set_regs(current_thread(), regs)) {
      return err_packet(1);
    }
    return "OK";
  }

  if (backend_.debug_fpregs_supported()) {
    memdbg::frontend::Client::DebugFpregs fpregs;
    if (!backend_.debug_get_fpregs(current_thread(), fpregs) ||
        !gdb_decode_g_packet(payload, regs.regs, &fpregs.fpregs) ||
        !backend_.debug_set_regs(current_thread(), regs) ||
        !backend_.debug_set_fpregs(current_thread(), fpregs)) {
      return err_packet(1);
    }
    return "OK";
  }

  return gdb_decode_g_packet(payload, regs.regs, nullptr) &&
           backend_.debug_set_regs(current_thread(), regs)
           ? "OK"
           : err_packet(1);
}

std::string RspHandler::handle_read_register(const std::string &packet) {
  if (!ensure_attached()) return err_packet(1);
  uint64_t regno = 0U;
  if (!parse_hex_u64(packet.c_str() + 1U, regno) || !gdb_reg_valid(static_cast<int>(regno))) {
    return err_packet(1);
  }

  const int ir = static_cast<int>(regno);
  const size_t size = gdb_reg_size(ir);
  if (gdb_reg_is_sse(ir) || gdb_reg_is_x87(ir)) {
    if (!backend_.debug_fpregs_supported()) return std::string(size * 2U, '0');
    memdbg::frontend::Client::DebugFpregs fpregs;
    if (!backend_.debug_get_fpregs(current_thread(), fpregs)) return err_packet(1);
    uint8_t buf[16]{};
    const bool got = gdb_reg_is_sse(ir) ? gdb_get_sse_bytes(fpregs.fpregs, ir, buf, sizeof(buf))
                                        : gdb_get_x87_bytes(fpregs.fpregs, ir, buf, sizeof(buf));
    return got ? bytes_to_hex(buf, size) : err_packet(1);
  }

  memdbg::frontend::Client::DebugRegs regs;
  if (!backend_.debug_get_regs(current_thread(), regs)) return err_packet(1);
  uint64_t value = gdb_get_reg_value(regs.regs, ir);
  if (size == 4U) value &= 0xFFFFFFFFULL;
  return bytes_to_hex(&value, size);
}

std::string RspHandler::handle_write_register(const std::string &packet) {
  if (!ensure_attached()) return err_packet(1);
  const size_t eq = packet.find('=');
  uint64_t regno = 0U;
  if (eq == std::string::npos || !parse_hex_u64(packet, 1U, eq, regno) ||
      !gdb_reg_valid(static_cast<int>(regno))) {
    return err_packet(1);
  }

  const int ir = static_cast<int>(regno);
  const size_t size = gdb_reg_size(ir);
  if (gdb_reg_is_sse(ir) || gdb_reg_is_x87(ir)) {
    uint8_t buf[16]{};
    if (!hex_to_bytes(packet.substr(eq + 1U), buf, size)) return err_packet(1);
    if (!backend_.debug_fpregs_supported()) return "OK";
    memdbg::frontend::Client::DebugFpregs fpregs;
    if (!backend_.debug_get_fpregs(current_thread(), fpregs)) return err_packet(1);
    const bool set = gdb_reg_is_sse(ir) ? gdb_set_sse_bytes(fpregs.fpregs, ir, buf, size)
                                        : gdb_set_x87_bytes(fpregs.fpregs, ir, buf, size);
    if (!set || !backend_.debug_set_fpregs(current_thread(), fpregs)) return err_packet(1);
    return "OK";
  }

  uint64_t value = 0U;
  memdbg::frontend::Client::DebugRegs regs;
  if (!hex_to_bytes(packet.substr(eq + 1U), &value, size) ||
      !backend_.debug_get_regs(current_thread(), regs) ||
      !gdb_set_reg_value(regs.regs, ir, value) ||
      !backend_.debug_set_regs(current_thread(), regs)) {
    return err_packet(1);
  }
  return "OK";
}

} // namespace memdbg::gdb_bridge
